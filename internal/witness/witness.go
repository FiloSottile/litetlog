package witness

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"
	"filippo.io/litetlog/internal/tlogx"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

type Witness struct {
	db  *sqlite.Conn
	s   note.Signer
	mux *http.ServeMux
	log *slog.Logger

	// testingOnlyStallRequest is called after checking a valid tree head, but
	// before committing it to the database. It's used in tests to cause a race
	// between two requests and simulating the risk of a rollback.
	testingOnlyStallRequest func()
}

func OpenDB(dbPath string) (*sqlite.Conn, error) {
	db, err := sqlite.OpenConn(dbPath, 0)
	if err != nil {
		return nil, fmt.Errorf("opening database: %v", err)
	}

	return db, sqlitex.ExecScript(db, `
		PRAGMA strict_types = ON;
		PRAGMA foreign_keys = ON;
		CREATE TABLE IF NOT EXISTS log (
			origin TEXT PRIMARY KEY,
			tree_size INTEGER NOT NULL,
			tree_hash TEXT NOT NULL -- base64-encoded
		);
		CREATE TABLE IF NOT EXISTS key (
			origin TEXT NOT NULL,
			key TEXT NOT NULL, -- note verifier key
			FOREIGN KEY(origin) REFERENCES log(origin)
		);
	`)
}

func NewWitness(dbPath, name string, key crypto.Signer, log *slog.Logger) (*Witness, error) {
	db, err := OpenDB(dbPath)
	if err != nil {
		return nil, fmt.Errorf("initializing database: %v", err)
	}

	s, err := tlogx.NewCosignatureV1Signer(name, key)
	if err != nil {
		return nil, fmt.Errorf("preparing signer: %v", err)
	}

	w := &Witness{
		db:  db,
		s:   s,
		log: log,
		mux: http.NewServeMux(),
	}
	w.mux.Handle("/v1/add-tree-head", http.HandlerFunc(w.serveAddTreeHead))
	w.mux.Handle("/v1/get-tree-size", http.HandlerFunc(w.serveGetTreeSize))
	return w, nil
}

func (w *Witness) Close() error {
	return w.db.Close()
}

func (w *Witness) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	w.mux.ServeHTTP(rw, r)
}

var errUnknownLog = errors.New("unknown log")
var errInvalidSignature = errors.New("invalid signature")
var errConflict = errors.New("known tree size doesn't match provided old size")
var errBadRequest = errors.New("invalid input")
var errProof = errors.New("bad consistency proof")

func (w *Witness) serveGetTreeSize(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(rw, "only GET is allowed", http.StatusMethodNotAllowed)
		return
	}

	origin := r.URL.Query().Get("origin")
	if origin == "" {
		http.Error(rw, "missing origin parameter", http.StatusBadRequest)
		return
	}

	treeSize, _, err := w.getLog(origin)
	if err == errUnknownLog {
		http.Error(rw, err.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Cache-Control", "no-store")
	if _, err := fmt.Fprintf(rw, "%d\n", treeSize); err != nil {
		w.log.DebugContext(r.Context(), "failed to write size", "err", err)
	}
}

func (w *Witness) serveAddTreeHead(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "only POST is allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	cosig, err := w.processAddTreeHeadRequest(body)
	switch err {
	case errUnknownLog, errInvalidSignature:
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	case errConflict:
		http.Error(rw, err.Error(), http.StatusConflict)
		return
	case errBadRequest:
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	case errProof:
		http.Error(rw, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	rw.Write(cosig)
}

func (w *Witness) processAddTreeHeadRequest(body []byte) (cosig []byte, err error) {
	body, noteBytes, ok := bytes.Cut(body, []byte("\n\n"))
	if !ok {
		return nil, errBadRequest
	}
	lines := strings.Split(string(body), "\n")
	if len(lines) < 1 {
		return nil, errBadRequest
	}
	size, ok := strings.CutPrefix(lines[0], "old ")
	if !ok {
		return nil, errBadRequest
	}
	oldSize, err := strconv.ParseInt(size, 10, 64)
	if err != nil || oldSize < 0 {
		return nil, errBadRequest
	}
	proof := make(tlog.TreeProof, len(lines[1:]))
	for i, h := range lines[1:] {
		proof[i], err = tlog.ParseHash(h)
		if err != nil {
			return nil, errBadRequest
		}
	}
	origin, _, _ := strings.Cut(string(noteBytes), "\n")
	verifier, err := w.getKeys(origin)
	if err != nil {
		return nil, err
	}
	n, err := note.Open(noteBytes, verifier)
	switch err.(type) {
	case *note.UnverifiedNoteError, *note.InvalidSignatureError:
		return nil, errInvalidSignature
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		l := w.log.With("origin", origin, "note", string(noteBytes))
		if err != nil {
			l.With("error", err).Warn("rejected signed checkpoint")
		} else {
			l.Debug("accepted signed checkpoint")
		}
	}()
	c, err := tlogx.ParseCheckpoint(n.Text)
	if err != nil {
		return nil, err
	}
	if err := w.checkConsistency(c.Origin, oldSize, c.N, c.Hash, proof); err != nil {
		return nil, err
	}
	if w.testingOnlyStallRequest != nil {
		w.testingOnlyStallRequest()
	}
	if err := w.persistTreeHead(c.Origin, oldSize, c.N, c.Hash); err != nil {
		return nil, err
	}
	signed, err := note.Sign(&note.Note{Text: n.Text}, w.s)
	if err != nil {
		return nil, err
	}
	sigs, err := splitSignatures(signed)
	if err != nil {
		return nil, err
	}
	return sigs, err
}

func splitSignatures(note []byte) ([]byte, error) {
	var sigSplit = []byte("\n\n")
	split := bytes.LastIndex(note, sigSplit)
	if split < 0 {
		return nil, errors.New("invalid note")
	}
	_, sigs := note[:split+1], note[split+2:]
	if len(sigs) == 0 || sigs[len(sigs)-1] != '\n' {
		return nil, errors.New("invalid note")
	}
	return sigs, nil
}

func (w *Witness) checkConsistency(origin string,
	oldSize, newSize int64, newHash tlog.Hash, proof tlog.TreeProof) error {
	if oldSize > newSize {
		return errBadRequest
	}
	knownSize, oldHash, err := w.getLog(origin)
	if err != nil {
		return err
	}
	if knownSize != oldSize {
		return errConflict
	}
	if oldSize == 0 {
		// This is the first tree head for this log.
		return nil
	}
	if err := tlog.CheckTree(proof, newSize, newHash, oldSize, oldHash); err != nil {
		return errProof
	}
	return nil
}

func (w *Witness) persistTreeHead(origin string, oldSize, newSize int64, newHash tlog.Hash) error {
	// Check oldSize against the database to prevent rolling back on a race.
	// Alternatively, we could use a database transaction which would be cleaner
	// but would encode a critical security semantic in the implicit use of the
	// correct Conn across functions, which is uncomfortable.
	err := sqlitex.Exec(w.db, `
			UPDATE log SET tree_size = ?, tree_hash = ?
			WHERE origin = ? AND tree_size = ?`,
		nil, newSize, newHash, origin, oldSize)
	if err == nil && w.db.Changes() != 1 {
		err = errConflict
	}
	return err
}

func (w *Witness) getLog(origin string) (treeSize int64, treeHash tlog.Hash, err error) {
	found := false
	err = sqlitex.Exec(w.db, "SELECT tree_size, tree_hash FROM log WHERE origin = ?",
		func(stmt *sqlite.Stmt) error {
			found = true
			treeSize = stmt.GetInt64("tree_size")
			treeHash, err = tlog.ParseHash(stmt.GetText("tree_hash"))
			return nil
		}, origin)
	if err == nil && !found {
		err = errUnknownLog
	}
	return
}

func (w *Witness) getKeys(origin string) (note.Verifiers, error) {
	var keys []string
	err := sqlitex.Exec(w.db, "SELECT key FROM key WHERE origin = ?",
		func(stmt *sqlite.Stmt) error {
			keys = append(keys, stmt.GetText("key"))
			return nil
		}, origin)
	if err == nil && keys == nil {
		err = errUnknownLog
	}
	if err != nil {
		return nil, err
	}
	var verifiers []note.Verifier
	for _, k := range keys {
		v, err := note.NewVerifier(k)
		if err != nil {
			return nil, fmt.Errorf("invalid key %q: %v", k, err)
		}
		verifiers = append(verifiers, v)
	}
	return note.VerifierList(verifiers...), nil
}
