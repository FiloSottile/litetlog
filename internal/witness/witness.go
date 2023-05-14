package witness

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"
	"golang.org/x/crypto/ssh"
	"golang.org/x/mod/sumdb/tlog"
	"sigsum.org/sigsum-go/pkg/ascii"
	sigsum "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
)

type Witness struct {
	db  *sqlite.Conn
	s   ssh.Signer
	mux *http.ServeMux
	log func(format string, v ...any)

	// testingOnlyStallRequest is called after checking a valid tree head, but
	// before committing it to the database. It's used in tests to cause a race
	// between two requests and simulating the risk of a rollback.
	testingOnlyStallRequest func()
}

func NewWitness(dbPath string, s ssh.Signer, log func(format string, v ...any)) (*Witness, error) {
	db, err := sqlite.OpenConn(dbPath, 0)
	if err != nil {
		return nil, fmt.Errorf("opening database: %v", err)
	}

	if err := sqlitex.ExecScript(db, `
		PRAGMA strict_types = ON;
		PRAGMA foreign_keys = ON;
		CREATE TABLE IF NOT EXISTS log (
			origin TEXT PRIMARY KEY,
			tree_size INTEGER NOT NULL,
			tree_hash TEXT NOT NULL -- base64-encoded
		);
		CREATE TABLE IF NOT EXISTS key (
			origin TEXT NOT NULL,
			key TEXT NOT NULL, -- base64-encoded
			FOREIGN KEY(origin) REFERENCES log(origin)
		);
		-- tree_head is an audit log of validly signed tree heads
		-- observed by this witness.
		CREATE TABLE IF NOT EXISTS tree_head (
			hash TEXT NOT NULL, -- base64-encoded SHA-256 of signed data
			json_details TEXT,
			UNIQUE(hash) ON CONFLICT IGNORE
		);
		CREATE INDEX IF NOT EXISTS tree_head_origin ON
			tree_head(json_extract(json_details, '$.origin'));
	`); err != nil {
		return nil, fmt.Errorf("initializing database: %v", err)
	}

	w := &Witness{
		db:  db,
		s:   s,
		log: log,
		mux: http.NewServeMux(),
	}
	w.mux.Handle("/sigsum/v1/add-tree-head", http.HandlerFunc(w.serveAddTreeHead))
	return w, nil
}

func (w *Witness) Close() error {
	return w.db.Close()
}

func (w *Witness) AddSigsumLog(key sigsum.PublicKey) error {
	keyHash := sigsum.HashBytes(key[:])
	treeHash := merkle.HashEmptyTree()
	origin := fmt.Sprintf("sigsum.org/v1/tree/%x", keyHash)
	err := sqlitex.Exec(w.db, "INSERT INTO log (origin, tree_size, tree_hash) VALUES (?, 0, ?)",
		nil, origin, base64.StdEncoding.EncodeToString(treeHash[:]))
	if err != nil {
		return err
	}
	return sqlitex.Exec(w.db, "INSERT INTO key (origin, key) VALUES (?, ?)",
		nil, origin, base64.StdEncoding.EncodeToString(key[:]))
}

func (w *Witness) ExecSQL(query string, resultFn func(stmt *sqlite.Stmt) error, args ...interface{}) error {
	return sqlitex.Exec(w.db, query, resultFn, args...)
}

func (w *Witness) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	w.mux.ServeHTTP(rw, r)
}

var errUnknownLog = errors.New("unknown log")
var errInvalidSignature = errors.New("invalid signature")
var errConflict = errors.New("known tree size doesn't match provided old size")
var errBadRequest = errors.New("invalid input")
var errProof = errors.New("bad consistency proof")

func (w *Witness) serveAddTreeHead(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(rw, "only POST is allowed", http.StatusMethodNotAllowed)
		return
	}

	keyHash, oldSize, newSize, newHash, signature, proof, err := parseSigsumRequest(r.Body)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	treeProof := make(tlog.TreeProof, len(proof))
	for i := range proof {
		treeProof[i] = tlog.Hash(proof[i])
	}
	cosig, t, err := w.processSigsumRequest(keyHash[:], int64(oldSize), int64(newSize),
		tlog.Hash(newHash), signature[:], treeProof)
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

	pub, err := w.publicKey()
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := ascii.WriteLine(rw, "cosignature", []byte(pub), uint64(t.Unix()), cosig); err != nil {
		w.log("Failed to write cosignature: %v", err)
	}
}

func parseSigsumRequest(r io.Reader) (keyHash sigsum.Hash, oldSize, newSize uint64, newHash sigsum.Hash,
	signature sigsum.Signature, proof []sigsum.Hash, err error) {
	p := ascii.NewParser(r)
	keyHash, err = p.GetHash("key_hash")
	if err != nil {
		return
	}
	newSize, err = p.GetInt("size")
	if err != nil {
		return
	}
	newHash, err = p.GetHash("root_hash")
	if err != nil {
		return
	}
	signature, err = p.GetSignature("signature")
	if err != nil {
		return
	}
	oldSize, err = p.GetInt("old_size")
	if err != nil {
		return
	}
	for {
		var h sigsum.Hash
		h, err = p.GetHash("node_hash")
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return
		}
		proof = append(proof, h)
	}
}

func (w *Witness) processSigsumRequest(
	keyHash []byte, oldSize, newSize int64, newHash tlog.Hash,
	signature []byte, proof tlog.TreeProof) (cosig []byte, t time.Time, err error) {

	origin := fmt.Sprintf("sigsum.org/v1/tree/%x", keyHash)
	checkpoint := serializeCheckpoint(origin, newSize, newHash)

	key, err := w.getSigsumKey(origin)
	if err != nil {
		return nil, t, err
	}
	if err := verifySingleSignature(key, checkpoint, signature); err != nil {
		return nil, t, err
	}
	defer func() { w.logValidCheckpoint(origin, newSize, checkpoint, key, signature, t, err) }()
	if err := w.checkConsistency(origin, oldSize, newSize, newHash, proof); err != nil {
		return nil, t, err
	}
	if w.testingOnlyStallRequest != nil {
		w.testingOnlyStallRequest()
	}
	t, err = w.persistTreeHead(origin, oldSize, newSize, newHash)
	if err != nil {
		return nil, t, err
	}
	cosig, err = w.signTreeHead(origin, newSize, newHash, t)
	if err != nil {
		return nil, t, err
	}
	return cosig, t, err
}

func (w *Witness) logValidCheckpoint(origin string, newSize int64, checkpoint, key, signature []byte, t time.Time, result error) {
	h := sha256.Sum256(checkpoint)
	hash := base64.StdEncoding.EncodeToString(h[:])
	m := map[string]interface{}{
		"origin":     origin,
		"time":       time.Now().Format(time.RFC3339),
		"checkpoint": checkpoint,
		"key":        key,
		"signature":  signature,
		"size":       newSize,
	}
	if result != nil {
		m["error"] = result.Error()
	}
	if !t.IsZero() {
		m["commit_time"] = t.Format(time.RFC3339)
	}
	metadata, err := json.Marshal(m)
	if err != nil {
		w.log("Failed to log tree head: %v", m)
	}

	if err := sqlitex.Exec(w.db,
		"INSERT INTO tree_head (hash, json_details) VALUES (?, ?)",
		nil, hash, metadata); err != nil {
		w.log("Failed to log tree head %v: %v", string(metadata), err)
	}
}

func verifySingleSignature(key, checkpoint, signature []byte) error {
	if !ed25519.Verify(key, checkpoint, signature) {
		return errInvalidSignature
	}
	return nil
}

func serializeCheckpoint(origin string, size int64, hash tlog.Hash) []byte {
	return []byte(fmt.Sprintf("%s\n%d\n%s\n", origin, size, hash))
}

func serializeCosignatureSignedData(t time.Time, origin string, size int64, hash tlog.Hash) []byte {
	return []byte(fmt.Sprintf("cosignature/v1\ntime %d\n%s\n%d\n%s\n", t.Unix(), origin, size, hash))
}

func (w *Witness) publicKey() (ed25519.PublicKey, error) {
	// agent.Key doesn't implement ssh.CryptoPublicKey.
	pubKey, err := ssh.ParsePublicKey(w.s.PublicKey().Marshal())
	if err != nil {
		return nil, errors.New("internal error: ssh public key can't be parsed")
	}
	k, ok := pubKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errors.New("internal error: ssh public key can't be retrieved")
	}
	key, ok := k.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("internal error: ssh public key of unknown type")
	}
	return key, nil
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

func (w *Witness) signTreeHead(origin string, size int64, h tlog.Hash, t time.Time) ([]byte, error) {
	signedData := serializeCosignatureSignedData(t, origin, size, h)
	sig, err := w.s.Sign(rand.Reader, signedData)
	if err != nil {
		return nil, err
	}
	return sig.Blob, nil
}

func (w *Witness) persistTreeHead(origin string, oldSize, newSize int64, newHash tlog.Hash) (t time.Time, err error) {
	// Check oldSize against the database to prevent rolling back on a race.
	// Alternatively, we could use a database transaction which would be cleaner
	// but would encode a critical security semantic in the implicit use of the
	// correct Conn across functions, which is uncomfortable.
	err = sqlitex.Exec(w.db, `
			UPDATE log SET tree_size = ?, tree_hash = ?
			WHERE origin = ? AND tree_size = ? RETURNING unixepoch()`,
		func(stmt *sqlite.Stmt) error {
			t = time.Unix(stmt.ColumnInt64(0), 0)
			return nil
		}, newSize, newHash, origin, oldSize)
	if err == nil && t.IsZero() || w.db.Changes() != 1 {
		err = errConflict
	}
	return
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

func (w *Witness) getKeys(origin string) (keys []string, err error) {
	found := false
	err = sqlitex.Exec(w.db, "SELECT key FROM key WHERE origin = ?",
		func(stmt *sqlite.Stmt) error {
			found = true
			keys = append(keys, stmt.GetText("key"))
			return nil
		}, origin)
	if err == nil && !found {
		err = errUnknownLog
	}
	return
}

func (w *Witness) getSigsumKey(origin string) ([]byte, error) {
	keys, err := w.getKeys(origin)
	if err != nil {
		return nil, err
	}
	if len(keys) != 1 {
		return nil, errors.New("a Sigsum log can only have one key")
	}
	return base64.StdEncoding.DecodeString(keys[0])
}
