package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"
	"filippo.io/torchwood/internal/witness"
	"golang.org/x/mod/sumdb/note"
	sigsum "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
)

func usage() {
	fmt.Printf("Usage: %s <command> [options]\n", os.Args[0])
	fmt.Println("Commands:")
	fmt.Println("    add-log -db <path> -origin <origin>")
	fmt.Println("    add-key -db <path> -origin <origin> -key <verifier key>")
	fmt.Println("    del-key -db <path> -origin <origin> -key <verifier key>")
	fmt.Println("    add-sigsum-log -db <path> -key <hex-encoded key>")
	fmt.Println("    list-logs -db <path>")
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	dbFlag := fs.String("db", "litewitness.db", "path to sqlite database")
	switch os.Args[1] {
	case "add-log":
		originFlag := fs.String("origin", "", "log name")
		fs.Parse(os.Args[2:])
		db := openDB(*dbFlag)
		addLog(db, *originFlag)

	case "add-key":
		originFlag := fs.String("origin", "", "log name")
		keyFlag := fs.String("key", "", "verifier key")
		fs.Parse(os.Args[2:])
		db := openDB(*dbFlag)
		addKey(db, *originFlag, *keyFlag)

	case "del-key":
		originFlag := fs.String("origin", "", "log name")
		keyFlag := fs.String("key", "", "verifier key")
		fs.Parse(os.Args[2:])
		db := openDB(*dbFlag)
		delKey(db, *originFlag, *keyFlag)

	case "add-sigsum-log":
		keyFlag := fs.String("key", "", "hex-encoded key")
		fs.Parse(os.Args[2:])
		db := openDB(*dbFlag)
		addSigsumLog(db, *keyFlag)

	case "list-logs":
		fs.Parse(os.Args[2:])
		db := openDB(*dbFlag)
		listLogs(db)

	default:
		usage()
	}
}

func openDB(dbPath string) *sqlite.Conn {
	db, err := witness.OpenDB(dbPath)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}
	return db
}

func addLog(db *sqlite.Conn, origin string) {
	treeHash := merkle.HashEmptyTree()
	if err := sqlitex.Exec(db, "INSERT INTO log (origin, tree_size, tree_hash) VALUES (?, 0, ?)",
		nil, origin, base64.StdEncoding.EncodeToString(treeHash[:])); err != nil {
		log.Fatalf("Error adding log: %v", err)
	}
	log.Printf("Added log %q.", origin)
}

func addKey(db *sqlite.Conn, origin string, vk string) {
	v, err := note.NewVerifier(vk)
	if err != nil {
		log.Fatalf("Error parsing verifier key: %v", err)
	}
	if v.Name() != origin {
		log.Printf("Warning: verifier key name %q does not match origin %q.", v.Name(), origin)
	}
	err = sqlitex.Exec(db, "INSERT INTO key (origin, key) VALUES (?, ?)", nil, origin, vk)
	if err != nil {
		log.Fatalf("Error adding key: %v", err)
	}
	log.Printf("Added key %q.", vk)
}

func delKey(db *sqlite.Conn, origin string, vk string) {
	err := sqlitex.Exec(db, "DELETE FROM key WHERE origin = ? AND key = ?", nil, origin, vk)
	if err != nil {
		log.Fatalf("Error deleting key: %v", err)
	}
	if db.Changes() == 0 {
		log.Fatalf("Key %q not found.", vk)
	}
	log.Printf("Deleted key %q.", vk)
}

func addSigsumLog(db *sqlite.Conn, keyFlag string) {
	if len(keyFlag) != sigsum.PublicKeySize*2 {
		log.Fatal("Key must be 32 hex-encoded bytes.")
	}
	var key sigsum.PublicKey
	if _, err := hex.Decode(key[:], []byte(keyFlag)); err != nil {
		log.Fatalf("Error decoding key: %v", err)
	}
	keyHash := sigsum.HashBytes(key[:])
	origin := fmt.Sprintf("sigsum.org/v1/tree/%x", keyHash)
	vk, err := note.NewEd25519VerifierKey(origin, key[:])
	if err != nil {
		log.Fatalf("Error computing verifier key: %v", err)
	}
	addLog(db, origin)
	addKey(db, origin, vk)
}

func listLogs(db *sqlite.Conn) {
	if err := sqlitex.Exec(db, `
	SELECT json_object(
		'origin', log.origin,
		'size', log.tree_size,
		'root_hash', log.tree_hash,
		'keys', json_group_array(key.key))
	FROM
		log
		LEFT JOIN key on log.origin = key.origin
	GROUP BY
		log.origin
	ORDER BY
		log.origin
	`, func(stmt *sqlite.Stmt) error {
		_, err := fmt.Printf("%s\n", stmt.ColumnText(0))
		return err
	}); err != nil {
		log.Fatalf("Error listing logs: %v", err)
	}
}
