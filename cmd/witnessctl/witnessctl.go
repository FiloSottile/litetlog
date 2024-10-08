package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"
	"filippo.io/litetlog/internal/witness"
	"golang.org/x/mod/sumdb/note"
	sigsum "sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
)

func usage() {
	fmt.Printf("Usage: %s <command> [options]\n", os.Args[0])
	fmt.Println("Commands:")
	fmt.Println("    add-log -db <path> -origin <origin> -key <base64-encoded Ed25519 key>")
	fmt.Println("    add-sigsum-log -db <path> -key <hex-encoded key>")
	fmt.Println("    list-logs -db <path>")
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "add-log":
		fs := flag.NewFlagSet("add-log", flag.ExitOnError)
		dbFlag := fs.String("db", "litewitness.db", "path to sqlite database")
		originFlag := fs.String("origin", "", "log name")
		keyFlag := fs.String("key", "", "base64-encoded key")
		fs.Parse(os.Args[2:])
		key, err := base64.StdEncoding.DecodeString(*keyFlag)
		if err != nil {
			log.Fatal(err)
		}
		db := openDB(*dbFlag)
		addLog(db, *originFlag, key)

	case "add-sigsum-log":
		fs := flag.NewFlagSet("add-sigsum-log", flag.ExitOnError)
		dbFlag := fs.String("db", "litewitness.db", "path to sqlite database")
		keyFlag := fs.String("key", "", "hex-encoded key")
		fs.Parse(os.Args[2:])
		if len(*keyFlag) != sigsum.PublicKeySize*2 {
			log.Println(*keyFlag)
			log.Fatal("key must be 32 hex-encoded bytes")
		}
		var key sigsum.PublicKey
		if _, err := hex.Decode(key[:], []byte(*keyFlag)); err != nil {
			log.Fatal(err)
		}
		db := openDB(*dbFlag)
		addSigsumLog(db, key)

	case "list-logs":
		fs := flag.NewFlagSet("list-logs", flag.ExitOnError)
		dbFlag := fs.String("db", "litewitness.db", "path to sqlite database")
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
		log.Fatalf("opening database: %v", err)
	}
	return db
}

func addLog(db *sqlite.Conn, origin string, key ed25519.PublicKey) {
	treeHash := merkle.HashEmptyTree()
	if err := sqlitex.Exec(db, "INSERT INTO log (origin, tree_size, tree_hash) VALUES (?, 0, ?)",
		nil, origin, base64.StdEncoding.EncodeToString(treeHash[:])); err != nil {
		log.Fatal(err)
	}
	k, err := note.NewEd25519VerifierKey(origin, key[:])
	if err != nil {
		log.Fatal(err)
	}
	if sqlitex.Exec(db, "INSERT INTO key (origin, key) VALUES (?, ?)", nil, origin, k); err != nil {
		log.Fatal(err)
	}
	log.Printf("Added log %q.", key)
}

func addSigsumLog(db *sqlite.Conn, key sigsum.PublicKey) {
	keyHash := sigsum.HashBytes(key[:])
	origin := fmt.Sprintf("sigsum.org/v1/tree/%x", keyHash)
	addLog(db, origin, key[:])
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
		log.Fatal(err)
	}
}
