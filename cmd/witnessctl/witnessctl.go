package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"crawshaw.io/sqlite"
	sigsum "sigsum.org/sigsum-go/pkg/crypto"

	"filippo.io/litetlog/internal/witness"
)

func usage() {
	fmt.Printf("Usage: %s <command> [options]\n", os.Args[0])
	fmt.Println("Commands:")
	fmt.Println("    add-sigsum-log -db <path> -key <hex-encoded key>")
	fmt.Println("    list-logs -db <path>")
	fmt.Println("    list-tree-heads -db <path> -origin <origin> [-only-failed]")
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
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
		addSigsumLog(*dbFlag, key)

	case "list-logs":
		fs := flag.NewFlagSet("list-logs", flag.ExitOnError)
		dbFlag := fs.String("db", "litewitness.db", "path to sqlite database")
		fs.Parse(os.Args[2:])
		listLogs(*dbFlag)

	case "list-tree-heads":
		fs := flag.NewFlagSet("list-logs", flag.ExitOnError)
		dbFlag := fs.String("db", "litewitness.db", "path to sqlite database")
		onlyFailedFlag := fs.Bool("only-failed", false, "only show rejected tree heads")
		fs.Parse(os.Args[2:])
		listTreeHeads(*dbFlag, *onlyFailedFlag)

	default:
		usage()
	}
}

func addSigsumLog(dbPath string, key sigsum.PublicKey) {
	w, err := witness.NewWitness(dbPath, nil, log.Printf)
	if err != nil {
		log.Fatal(err)
	}
	if err := w.AddSigsumLog(key); err != nil {
		log.Fatal(err)
	}
	log.Printf("Added Sigsum log with public key %x.", key)
}

func listLogs(dbPath string) {
	w, err := witness.NewWitness(dbPath, nil, log.Printf)
	if err != nil {
		log.Fatal(err)
	}
	if err := w.ExecSQL(`
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

func listTreeHeads(dbPath string, onlyFailed bool) {
	w, err := witness.NewWitness(dbPath, nil, log.Printf)
	if err != nil {
		log.Fatal(err)
	}
	if err := w.ExecSQL(`
	SELECT json_details FROM tree_head
	WHERE NOT(?) OR json_extract(json_details, '$.error') IS NOT NULL
	ORDER BY json_extract(json_details, '$.timestamp') DESC
	`, func(stmt *sqlite.Stmt) error {
		_, err := fmt.Printf("%s\n", stmt.ColumnText(0))
		return err
	}, onlyFailed); err != nil {
		log.Fatal(err)
	}
}
