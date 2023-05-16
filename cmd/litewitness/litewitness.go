package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"filippo.io/litetlog/internal/witness"
)

var dbFlag = flag.String("db", "litewitness.db", "path to sqlite database")
var sshAgentFlag = flag.String("ssh-agent", "litewitness.sock", "path to ssh-agent socket")
var listenFlag = flag.String("listen", "localhost:7380", "address to listen for HTTP requests")
var keyFlag = flag.String("key", "", "hex-encoded SHA-256 hash of the witness key")

func main() {
	flag.Parse()

	conn, err := net.Dial("unix", *sshAgentFlag)
	if err != nil {
		log.Fatalf("dialing ssh-agent: %v", err)
	}
	defer conn.Close()
	a := agent.NewClient(conn)
	signers, err := a.Signers()
	if err != nil {
		log.Fatalf("getting keys from ssh-agent: %v", err)
	}
	var signer ssh.Signer
	var keys []string
	for _, s := range signers {
		h, err := hashPublicKey(s.PublicKey())
		if err != nil {
			continue
		}
		if h == *keyFlag {
			signer = s
			break
		}
		keys = append(keys, h)
	}
	if signer == nil {
		log.Fatalf("ssh-agent does not contain Ed25519 key %q, only %q", *keyFlag, keys)
	}

	w, err := witness.NewWitness(*dbFlag, signer, log.Printf)
	if err != nil {
		log.Fatalf("creating witness: %v", err)
	}

	s := &http.Server{
		Addr:         *listenFlag,
		Handler:      http.MaxBytesHandler(w, 10*1024),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	go func() {
		if err := s.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("listen error: %v", err)
		}
	}()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := s.Shutdown(ctx); err != nil {
		log.Fatalf("error shutting down: %v", err)
	}
	cancel()
}

func hashPublicKey(k ssh.PublicKey) (string, error) {
	// agent.Key doesn't implement ssh.CryptoPublicKey.
	pubKey, err := ssh.ParsePublicKey(k.Marshal())
	if err != nil {
		panic("internal error: ssh public key can't be parsed")
	}
	ck, ok := pubKey.(ssh.CryptoPublicKey)
	if !ok {
		panic("internal error: ssh public key can't be retrieved")
	}
	key, ok := ck.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return "", errors.New("internal error: ssh public key type is not Ed25519")
	}
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:]), nil
}
