package main

import (
	"context"
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
var keyFlag = flag.String("key", "", "SSH fingerprint of the witness key")

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
	var fingerprints []string
	for _, s := range signers {
		fingerprint := ssh.FingerprintSHA256(s.PublicKey())
		if fingerprint == *keyFlag {
			signer = s
			break
		}
		fingerprints = append(fingerprints, fingerprint)
	}
	if signer == nil {
		log.Fatalf("ssh-agent does not contain key %q, only %q", *keyFlag, fingerprints)
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
