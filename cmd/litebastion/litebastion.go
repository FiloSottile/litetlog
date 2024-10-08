// Command litebastion runs a reverse proxy service that allows un-addressable
// applications (for example those running behind a firewall or a NAT, or where
// the operator doesn't wish to take the DoS risk of being reachable from the
// Internet) to accept HTTP requests.
//
// Backends are identified by an Ed25519 public key, they authenticate with a
// self-signed TLS 1.3 certificate, and are reachable at a sub-path prefixed by
// the key hash.
//
// Read more at https://c2sp.org/https-bastion.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"filippo.io/litetlog/bastion"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
)

var listenAddr = flag.String("listen", "localhost:8443", "host and port to listen at")
var testCertificates = flag.Bool("testcert", false, "use localhost.pem and localhost-key.pem instead of ACME")
var autocertCache = flag.String("cache", "", "directory to cache ACME certificates at")
var autocertHost = flag.String("host", "", "host to obtain ACME certificate for")
var autocertEmail = flag.String("email", "", "")
var allowedBackendsFile = flag.String("backends", "", "file of accepted key hashes, one per line, reloaded on SIGHUP")

type keyHash [sha256.Size]byte

func main() {
	flag.BoolVar(&http2.VerboseLogs, "h2v", false, "enable HTTP/2 verbose logs")
	flag.Parse()

	var getCertificate func(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
	if *testCertificates {
		cert, err := tls.LoadX509KeyPair("localhost.pem", "localhost-key.pem")
		if err != nil {
			log.Fatalf("can't load test certificates: %v", err)
		}
		getCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &cert, nil
		}
	} else {
		if *autocertCache == "" || *autocertHost == "" || *autocertEmail == "" {
			log.Fatal("-cache, -host, and -email or -testcert are required")
		}
		m := &autocert.Manager{
			Cache:      autocert.DirCache(*autocertCache),
			Prompt:     autocert.AcceptTOS,
			Email:      *autocertEmail,
			HostPolicy: autocert.HostWhitelist(*autocertHost),
		}
		getCertificate = m.GetCertificate
	}

	if *allowedBackendsFile == "" {
		log.Fatal("-backends is missing")
	}
	var allowedBackendsMu sync.RWMutex
	var allowedBackends map[keyHash]bool
	reloadBackends := func() error {
		newBackends := make(map[keyHash]bool)
		backendsList, err := os.ReadFile(*allowedBackendsFile)
		if err != nil {
			return err
		}
		bs := strings.TrimSpace(string(backendsList))
		for _, line := range strings.Split(bs, "\n") {
			l, err := hex.DecodeString(line)
			if err != nil {
				return fmt.Errorf("invalid backend: %q", line)
			}
			if len(l) != sha256.Size {
				return fmt.Errorf("invalid backend: %q", line)
			}
			h := keyHash(l)
			newBackends[h] = true
		}
		allowedBackendsMu.Lock()
		defer allowedBackendsMu.Unlock()
		allowedBackends = newBackends
		return nil
	}
	if err := reloadBackends(); err != nil {
		log.Fatalf("failed to load backends: %v", err)
	}
	log.Printf("loaded %d backends", len(allowedBackends))
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for range c {
			if err := reloadBackends(); err != nil {
				log.Printf("failed to reload backends: %v", err)
			} else {
				log.Printf("reloaded backends")
			}
		}
	}()

	b, err := bastion.New(&bastion.Config{
		AllowedBackend: func(keyHash [sha256.Size]byte) bool {
			allowedBackendsMu.RLock()
			defer allowedBackendsMu.RUnlock()
			return allowedBackends[keyHash]
		},
		GetCertificate: getCertificate,
	})
	if err != nil {
		log.Fatalf("failed to load bastion: %v", err)
	}

	hs := &http.Server{
		Addr:         *listenAddr,
		Handler:      http.MaxBytesHandler(b, 10*1024),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			NextProtos:     []string{acme.ALPNProto},
			GetCertificate: getCertificate,
		},
	}
	if err := b.ConfigureServer(hs); err != nil {
		log.Fatalln("failed to configure bastion:", err)
	}
	if err := http2.ConfigureServer(hs, nil); err != nil {
		log.Fatalln("failed to configure HTTP/2:", err)
	}

	log.Printf("listening on %s", *listenAddr)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	e := make(chan error, 1)
	go func() { e <- hs.ListenAndServeTLS("", "") }()
	select {
	case <-ctx.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(ctx)
	case err := <-e:
		log.Fatalf("server error: %v", err)
	}
}
