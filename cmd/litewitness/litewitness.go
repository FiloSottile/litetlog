package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/net/http2"

	"filippo.io/litetlog/internal/witness"
)

var nameFlag = flag.String("name", "", "URL-like (e.g. example.com/foo) name of this witness")
var dbFlag = flag.String("db", "litewitness.db", "path to sqlite database")
var sshAgentFlag = flag.String("ssh-agent", "litewitness.sock", "path to ssh-agent socket")
var listenFlag = flag.String("listen", "localhost:7380", "address to listen for HTTP requests")
var keyFlag = flag.String("key", "", "hex-encoded SHA-256 hash of the witness key")
var bastionFlag = flag.String("bastion", "", "address of the bastion(s) to reverse proxy through, comma separated, the first online one is selected")
var testCertFlag = flag.Bool("testcert", false, "use rootCA.pem for connections to the bastion")

func main() {
	flag.Parse()

	signer := connectToSSHAgent()

	w, err := witness.NewWitness(*dbFlag, *nameFlag, signer, log.Printf)
	if err != nil {
		log.Fatalf("creating witness: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	srv := &http.Server{
		Addr:         *listenFlag,
		Handler:      http.MaxBytesHandler(w, 10*1024),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		BaseContext:  func(net.Listener) context.Context { return ctx },
	}
	e := make(chan error, 1)
	if *bastionFlag != "" {
		go func() {
			for _, bastion := range strings.Split(*bastionFlag, ",") {
				log.Printf("connecting to bastion at %s", bastion)
				err := connectToBastion(ctx, bastion, signer, srv)
				if err == errBastionDisconnected {
					// Connection succeeded and then was interrupted. Restart to
					// let the scheduler apply any backoff, and then retry all bastions.
					e <- err
					return
				}
				log.Printf("connecting to bastion at %s failed: %v", bastion, err)
			}
			e <- errors.New("couldn't connect to any bastion")
		}()
	} else {

		go func() {
			log.Printf("listening on %s", *listenFlag)
			e <- srv.ListenAndServe()
		}()
	}

	select {
	case <-ctx.Done():
		log.Printf("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	case err := <-e:
		log.Fatalf("server error: %v", err)
	}
}

func connectToSSHAgent() *signer {
	conn, err := net.Dial("unix", *sshAgentFlag)
	if err != nil {
		log.Fatalf("dialing ssh-agent: %v", err)
	}
	a := agent.NewClient(conn)
	signers, err := a.Signers()
	if err != nil {
		log.Fatalf("getting keys from ssh-agent: %v", err)
	}
	log.Printf("connected to ssh-agent at %s", *sshAgentFlag)
	var signer *signer
	var keys []string
	for _, s := range signers {
		if s.PublicKey().Type() != ssh.KeyAlgoED25519 {
			continue
		}
		ss, err := newSigner(s)
		if err != nil {
			log.Fatal(err)
		}
		hh := sha256.Sum256(ss.Public().(ed25519.PublicKey))
		h := hex.EncodeToString(hh[:])
		if h == *keyFlag {
			signer = ss
			break
		}
		keys = append(keys, h)
	}
	if signer == nil {
		log.Fatalf("ssh-agent does not contain Ed25519 key %q, only %q", *keyFlag, keys)
	}
	log.Printf("found key %s", *keyFlag)
	return signer
}

type signer struct {
	s ssh.Signer
	p ed25519.PublicKey
}

func newSigner(s ssh.Signer) (*signer, error) {
	// agent.Key doesn't implement ssh.CryptoPublicKey.
	k, err := ssh.ParsePublicKey(s.PublicKey().Marshal())
	if err != nil {
		return nil, errors.New("internal error: ssh public key can't be parsed")
	}
	ck, ok := k.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errors.New("internal error: ssh public key can't be retrieved")
	}
	pk, ok := ck.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("internal error: ssh public key type is not Ed25519")
	}
	return &signer{s: s, p: pk}, nil
}

func (s *signer) Public() crypto.PublicKey {
	return s.p
}

func (s *signer) Sign(rand io.Reader, data []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("expected crypto.Hash(0)")
	}
	sig, err := s.s.Sign(rand, data)
	if err != nil {
		return nil, err
	}
	return sig.Blob, nil
}

var errBastionDisconnected = errors.New("connection to bastion interrupted")

func connectToBastion(ctx context.Context, bastion string, signer *signer, srv *http.Server) error {
	cert, err := selfSignedCertificate(signer)
	if err != nil {
		log.Fatalf("generating self-signed certificate: %v", err)
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var roots *x509.CertPool
	if *testCertFlag {
		roots = x509.NewCertPool()
		root, err := os.ReadFile("rootCA.pem")
		if err != nil {
			log.Fatalf("reading test root: %v", err)
		}
		roots.AppendCertsFromPEM(root)
	}
	conn, err := (&tls.Dialer{
		Config: &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{cert},
				PrivateKey:  signer,
			}},
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			NextProtos: []string{"bastion/0"},
			RootCAs:    roots,
		},
	}).DialContext(dialCtx, "tcp", bastion)
	if err != nil {
		return fmt.Errorf("connecting to bastion: %v", err)
	}
	log.Printf("connected to bastion at %s", bastion)
	// TODO: find a way to surface the fatal error, especially since with
	// TLS 1.3 it might be that the bastion rejected the client certificate.
	(&http2.Server{
		CountError: func(errType string) {
			if http2.VerboseLogs {
				log.Printf("HTTP/2 server error: %v", errType)
			}
		},
	}).ServeConn(conn, &http2.ServeConnOpts{
		Context:    ctx,
		BaseConfig: srv,
		Handler:    srv.Handler,
	})
	return errBastionDisconnected
}

func selfSignedCertificate(key crypto.Signer) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "litewitness"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
}
