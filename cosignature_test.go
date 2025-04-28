package torchwood_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
)

func TestSignerRoundtrip(t *testing.T) {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	s, err := torchwood.NewCosignatureSigner("example.com", k)
	if err != nil {
		t.Fatal(err)
	}

	msg := "test\n123\nf+7CoKgXKE/tNys9TTXcr/ad6U/K3xvznmzew9y6SP0=\n"
	n, err := note.Sign(&note.Note{Text: msg}, s)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := note.Open(n, note.VerifierList(s.Verifier())); err != nil {
		t.Fatal(err)
	}
}
