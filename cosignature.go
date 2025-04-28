// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found at
// https://go.googlesource.com/go/+/refs/heads/master/LICENSE.

package torchwood

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/mod/sumdb/note"
)

const algCosignatureV1 = 4

// NewCosignatureSigner constructs a new [CosignatureSigner] from an Ed25519
// private key.
func NewCosignatureSigner(name string, key crypto.Signer) (*CosignatureSigner, error) {
	if !isValidName(name) {
		return nil, errors.New("invalid name")
	}
	k, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("key type is not Ed25519")
	}

	s := &CosignatureSigner{}
	s.v.name = name
	s.v.hash = keyHash(name, append([]byte{algCosignatureV1}, k...))
	s.v.key = k
	s.sign = func(msg []byte) ([]byte, error) {
		t := uint64(time.Now().Unix())
		m, err := formatCosignatureV1(t, msg)
		if err != nil {
			return nil, err
		}
		s, err := key.Sign(nil, m, crypto.Hash(0))
		if err != nil {
			return nil, err
		}

		// The signature itself is encoded as timestamp || signature.
		sig := make([]byte, 0, 8+ed25519.SignatureSize)
		sig = binary.BigEndian.AppendUint64(sig, t)
		sig = append(sig, s...)
		return sig, nil
	}
	s.v.verify = func(msg, sig []byte) bool {
		if len(sig) != 8+ed25519.SignatureSize {
			return false
		}
		t := binary.BigEndian.Uint64(sig)
		sig = sig[8:]
		m, err := formatCosignatureV1(t, msg)
		if err != nil {
			return false
		}
		return ed25519.Verify(k, m, sig)
	}

	return s, nil
}

func formatCosignatureV1(t uint64, msg []byte) ([]byte, error) {
	// The signed message is in the following format
	//
	//      cosignature/v1
	//      time TTTTTTTTTT
	//      origin line
	//      NNNNNNNNN
	//      tree hash
	//
	// where TTTTTTTTTT is the current UNIX timestamp, and the following
	// three lines are the first three lines of the note. All other
	// lines are not processed by the witness, so are not signed.

	c, err := ParseCheckpoint(string(msg))
	if err != nil {
		return nil, fmt.Errorf("message being signed is not a valid checkpoint: %w", err)
	}
	return []byte(fmt.Sprintf(
		"cosignature/v1\ntime %d\n%s\n%d\n%s\n",
		t, c.Origin, c.N, base64.StdEncoding.EncodeToString(c.Hash[:]))), nil
}

// CosignatureSigner is a [note.Signer] that produces timestamped
// cosignatures according to c2sp.org/tlog-cosignature.
type CosignatureSigner struct {
	v    CosignatureVerifier
	sign func([]byte) ([]byte, error)
}

func (s *CosignatureSigner) Name() string                    { return s.v.Name() }
func (s *CosignatureSigner) KeyHash() uint32                 { return s.v.KeyHash() }
func (s *CosignatureSigner) Sign(msg []byte) ([]byte, error) { return s.sign(msg) }
func (s *CosignatureSigner) Verifier() *CosignatureVerifier  { return &s.v }

var _ note.Signer = &CosignatureSigner{}

// CosignatureVerifier is a [note.Verifier] that verifies cosignatures
// according to c2sp.org/tlog-cosignature.
type CosignatureVerifier struct {
	verifier
	key ed25519.PublicKey
}

var _ note.Verifier = &CosignatureVerifier{}

// String returns the vkey encoding of the verifier, according to
// c2sp.org/signed-note.
func (v *CosignatureVerifier) String() string {
	return fmt.Sprintf("%s+%08x+%s", v.name, v.hash, base64.StdEncoding.EncodeToString(
		append([]byte{algCosignatureV1}, v.key...)))
}

// isValidName reports whether name is valid.
// It must be non-empty and not have any Unicode spaces or pluses.
func isValidName(name string) bool {
	return name != "" && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.Contains(name, "+")
}

func keyHash(name string, key []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(key)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum)
}
