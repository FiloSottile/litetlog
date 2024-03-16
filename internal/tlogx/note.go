package tlogx

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"
)

const algEd25519 = 1

func NewVerifierFromSigner(skey string) (note.Verifier, error) {
	priv1, skey := chop(skey, "+")
	priv2, skey := chop(skey, "+")
	name, skey := chop(skey, "+")
	hash16, key64 := chop(skey, "+")
	hash, err1 := strconv.ParseUint(hash16, 16, 32)
	key, err2 := base64.StdEncoding.DecodeString(key64)
	if priv1 != "PRIVATE" || priv2 != "KEY" || len(hash16) != 8 || err1 != nil || err2 != nil || !isValidName(name) || len(key) == 0 {
		return nil, errors.New("malformed verifier id")
	}

	alg, key := key[0], key[1:]
	if alg != algEd25519 {
		return nil, errors.New("unknown verifier algorithm")
	}
	if len(key) != 32 {
		return nil, errors.New("malformed verifier id")
	}
	pub := ed25519.NewKeyFromSeed(key).Public().(ed25519.PublicKey)
	if uint32(hash) != keyHash(name, append([]byte{algEd25519}, pub...)) {
		return nil, errors.New("invalid verifier hash")
	}

	return &verifier{
		name: name,
		hash: uint32(hash),
		verify: func(msg, sig []byte) bool {
			return ed25519.Verify(pub, msg, sig)
		},
	}, nil
}

// chop chops s at the first instance of sep, if any,
// and returns the text before and after sep.
// If sep is not present, chop returns before is s and after is empty.
func chop(s, sep string) (before, after string) {
	i := strings.Index(s, sep)
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+len(sep):]
}
