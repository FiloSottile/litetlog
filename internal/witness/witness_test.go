package witness

import (
	"crypto/ed25519"
	"encoding/hex"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/mod/sumdb/tlog"
	sigsum "sigsum.org/sigsum-go/pkg/crypto"
)

func TestRace(t *testing.T) {
	// gentest seed b4e385f4358f7373cfa9184b176f3cccf808e795baf04092ddfde9461014f0c4
	ss, err := ssh.NewSignerFromSigner(ed25519.PrivateKey(mustDecodeHex(t,
		"31ffc2116ecbe003acaa800ab70757bd7d53206e3febef6a6d0796d95530b34f"+
			"544ae249dde650fc9cd5380f3b3de0ba05cbae61906825b785f522dd3ab376c6")))
	fatalIfErr(t, err)
	w, err := NewWitness(":memory:", ss, t.Logf)
	fatalIfErr(t, err)
	t.Cleanup(func() { w.Close() })
	pk := mustDecodeHex(t, "ffdc2d4d98e4124d3feaf788c0c2f9abfd796083d1f0495437f302ec79cf100f")
	fatalIfErr(t, w.AddSigsumLog(sigsum.PublicKey(pk)))
	keyHash := mustDecodeHex(t, "4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562")

	_, _, err = w.processSigsumRequest(keyHash, 0, 1,
		tlog.Hash(mustDecodeHex(t, "2a00000000000000000000000000000000000000000000000000000000000000")),
		mustDecodeHex(t, "b7cf653aa9c565a1ca359db81bd3bc656ab2890c6ea4c0aec42295e80aa05049423505026434f987923ccdf07d440c152cd59e736e5914d8ada8d7a4d51b2106"), nil)
	fatalIfErr(t, err)

	// Stall the first request updating to the shorter size between getting
	// consistency checked and being committed to the database.
	var firstHalf, secondHalf, final sync.Mutex
	firstHalf.Lock()
	secondHalf.Lock()
	final.Lock()
	w.testingOnlyStallRequest = func() {
		firstHalf.Unlock()
		secondHalf.Lock()
	}
	go func() {
		cosig, _, err := w.processSigsumRequest(keyHash, 1, 3,
			tlog.Hash(mustDecodeHex(t, "45c088d4d939e9971298811f227d1295eaad57bbafae55cd71c171e7de48c25d")),
			mustDecodeHex(t, "655bb4871d15bc05032d67eece88900c4863a27f190393b99176391577f5def971b023d9a418c3226b7b7ea47b33686d9b3849451dadc6b07c007c595af1ea0a"), tlog.TreeProof{
				tlog.Hash(mustDecodeHex(t, "2a01000000000000000000000000000000000000000000000000000000000000")),
				tlog.Hash(mustDecodeHex(t, "2a02000000000000000000000000000000000000000000000000000000000000")),
			})
		if err != errConflict {
			t.Errorf("expected conflict, got %v", err)
		}
		if cosig != nil {
			t.Error("returned a cosignature on conflict")
		}
		final.Unlock()
	}()

	// Wait for testingOnlyStallRequest to fire.
	firstHalf.Lock()

	w.testingOnlyStallRequest = nil
	_, _, err = w.processSigsumRequest(keyHash, 1, 5,
		tlog.Hash(mustDecodeHex(t, "42bb57ad06420afa4882c4a63ac6a1ec77480b330b2f20dfc53a0caa5f564e36")),
		mustDecodeHex(t, "0fc43899968b48b5150b0e8fe7ad07b17c21c7056a6fe381deb0cd19ece103d59b2119b5dbe5d54d8a1262ce67f01245c5898b4b56f747495804a17a2eec0f0c"), tlog.TreeProof{
			tlog.Hash(mustDecodeHex(t, "2a01000000000000000000000000000000000000000000000000000000000000")),
			tlog.Hash(mustDecodeHex(t, "f9f50357e93def4078237b8aaea24ce1a3f5965a0f64ff26bebd99e30470d8b2")),
			tlog.Hash(mustDecodeHex(t, "2a04000000000000000000000000000000000000000000000000000000000000")),
		})
	if err != nil {
		t.Errorf("racing request failed: %v", err)
	}

	// Unblock testingOnlyStallRequest and wait for that request to finish.
	secondHalf.Unlock()
	final.Lock()

	size, hash, err := w.getLog("sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562")
	if err != nil {
		t.Fatal(err)
	}
	if size != 5 {
		t.Error("log got rollbacked")
	}
	if hash != tlog.Hash(mustDecodeHex(t, "42bb57ad06420afa4882c4a63ac6a1ec77480b330b2f20dfc53a0caa5f564e36")) {
		t.Error("unexpected tree hash")
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fatalIfErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
