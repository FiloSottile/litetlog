package mpt_test

import (
	"encoding/binary"
	"encoding/hex"
	"math/rand/v2"
	"testing"

	"lukechampine.com/blake3"

	. "filippo.io/torchwood/mpt"
)

func TestFullTree(t *testing.T) {
	store := NewMemoryStorage()
	fatalIfErr(t, InitStorage(blake3.Sum256, store))
	tree := NewTree(blake3.Sum256, store)

	for n := range 1000 {
		var label [32]byte
		binary.LittleEndian.PutUint16(label[:], uint16(n))
		value := blake3.Sum256(label[:])
		fatalIfErr(t, tree.Insert(label, value))
	}

	root, err := store.Load(RootLabel)
	fatalIfErr(t, err)
	rootHash := root.Hash

	store = NewMemoryStorage()
	fatalIfErr(t, InitStorage(blake3.Sum256, store))
	tree = NewTree(blake3.Sum256, store)

	for n := 999; n >= 0; n-- {
		var label [32]byte
		binary.LittleEndian.PutUint16(label[:], uint16(n))
		value := blake3.Sum256(label[:])
		fatalIfErr(t, tree.Insert(label, value))
	}

	root, err = store.Load(RootLabel)
	fatalIfErr(t, err)
	if root.Hash != rootHash {
		t.Fatalf("after inserting in reverse order: got %x, want %x", root.Hash, rootHash)
	}

	store = NewMemoryStorage()
	fatalIfErr(t, InitStorage(blake3.Sum256, store))
	tree = NewTree(blake3.Sum256, store)

	for _, n := range rand.Perm(1000) {
		var label [32]byte
		binary.LittleEndian.PutUint16(label[:], uint16(n))
		value := blake3.Sum256(label[:])
		fatalIfErr(t, tree.Insert(label, value))
	}

	root, err = store.Load(RootLabel)
	fatalIfErr(t, err)
	if root.Hash != rootHash {
		t.Fatalf("after inserting in random order: got %x, want %x", root.Hash, rootHash)
	}
}

func TestAccumulated(t *testing.T) {
	source := blake3.New(0, nil).XOF()
	sink := blake3.New(32, nil)

	for range 100 {
		store := NewMemoryStorage()
		fatalIfErr(t, InitStorage(blake3.Sum256, store))
		tree := NewTree(blake3.Sum256, store)
		root, err := store.Load(RootLabel)
		fatalIfErr(t, err)
		sink.Write(root.Hash[:])
		for range 1000 {
			var label, value [32]byte
			source.Read(label[:])
			source.Read(value[:])
			fatalIfErr(t, tree.Insert(label, value))
			root, err := store.Load(RootLabel)
			fatalIfErr(t, err)
			sink.Write(root.Hash[:])
		}
	}

	exp := "dfa5cc5758518f612c53d3434688996895373f29e2df61b7f7c26f0e25b095eb"
	result := sink.Sum(nil)
	if hex.EncodeToString(result) != exp {
		t.Fatalf("expected hash %s, got %x", exp, result)
	}
}

func fatalIfErr(t *testing.T, err error) {
	if err != nil {
		t.Helper()
		t.Fatal(err)
	}
}
