//go:build go1.24

package mpt_test

import (
	"encoding/binary"
	"encoding/hex"
	"math/rand/v2"
	"testing"

	"lukechampine.com/blake3"

	. "filippo.io/torchwood/mpt"
	"filippo.io/torchwood/mpt/mptsqlite"
)

func testAllStorage(t *testing.T, f func(t *testing.T, newStorage func(t *testing.T) Storage)) {
	t.Run("memory", func(t *testing.T) {
		f(t, func(t *testing.T) Storage {
			return NewMemoryStorage()
		})
	})

	t.Run("sqlite", func(t *testing.T) {
		f(t, func(t *testing.T) Storage {
			store, err := mptsqlite.NewSQLiteStorage(t.Context(), "file::memory:?cache=shared")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { fatalIfErr(t, store.Close()) })
			return store
		})
	})
}

func TestFullTree(t *testing.T) {
	testAllStorage(t, testFullTree)
}
func testFullTree(t *testing.T, newStorage func(t *testing.T) Storage) {
	store := newStorage(t)
	fatalIfErr(t, InitStorage(t.Context(), blake3.Sum256, store))
	tree := NewTree(blake3.Sum256, store)

	for n := range 1000 {
		var label [32]byte
		binary.LittleEndian.PutUint16(label[:], uint16(n))
		value := blake3.Sum256(label[:])
		fatalIfErr(t, tree.Insert(t.Context(), label, value))
	}

	root, err := store.Load(t.Context(), RootLabel)
	fatalIfErr(t, err)
	rootHash := root.Hash

	store = newStorage(t)
	fatalIfErr(t, InitStorage(t.Context(), blake3.Sum256, store))
	tree = NewTree(blake3.Sum256, store)

	for n := 999; n >= 0; n-- {
		var label [32]byte
		binary.LittleEndian.PutUint16(label[:], uint16(n))
		value := blake3.Sum256(label[:])
		fatalIfErr(t, tree.Insert(t.Context(), label, value))
	}

	root, err = store.Load(t.Context(), RootLabel)
	fatalIfErr(t, err)
	if root.Hash != rootHash {
		t.Fatalf("after inserting in reverse order: got %x, want %x", root.Hash, rootHash)
	}

	store = newStorage(t)
	fatalIfErr(t, InitStorage(t.Context(), blake3.Sum256, store))
	tree = NewTree(blake3.Sum256, store)

	for _, n := range rand.Perm(1000) {
		var label [32]byte
		binary.LittleEndian.PutUint16(label[:], uint16(n))
		value := blake3.Sum256(label[:])
		fatalIfErr(t, tree.Insert(t.Context(), label, value))
	}

	root, err = store.Load(t.Context(), RootLabel)
	fatalIfErr(t, err)
	if root.Hash != rootHash {
		t.Fatalf("after inserting in random order: got %x, want %x", root.Hash, rootHash)
	}
}

func TestAccumulated(t *testing.T) {
	testAllStorage(t, testAccumulated)
}
func testAccumulated(t *testing.T, newStorage func(t *testing.T) Storage) {
	source := blake3.New(0, nil).XOF()
	sink := blake3.New(32, nil)

	for range 100 {
		store := newStorage(t)
		fatalIfErr(t, InitStorage(t.Context(), blake3.Sum256, store))
		tree := NewTree(blake3.Sum256, store)
		root, err := store.Load(t.Context(), RootLabel)
		fatalIfErr(t, err)
		sink.Write(root.Hash[:])
		for range 1000 {
			var label, value [32]byte
			source.Read(label[:])
			source.Read(value[:])
			fatalIfErr(t, tree.Insert(t.Context(), label, value))
			root, err := store.Load(t.Context(), RootLabel)
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
