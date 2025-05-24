// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found at
// https://go.googlesource.com/go/+/refs/heads/master/LICENSE.

// Package torchwood implements a tlog client and various c2sp.org/signed-note,
// c2sp.org/tlog-cosignature, c2sp.org/tlog-checkpoint, and c2sp.org/tlog-tiles
// functions, including extensions to the [golang.org/x/mod/sumdb/tlog] and
// [golang.org/x/mod/sumdb/note] packages.
package torchwood

import (
	"errors"
	"fmt"

	"golang.org/x/mod/sumdb/tlog"
)

// RightEdge returns the stored hash indexes of the right edge of a tree of
// size n. These are the same hashes that are combined into a [tlog.TreeHash]
// and allow producing record and tree proofs for any size bigger than n. See
// [tlog.StoredHashIndex] for the definition of stored hash indexes.
func RightEdge(n int64) []int64 {
	var lo int64
	var idx []int64
	for lo < n {
		k, level := maxpow2(n - lo + 1)
		idx = append(idx, tlog.StoredHashIndex(level, lo>>level))
		lo += k
	}
	return idx
}

// A HashProof is a verifiable proof that a particular tree head contains a
// particular sub-tree hash. A [tlog.RecordProof] is a special case of a
// HashProof where the sub-tree has height 0.
type HashProof []tlog.Hash

// ProveHash returns the proof that the tree of size t contains the hash with
// [tlog.StoredHashIndex] i.
func ProveHash(t, i int64, r tlog.HashReader) (HashProof, error) {
	if t < 0 || i < 0 || i >= tlog.StoredHashIndex(0, t) {
		return nil, fmt.Errorf("tlog: invalid inputs in ProveHash")
	}
	indexes := hashProofIndex(0, t, i, nil)
	if len(indexes) == 0 {
		return HashProof{}, nil
	}
	hashes, err := r.ReadHashes(indexes)
	if err != nil {
		return nil, err
	}
	if len(hashes) != len(indexes) {
		return nil, fmt.Errorf("tlog: ReadHashes(%d indexes) = %d hashes", len(indexes), len(hashes))
	}

	p, hashes := hashProof(0, t, i, hashes)
	if len(hashes) != 0 {
		panic("tlog: bad index math in ProveHash")
	}
	return p, nil
}

// hashProofIndex builds the list of indexes needed to construct the proof
// that hash i is contained in the subtree with leaves [lo, hi).
// It appends those indexes to need and returns the result.
func hashProofIndex(lo, hi, i int64, need []int64) []int64 {
	l, n := tlog.SplitStoredHashIndex(i)
	if !(lo <= n<<l && (n+1)<<l <= hi) {
		panic("tlog: bad math in hashProofIndex")
	}
	if lo == n<<l && (n+1)<<l == hi {
		return need
	}
	if k, _ := maxpow2(hi - lo); n<<l < lo+k {
		need = hashProofIndex(lo, lo+k, i, need)
		need = subTreeIndex(lo+k, hi, need)
	} else {
		need = subTreeIndex(lo, lo+k, need)
		need = hashProofIndex(lo+k, hi, i, need)
	}
	return need
}

// hashProof constructs the proof that hash i is contained in the subtree with leaves [lo, hi).
// It returns any leftover hashes as well.
func hashProof(lo, hi, i int64, hashes []tlog.Hash) (HashProof, []tlog.Hash) {
	l, n := tlog.SplitStoredHashIndex(i)
	if !(lo <= n<<l && (n+1)<<l <= hi) {
		panic("tlog: bad math in hashProof")
	}
	if lo == n<<l && (n+1)<<l == hi {
		return HashProof{}, hashes
	}
	var p HashProof
	var th tlog.Hash
	if k, _ := maxpow2(hi - lo); n<<l < lo+k {
		p, hashes = hashProof(lo, lo+k, i, hashes)
		th, hashes = subTreeHash(lo+k, hi, hashes)
	} else {
		th, hashes = subTreeHash(lo, lo+k, hashes)
		p, hashes = hashProof(lo+k, hi, i, hashes)
	}
	return append(p, th), hashes
}

var errProofFailed = errors.New("invalid transparency proof")

// CheckHash verifies that p is a valid proof that the tree of size t
// with hash th has an i'th hash with hash h.
func CheckHash(p HashProof, t int64, th tlog.Hash, i int64, h tlog.Hash) error {
	if t < 0 || i < 0 || i >= tlog.StoredHashIndex(0, t) {
		return fmt.Errorf("tlog: invalid inputs in CheckHash")
	}
	th2, err := runHashProof(p, 0, t, i, h)
	if err != nil {
		return err
	}
	if th2 == th {
		return nil
	}
	return errProofFailed
}

// runHashProof runs the proof p that hash i is contained in the subtree with leaves [lo, hi).
// Running the proof means constructing and returning the implied hash of that subtree.
func runHashProof(p HashProof, lo, hi, i int64, h tlog.Hash) (tlog.Hash, error) {
	l, n := tlog.SplitStoredHashIndex(i)
	if !(lo <= n<<l && (n+1)<<l <= hi) {
		panic("tlog: bad math in runHashProof")
	}
	if lo == n<<l && (n+1)<<l == hi {
		if len(p) != 0 {
			return tlog.Hash{}, errProofFailed
		}
		return h, nil
	}
	if len(p) == 0 {
		return tlog.Hash{}, errProofFailed
	}
	k, _ := maxpow2(hi - lo)
	if n<<l < lo+k {
		th, err := runHashProof(p[:len(p)-1], lo, lo+k, i, h)
		if err != nil {
			return tlog.Hash{}, err
		}
		return tlog.NodeHash(th, p[len(p)-1]), nil
	} else {
		th, err := runHashProof(p[:len(p)-1], lo+k, hi, i, h)
		if err != nil {
			return tlog.Hash{}, err
		}
		return tlog.NodeHash(p[len(p)-1], th), nil
	}
}

// The functions below are unmodified copies from package tlog.

// subTreeIndex returns the storage indexes needed to compute
// the hash for the subtree containing records [lo, hi),
// appending them to need and returning the result.
// See https://tools.ietf.org/html/rfc6962#section-2.1
func subTreeIndex(lo, hi int64, need []int64) []int64 {
	// See subTreeHash below for commentary.
	for lo < hi {
		k, level := maxpow2(hi - lo + 1)
		if lo&(k-1) != 0 {
			panic("tlog: bad math in subTreeIndex")
		}
		need = append(need, tlog.StoredHashIndex(level, lo>>uint(level)))
		lo += k
	}
	return need
}

// subTreeHash computes the hash for the subtree containing records [lo, hi),
// assuming that hashes are the hashes corresponding to the indexes
// returned by subTreeIndex(lo, hi).
// It returns any leftover hashes.
func subTreeHash(lo, hi int64, hashes []tlog.Hash) (tlog.Hash, []tlog.Hash) {
	// Repeatedly partition the tree into a left side with 2^level nodes,
	// for as large a level as possible, and a right side with the fringe.
	// The left hash is stored directly and can be read from storage.
	// The right side needs further computation.
	numTree := 0
	for lo < hi {
		k, _ := maxpow2(hi - lo + 1)
		if lo&(k-1) != 0 || lo >= hi {
			panic("tlog: bad math in subTreeHash")
		}
		numTree++
		lo += k
	}

	if len(hashes) < numTree {
		panic("tlog: bad index math in subTreeHash")
	}

	// Reconstruct hash.
	h := hashes[numTree-1]
	for i := numTree - 2; i >= 0; i-- {
		h = tlog.NodeHash(hashes[i], h)
	}
	return h, hashes[numTree:]
}

// maxpow2 returns k, the maximum power of 2 smaller than n,
// as well as l = log₂ k (so k = 1<<l).
func maxpow2(n int64) (k int64, l int) {
	l = 0
	for 1<<(l+1) < n {
		l++
	}
	return 1 << l, l
}
