// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found at
// https://go.googlesource.com/go/+/refs/heads/master/LICENSE.

package tlogx

import "golang.org/x/mod/sumdb/tlog"

// TileParent returns t's k'th tile parent in the tiles for a tree of size n.
// If there is no such parent, ok is false.
func TileParent(t tlog.Tile, k int, n int64) (parent tlog.Tile, ok bool) {
	t.L += k
	t.N >>= k * t.H
	t.W = 1 << t.H
	if max := n >> (t.L * t.H); t.N<<t.H+int64(t.W) >= max {
		if t.N<<t.H >= max {
			return parent, false
		}
		t.W = int(max - t.N<<t.H)
	}
	return t, true
}

// PartialTiles returns the partial tiles for a tree of size n.
func PartialTiles(h int, n int64) []tlog.Tile {
	var partial []tlog.Tile
	t := tlog.TileForIndex(h, tlog.StoredHashIndex(0, n-1))
	for {
		if t.W < 1<<t.H {
			partial = append(partial, t)
		}
		var ok bool
		t, ok = TileParent(t, 1, n)
		if !ok {
			break
		}
	}
	return partial
}

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

// maxpow2 returns k, the maximum power of 2 smaller than n,
// as well as l = log₂ k (so k = 1<<l).
func maxpow2(n int64) (k int64, l int) {
	l = 0
	for 1<<(l+1) < n {
		l++
	}
	return 1 << l, l
}
