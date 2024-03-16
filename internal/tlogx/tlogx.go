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
