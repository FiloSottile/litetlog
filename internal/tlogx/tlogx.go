// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found at
// https://go.googlesource.com/go/+/refs/heads/master/LICENSE.

package tlogx

import "golang.org/x/mod/sumdb/tlog"

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
