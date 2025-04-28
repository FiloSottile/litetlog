// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found at
// https://go.googlesource.com/go/+/refs/heads/master/LICENSE.

package torchwood

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/tlog"
)

const maxCheckpointSize = 1e6

// A Checkpoint is a tree head to be formatted according to c2sp.org/checkpoint.
//
// A checkpoint looks like this:
//
//	example.com/origin
//	923748
//	nND/nri/U0xuHUrYSy0HtMeal2vzD9V4k/BO79C+QeI=
//
// It can be followed by extra extension lines.
type Checkpoint struct {
	Origin string
	tlog.Tree

	// Extension is empty or a sequence of non-empty lines,
	// each terminated by a newline character.
	Extension string
}

func ParseCheckpoint(text string) (Checkpoint, error) {
	// This is an extended version of tlog.ParseTree.

	if strings.Count(text, "\n") < 3 || len(text) > maxCheckpointSize {
		return Checkpoint{}, errors.New("malformed checkpoint")
	}
	if !strings.HasSuffix(text, "\n") {
		return Checkpoint{}, errors.New("malformed checkpoint")
	}

	lines := strings.SplitN(text, "\n", 4)

	n, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || n < 0 || lines[1] != strconv.FormatInt(n, 10) {
		return Checkpoint{}, errors.New("malformed checkpoint")
	}

	h, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(h) != tlog.HashSize {
		return Checkpoint{}, errors.New("malformed checkpoint")
	}

	rest := lines[3]
	for rest != "" {
		before, after, found := strings.Cut(rest, "\n")
		if before == "" || !found {
			return Checkpoint{}, errors.New("malformed checkpoint")
		}
		rest = after
	}

	var hash tlog.Hash
	copy(hash[:], h)
	return Checkpoint{lines[0], tlog.Tree{N: n, Hash: hash}, lines[3]}, nil
}

func (c Checkpoint) String() string {
	return fmt.Sprintf("%s\n%d\n%s\n%s",
		c.Origin,
		c.N,
		base64.StdEncoding.EncodeToString(c.Hash[:]),
		c.Extension,
	)
}
