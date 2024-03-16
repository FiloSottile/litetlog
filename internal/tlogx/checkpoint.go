// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found at
// https://go.googlesource.com/go/+/refs/heads/master/LICENSE.

package tlogx

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/tlog"
)

const maxCheckpointSize = 1e6

type Checkpoint struct {
	Origin    string
	N         int64
	Hash      tlog.Hash
	Extension string
}

func ParseCheckpoint(text string) (Checkpoint, error) {
	// This is an extended version of tlog.ParseTree.
	//
	// A checkpoint looks like:
	//
	//	example.com/origin
	//	2
	//	nND/nri/U0xuHUrYSy0HtMeal2vzD9V4k/BO79C+QeI=
	//
	// It can be followed by extra extension lines.

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
	return Checkpoint{lines[0], n, hash, lines[3]}, nil
}

func MarshalCheckpoint(c Checkpoint) string {
	return fmt.Sprintf("%s\n%d\n%s\n%s",
		c.Origin, c.N, base64.StdEncoding.EncodeToString(c.Hash[:]), c.Extension)
}
