package tlogclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/litetlog/internal/tlogx"
	"golang.org/x/mod/sumdb/tlog"
	"golang.org/x/sync/errgroup"
)

const tileHeight = 8
const tileWidth = 1 << tileHeight

type Client struct {
	tr  tlog.TileReader
	cut func([]byte) ([]byte, tlog.Hash, []byte, error)
	err error
}

func NewClient(tr tlog.TileReader) *Client {
	tr = &edgeMemoryCache{tr: tr, t: make(map[int][2]tileWithData)}
	return &Client{tr: tr}
}

// SetCutEntry sets the function to split the next entry from a tile.
//
// The entry is surfaced by the Entries method, the record hash is used to check
// inclusion in the tree, and the rest is passed to the next invocation of cut.
//
// The input tile is never empty. cut must not modify the tile.
func (c *Client) SetCutEntry(cut func(tile []byte) (entry []byte, rh tlog.Hash, rest []byte, err error)) {
	c.cut = cut
}

func (c *Client) Error() error {
	return c.err
}

func (c *Client) Entries(tree tlog.Tree, start int64) iter.Seq2[int64, []byte] {
	return func(yield func(int64, []byte) bool) {
		if c.err != nil {
			return
		}
		for {
			base := start / tileWidth * tileWidth
			// In regular operations, don't actually fetch the trailing partial
			// tile, to avoid duplicating that traffic in steady state. The
			// assumption is that a future call to Entries will pass a bigger
			// tree where that tile is full. However, if the tree grows too
			// slowly, we'll get another call where start is at the beginning of
			// the partial tile; in that case, fetch it.
			top := tree.N / tileWidth * tileWidth
			if top-base == 0 {
				top = tree.N
			}
			tiles := make([]tlog.Tile, 0, 50)
			for i := 0; i < 50; i++ {
				tileStart := base + int64(i)*tileWidth
				if tileStart >= top {
					break
				}
				tileEnd := tileStart + tileWidth
				if tileEnd > top {
					tileEnd = top
				}
				tiles = append(tiles, tlog.Tile{H: tileHeight, L: -1,
					N: tileStart / tileWidth, W: int(tileEnd - tileStart)})
			}
			if len(tiles) == 0 {
				return
			}
			tdata, err := c.tr.ReadTiles(tiles)
			if err != nil {
				c.err = err
				return
			}

			// TODO: hash data tile directly against level 8 hash.
			indexes := make([]int64, 0, tileWidth*len(tiles))
			for _, t := range tiles {
				for i := range t.W {
					indexes = append(indexes, tlog.StoredHashIndex(0, t.N*tileWidth+int64(i)))
				}
			}
			hashes, err := tlog.TileHashReader(tree, c.tr).ReadHashes(indexes)
			if err != nil {
				c.err = err
				return
			}

			for ti, t := range tiles {
				tileStart := t.N * tileWidth
				tileEnd := tileStart + int64(t.W)
				data := tdata[ti]
				for i := tileStart; i < tileEnd; i++ {
					if len(data) == 0 {
						c.err = fmt.Errorf("unexpected end of tile data for tile %d", t.N)
						return
					}

					entry, rh, rest, err := c.cut(data)
					if err != nil {
						c.err = fmt.Errorf("failed to cut entry %d: %w", i, err)
						return
					}
					data = rest

					if rh != hashes[i-base] {
						c.err = fmt.Errorf("hash mismatch for entry %d", i)
						return
					}

					if i < start {
						continue
					}
					if !yield(i, entry) {
						return
					}
				}
				if len(data) != 0 {
					c.err = fmt.Errorf("unexpected leftover data in tile %d", t.N)
					return
				}
				start = tileEnd
			}

			c.tr.SaveTiles(tiles, tdata)

			if start == top {
				return
			}
		}
	}
}

func CutSumDBEntry(tile []byte) (entry []byte, rh tlog.Hash, rest []byte, err error) {
	if idx := bytes.Index(tile, []byte("\n\n")); idx >= 0 {
		// Add back one of the newlines.
		entry, rest = tile[:idx+1], tile[idx+2:]
	} else {
		entry, rest = tile, nil
	}
	return entry, tlog.RecordHash(entry), rest, nil
}

type tileWithData struct {
	tlog.Tile
	data []byte
}

// edgeMemoryCache is a [tlog.TileReader] that caches two edges in the tree: the
// rightmost one that's used to compute the tree hash, and the one that moves
// through the tree as we progress through entries.
type edgeMemoryCache struct {
	tr tlog.TileReader
	t  map[int][2]tileWithData
}

func (c *edgeMemoryCache) Height() int {
	return c.tr.Height()
}

func (c *edgeMemoryCache) ReadTiles(tiles []tlog.Tile) (data [][]byte, err error) {
	data = make([][]byte, len(tiles))
	missing := make([]tlog.Tile, 0, len(tiles))
	for i, t := range tiles {
		if td := c.t[t.L]; td[0].Tile == t {
			data[i] = td[0].data
		} else if td[1].Tile == t {
			data[i] = td[1].data
		} else {
			missing = append(missing, t)
		}
	}
	if len(missing) == 0 {
		return data, nil
	}
	missingData, err := c.tr.ReadTiles(missing)
	if err != nil {
		return nil, err
	}
	for i := range data {
		if data[i] == nil {
			data[i] = missingData[0]
			missingData = missingData[1:]
		}
	}
	return data, nil
}

func (c *edgeMemoryCache) SaveTiles(tiles []tlog.Tile, data [][]byte) {
	ts, ds := make([]tlog.Tile, 0, len(tiles)), make([][]byte, 0, len(tiles))
	for i, t := range tiles {
		// If it's already in the memory cache, it was already saved by the
		// lower layer, as well.
		if td := c.t[t.L]; td[0].Tile == t || td[1].Tile == t {
			continue
		}
		ts = append(ts, t)
		ds = append(ds, data[i])
	}
	c.tr.SaveTiles(ts, ds)

	for i, t := range tiles {
		td, ok := c.t[t.L]
		switch {
		case !ok:
			c.t[t.L] = [2]tileWithData{{Tile: t, data: data[i]}}
		case td[0].Tile == t || td[1].Tile == t:
			// Already saved.
		case tileLess(td[0].Tile, t) && tileLess(td[0].Tile, td[1].Tile):
			c.t[t.L] = [2]tileWithData{{Tile: t, data: data[i]}, td[1]}
		case tileLess(td[1].Tile, t) && tileLess(td[1].Tile, td[0].Tile):
			c.t[t.L] = [2]tileWithData{td[0], {Tile: t, data: data[i]}}
		}
	}
}

func tileLess(a, b tlog.Tile) bool {
	// A zero tile is always less than any other tile.
	if a == (tlog.Tile{}) {
		return true
	}
	if b == (tlog.Tile{}) {
		return false
	}
	if a.L != b.L {
		panic("different levels")
	}
	return a.N < b.N || (a.N == b.N && a.W < b.W)
}

type TileFetcher struct {
	base     string
	hc       *http.Client
	log      *slog.Logger
	limit    int
	tilePath func(tlog.Tile) string
}

func NewTileFetcher(base string) *TileFetcher {
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = transport.MaxIdleConns
	return &TileFetcher{
		base: base,
		hc: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		log:      slog.New(slogDiscardHandler{}),
		tilePath: tlogx.TilePath,
	}
}

func (f *TileFetcher) SetLogger(log *slog.Logger) {
	f.log = log
}

func (f *TileFetcher) SetHTTPClient(hc *http.Client) {
	f.hc = hc
}

func (f *TileFetcher) SetLimit(limit int) {
	f.limit = limit
}

func (f *TileFetcher) SetTilePath(tilePath func(tlog.Tile) string) {
	f.tilePath = tilePath
}

func (f *TileFetcher) Height() int {
	return tileHeight
}

func (f *TileFetcher) ReadTiles(tiles []tlog.Tile) (data [][]byte, err error) {
	data = make([][]byte, len(tiles))
	errGroup, ctx := errgroup.WithContext(context.Background())
	if f.limit > 0 {
		errGroup.SetLimit(f.limit)
	}
	for i, t := range tiles {
		if t.H != tileHeight {
			return nil, fmt.Errorf("unexpected tile height %d", t.H)
		}
		errGroup.Go(func() error {
			path := f.tilePath(t)
			resp, err := f.hc.Get(f.base + path)
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("%s: unexpected status code %d", path, resp.StatusCode)
			}
			data[i], err = io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			f.log.InfoContext(ctx, "fetched tile", "path", path, "size", len(data[i]))
			return nil
		})
	}
	return data, errGroup.Wait()
}

func (f *TileFetcher) SaveTiles(tiles []tlog.Tile, data [][]byte) {}

type slogDiscardHandler struct{}

func (slogDiscardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (slogDiscardHandler) Handle(context.Context, slog.Record) error { return nil }
func (slogDiscardHandler) WithAttrs(attrs []slog.Attr) slog.Handler  { return slogDiscardHandler{} }
func (slogDiscardHandler) WithGroup(name string) slog.Handler        { return slogDiscardHandler{} }

// PermanentCache is a [tlog.TileReader] that caches verified, non-partial tiles
// in a filesystem directory, following the same structure as c2sp.org/tlog-tiles
// (even if the wrapped TileReader fetches tiles following a different scheme,
// such as c2sp.org/static-ct-api or go.dev/design/25530-sumdb).
type PermanentCache struct {
	tr  tlog.TileReader
	dir string
	log *slog.Logger
}

func NewPermanentCache(tr tlog.TileReader, dir string) (*PermanentCache, error) {
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("cache directory %q does not exist or is not a directory: %w", dir, err)
	}
	if tr.Height() != tileHeight {
		return nil, fmt.Errorf("only tile height 8 is supported")
	}
	return &PermanentCache{tr: tr, dir: dir, log: slog.New(slogDiscardHandler{})}, nil
}

func (c *PermanentCache) SetLogger(log *slog.Logger) {
	c.log = log
}

func (c *PermanentCache) Height() int {
	return tileHeight
}

func (c *PermanentCache) ReadTiles(tiles []tlog.Tile) (data [][]byte, err error) {
	data = make([][]byte, len(tiles))
	missing := make([]tlog.Tile, 0, len(tiles))
	for i, t := range tiles {
		if t.H != tileHeight {
			return nil, fmt.Errorf("unexpected tile height %d", t.H)
		}
		path := filepath.Join(c.dir, tlogx.TilePath(t))
		if d, err := os.ReadFile(path); errors.Is(err, os.ErrNotExist) {
			missing = append(missing, t)
		} else if err != nil {
			return nil, err
		} else {
			c.log.Info("loaded tile from cache", "path", tlogx.TilePath(t), "size", len(d))
			data[i] = d
		}
	}
	if len(missing) == 0 {
		return data, nil
	}
	missingData, err := c.tr.ReadTiles(missing)
	if err != nil {
		return nil, err
	}
	for i := range data {
		if data[i] == nil {
			data[i] = missingData[0]
			missingData = missingData[1:]
		}
	}
	return data, nil
}

func (c *PermanentCache) SaveTiles(tiles []tlog.Tile, data [][]byte) {
	for i, t := range tiles {
		if t.H != tileHeight {
			c.log.Error("unexpected tile height", "tile", t, "height", t.H)
			continue
		}
		if t.W != tileWidth {
			continue // skip partial tiles
		}
		path := filepath.Join(c.dir, tlogx.TilePath(t))
		if _, err := os.Stat(path); err == nil {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			c.log.Error("failed to create directory", "path", path, "error", err)
			return
		}
		if err := os.WriteFile(path, data[i], 0600); err != nil {
			c.log.Error("failed to write file", "path", path, "error", err)
		} else {
			c.log.Info("saved tile to cache", "path", tlogx.TilePath(t), "size", len(data[i]))
		}
	}
	c.tr.SaveTiles(tiles, data)
}
