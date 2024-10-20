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

	"golang.org/x/mod/sumdb/tlog"
	"golang.org/x/sync/errgroup"
)

const tileHeight = 8
const tileWidth = 1 << tileHeight

type Client struct {
	tr  tlog.TileReader
	err error
}

func NewClient(tr tlog.TileReader) *Client {
	// edgeMemoryCache keeps track of two edges: the rightmost one that's used
	// to compute the tree hash, and the one that moves through the tree as we
	// progress through entries.
	tr = &edgeMemoryCache{tr: tr, t: make(map[int][2]tileWithData)}
	return &Client{tr: tr}
}

func (c *Client) Error() error {
	return c.err
}

func (c *Client) EntriesSumDB(tree tlog.Tree, start int64) iter.Seq2[int64, []byte] {
	return func(yield func(int64, []byte) bool) {
		if c.err != nil {
			return
		}
		for {
			base := start / tileWidth * tileWidth
			tiles := make([]tlog.Tile, 0, 16)
			for i := 0; i < 50; i++ {
				tileStart := base + int64(i)*tileWidth
				tileEnd := tileStart + tileWidth
				if tileEnd > tree.N {
					break
				}
				tiles = append(tiles, tlog.Tile{H: tileHeight, L: -1,
					N: tileStart / tileWidth, W: tileWidth})
			}
			if len(tiles) == 0 {
				// TODO: document and support partial tile optimization.
				return
			}
			tdata, err := c.tr.ReadTiles(tiles)
			if err != nil {
				c.err = err
				return
			}

			// TODO: hash data tile directly against level 8 hash.
			indexes := make([]int64, tileWidth*len(tiles))
			for i := range indexes {
				indexes[i] = tlog.StoredHashIndex(0, base+int64(i))
			}
			hashes, err := tlog.TileHashReader(tree, c.tr).ReadHashes(indexes)
			if err != nil {
				c.err = err
				return
			}

			for ti, t := range tiles {
				tileStart := t.N * tileWidth
				tileEnd := tileStart + tileWidth
				data := tdata[ti]
				for i := tileStart; i < tileEnd; i++ {
					if len(data) == 0 {
						c.err = fmt.Errorf("unexpected end of tile data")
						return
					}

					var entry []byte
					if idx := bytes.Index(data, []byte("\n\n")); idx >= 0 {
						// Add back one of the newlines.
						entry, data = data[:idx+1], data[idx+2:]
					} else {
						entry, data = data, nil
					}

					if tlog.RecordHash(entry) != hashes[i-base] {
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
				start = tileEnd
			}

			c.tr.SaveTiles(tiles, tdata)
		}
	}
}

type tileWithData struct {
	tlog.Tile
	data []byte
}

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
	base  string
	hc    *http.Client
	log   *slog.Logger
	limit int
}

func NewSumDBFetcher(base string) *TileFetcher {
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = transport.MaxIdleConns
	return &TileFetcher{base: base, hc: &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}, log: slog.New(slogDiscardHandler{})}
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
		errGroup.Go(func() error {
			resp, err := f.hc.Get(f.base + t.Path())
			if err != nil {
				return fmt.Errorf("%s: %w", t.Path(), err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("%s: unexpected status code %d", t.Path(), resp.StatusCode)
			}
			data[i], err = io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("%s: %w", t.Path(), err)
			}
			f.log.InfoContext(ctx, "fetched tile", "path", t.Path(), "size", len(data[i]))
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

type PermanentCache struct {
	tr  tlog.TileReader
	dir string
	log *slog.Logger
}

func NewPermanentCache(tr tlog.TileReader, dir string) *PermanentCache {
	return &PermanentCache{tr: tr, dir: dir, log: slog.New(slogDiscardHandler{})}
}

func (c *PermanentCache) SetLogger(log *slog.Logger) {
	c.log = log
}

func (c *PermanentCache) Height() int {
	return c.tr.Height()
}

func (c *PermanentCache) ReadTiles(tiles []tlog.Tile) (data [][]byte, err error) {
	data = make([][]byte, len(tiles))
	missing := make([]tlog.Tile, 0, len(tiles))
	for i, t := range tiles {
		path := filepath.Join(c.dir, t.Path())
		if d, err := os.ReadFile(path); errors.Is(err, os.ErrNotExist) {
			missing = append(missing, t)
		} else if err != nil {
			return nil, err
		} else {
			c.log.Info("loaded tile from cache", "path", t.Path(), "size", len(d))
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
		if t.W != tileWidth {
			continue // skip partial tiles
		}
		path := filepath.Join(c.dir, t.Path())
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
			c.log.Info("saved tile to cache", "path", t.Path(), "size", len(data[i]))
		}
	}
	c.tr.SaveTiles(tiles, data)
}
