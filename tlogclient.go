package torchwood

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

// Client is a tlog client that fetches and authenticates tiles, and exposes log
// entries as a Go iterator.
type Client struct {
	tr  tlog.TileReader
	cut func([]byte) ([]byte, tlog.Hash, []byte, error)
	err error
}

// NewClient creates a new [Client] that fetches tiles using the given
// [tlog.TileReader]. The TileReader would typically be a [TileFetcher],
// optionally wrapped in a [PermanentCache] to cache tiles on disk.
func NewClient(tr tlog.TileReader, opts ...ClientOption) (*Client, error) {
	if tr.Height() != TileHeight {
		return nil, fmt.Errorf("only tile height %d is supported", TileHeight)
	}
	tr = &edgeMemoryCache{tr: tr, t: make(map[int][2]tileWithData)}
	c := &Client{tr: tr}
	for _, opt := range opts {
		opt(c)
	}
	if c.cut == nil {
		// TODO: default to the tlog-tile entries format.
		return nil, fmt.Errorf("cut function not set")
	}
	return c, nil
}

// ClientOption is a function that configures a [Client].
type ClientOption func(*Client)

// WithCutEntry configures the function to split the next entry from a tile.
//
// The entry is surfaced by the Entries method, the record hash is used to check
// inclusion in the tree, and the rest is passed to the next invocation of cut.
//
// The input tile is never empty. cut must not modify the tile.
func WithCutEntry(cut func(tile []byte) (entry []byte, rh tlog.Hash, rest []byte, err error)) ClientOption {
	return func(c *Client) {
		c.cut = cut
	}
}

// WithSumDBEntries configures the function to split the next entry from a tile
// according to the go.dev/design/25530-sumdb format.
func WithSumDBEntries() ClientOption {
	return func(c *Client) {
		c.cut = func(tile []byte) (entry []byte, rh tlog.Hash, rest []byte, err error) {
			if idx := bytes.Index(tile, []byte("\n\n")); idx >= 0 {
				// Add back one of the newlines.
				entry, rest = tile[:idx+1], tile[idx+2:]
			} else {
				entry, rest = tile, nil
			}
			return entry, tlog.RecordHash(entry), rest, nil
		}
	}
}

// Err returns the error encountered by the latest [Client.Entries] call.
func (c *Client) Err() error {
	return c.err
}

// Entries returns an iterator that yields entries from the given tree, starting
// at the given index. The first item in the yielded pair is the overall entry
// index in the log, starting at start.
//
// The provided tree should have been verified by the caller, for example by
// verifying the signatures on a [Checkpoint].
//
// Iteration may stop before the size of the tree to avoid fetching a partial
// data tile. Resuming with the same tree will yield the remaining entries,
// however clients tailing a growing log are encouraged to fetch the next
// checkpoint and use that as the tree argument.
//
// Callers must check [Client.Err] after the iteration breaks.
func (c *Client) Entries(tree tlog.Tree, start int64) iter.Seq2[int64, []byte] {
	c.err = nil
	return func(yield func(int64, []byte) bool) {
		for {
			base := start / TileWidth * TileWidth
			// In regular operations, don't actually fetch the trailing partial
			// tile, to avoid duplicating that traffic in steady state. The
			// assumption is that a future call to Entries will pass a bigger
			// tree where that tile is full. However, if the tree grows too
			// slowly, we'll get another call where start is at the beginning of
			// the partial tile; in that case, fetch it.
			top := tree.N / TileWidth * TileWidth
			if top-base == 0 {
				top = tree.N
			}
			tiles := make([]tlog.Tile, 0, 50)
			for i := 0; i < 50; i++ {
				tileStart := base + int64(i)*TileWidth
				if tileStart >= top {
					break
				}
				tileEnd := tileStart + TileWidth
				if tileEnd > top {
					tileEnd = top
				}
				tiles = append(tiles, tlog.Tile{H: TileHeight, L: -1,
					N: tileStart / TileWidth, W: int(tileEnd - tileStart)})
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
			indexes := make([]int64, 0, TileWidth*len(tiles))
			for _, t := range tiles {
				for i := range t.W {
					indexes = append(indexes, tlog.StoredHashIndex(0, t.N*TileWidth+int64(i)))
				}
			}
			hashes, err := tlog.TileHashReader(tree, c.tr).ReadHashes(indexes)
			if err != nil {
				c.err = err
				return
			}

			for ti, t := range tiles {
				tileStart := t.N * TileWidth
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

// TileFetcher is a [tlog.TileReader] that fetches tiles from a remote server.
type TileFetcher struct {
	base     string
	hc       *http.Client
	log      *slog.Logger
	limit    int
	tilePath func(tlog.Tile) string
}

// NewTileFetcher creates a new [TileFetcher] that fetches tiles from the given
// base URL. By default, it fetches tiles according to c2sp.org/tlog-tiles.
func NewTileFetcher(base string, opts ...TileFetcherOption) (*TileFetcher, error) {
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}

	tf := &TileFetcher{base: base}
	for _, opt := range opts {
		opt(tf)
	}
	if tf.tilePath == nil {
		tf.tilePath = TilePath
	}
	if tf.hc == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.MaxIdleConnsPerHost = transport.MaxIdleConns
		tf.hc = &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		}
	}
	if tf.log == nil {
		tf.log = slog.New(slogDiscardHandler{})
	}

	return tf, nil
}

// TileFetcherOption is a function that configures a [TileFetcher].
type TileFetcherOption func(*TileFetcher)

// WithTileFetcherLogger configures the logger used by the TileFetcher.
// By default, log lines are discarded.
func WithTileFetcherLogger(log *slog.Logger) TileFetcherOption {
	return func(f *TileFetcher) {
		f.log = log
	}
}

// WithHTTPClient configures the HTTP client used by the TileFetcher.
//
// Note that TileFetcher may need to make multiple parallel requests to
// the same host, more than the default MaxIdleConnsPerHost.
func WithHTTPClient(hc *http.Client) TileFetcherOption {
	return func(f *TileFetcher) {
		f.hc = hc
	}
}

// WithConcurrencyLimit configures the maximum number of concurrent requests
// made by the TileFetcher. By default, there is no limit.
func WithConcurrencyLimit(limit int) TileFetcherOption {
	return func(f *TileFetcher) {
		f.limit = limit
	}
}

// WithTilePath configures the function used to generate the tile path from a
// [tlog.Tile]. By default, TileFetcher uses the c2sp.org/tlog-tiles scheme
// implemented by [TilePath]. For the go.dev/design/25530-sumdb scheme, use
// [tlog.Tile.Path]. For the c2sp.org/static-ct-api scheme, use
// [filippo.io/sunlight.TilePath].
func WithTilePath(tilePath func(tlog.Tile) string) TileFetcherOption {
	return func(f *TileFetcher) {
		f.tilePath = tilePath
	}
}

// Height implements [tlog.TileReader].
func (f *TileFetcher) Height() int {
	return TileHeight
}

// ReadTiles implements [tlog.TileReader].
func (f *TileFetcher) ReadTiles(tiles []tlog.Tile) (data [][]byte, err error) {
	data = make([][]byte, len(tiles))
	errGroup, ctx := errgroup.WithContext(context.Background())
	if f.limit > 0 {
		errGroup.SetLimit(f.limit)
	}
	for i, t := range tiles {
		if t.H != TileHeight {
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

// SaveTiles implements [tlog.TileReader]. It does nothing.
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

// NewPermanentCache creates a new [PermanentCache] that caches tiles in the
// given directory. The directory must exist.
func NewPermanentCache(tr tlog.TileReader, dir string, opts ...PermanentCacheOption) (*PermanentCache, error) {
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("cache directory %q does not exist or is not a directory: %w", dir, err)
	}
	if tr.Height() != TileHeight {
		return nil, fmt.Errorf("only tile height 8 is supported")
	}
	c := &PermanentCache{tr: tr, dir: dir}
	for _, opt := range opts {
		opt(c)
	}
	if c.log == nil {
		c.log = slog.New(slogDiscardHandler{})
	}
	return c, nil
}

// PermanentCacheOption is a function that configures a [PermanentCache].
type PermanentCacheOption func(*PermanentCache)

// WithPermanentCacheLogger configures the logger used by the PermanentCache.
// By default, log lines are discarded.
func WithPermanentCacheLogger(log *slog.Logger) PermanentCacheOption {
	return func(c *PermanentCache) {
		c.log = log
	}
}

// Height implements [tlog.TileReader].
func (c *PermanentCache) Height() int {
	return TileHeight
}

// ReadTiles implements [tlog.TileReader].
func (c *PermanentCache) ReadTiles(tiles []tlog.Tile) (data [][]byte, err error) {
	data = make([][]byte, len(tiles))
	missing := make([]tlog.Tile, 0, len(tiles))
	for i, t := range tiles {
		if t.H != TileHeight {
			return nil, fmt.Errorf("unexpected tile height %d", t.H)
		}
		path := filepath.Join(c.dir, TilePath(t))
		if d, err := os.ReadFile(path); errors.Is(err, os.ErrNotExist) {
			missing = append(missing, t)
		} else if err != nil {
			return nil, err
		} else {
			c.log.Info("loaded tile from cache", "path", TilePath(t), "size", len(d))
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

// SaveTiles implements [tlog.TileReader].
func (c *PermanentCache) SaveTiles(tiles []tlog.Tile, data [][]byte) {
	for i, t := range tiles {
		if t.H != TileHeight {
			c.log.Error("unexpected tile height", "tile", t, "height", t.H)
			continue
		}
		if t.W != TileWidth {
			continue // skip partial tiles
		}
		path := filepath.Join(c.dir, TilePath(t))
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
			c.log.Info("saved tile to cache", "path", TilePath(t), "size", len(data[i]))
		}
	}
	c.tr.SaveTiles(tiles, data)
}
