package torchwood

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/mod/sumdb/tlog"
)

const TileHeight = 8
const TileWidth = 1 << TileHeight

// TilePath returns a tile coordinate path describing t, according to
// c2sp.org/tlog-tiles.
//
// For the go.dev/design/25530-sumdb scheme, use [tlog.Tile.Path]. For the
// c2sp.org/static-ct-api scheme, use [filippo.io/sunlight/TilePath].
//
// If t.Height is not TileHeight, TilePath panics.
func TilePath(t tlog.Tile) string {
	if t.H != TileHeight {
		panic(fmt.Sprintf("unexpected tile height %d", t.H))
	}
	if t.L == -1 {
		return "tile/entries/" + strings.TrimPrefix(t.Path(), "tile/8/data/")
	}
	return "tile/" + strings.TrimPrefix(t.Path(), "tile/8/")
}

// ParseTilePath parses a tile coordinate path according to c2sp.org/tlog-tiles.
//
// For the go.dev/design/25530-sumdb scheme, use [tlog.ParseTilePath]. For the
// c2sp.org/static-ct-api scheme, use [filippo.io/sunlight/ParseTilePath].
func ParseTilePath(path string) (tlog.Tile, error) {
	if rest, ok := strings.CutPrefix(path, "tile/entries/"); ok {
		t, err := tlog.ParseTilePath("tile/8/data/" + rest)
		if err != nil {
			return tlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
		}
		return t, nil
	}
	if rest, ok := strings.CutPrefix(path, "tile/"); ok {
		t, err := tlog.ParseTilePath("tile/8/" + rest)
		if err != nil {
			return tlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
		}
		return t, nil
	}
	return tlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
}

// TileReaderWithContext is an interface equivalent to [tlog.TileReader], but
// with a context parameter for cancellation and a fixed [TileHeight].
type TileReaderWithContext interface {
	// ReadTiles returns the data for each requested tile.
	// See [tlog.TileReader.ReadTiles] for details.
	ReadTiles(ctx context.Context, tiles []tlog.Tile) (data [][]byte, err error)

	// SaveTiles informs the TileReader that the tile data has been confirmed.
	// See [tlog.TileReader.SaveTiles] for details.
	SaveTiles(tiles []tlog.Tile, data [][]byte)
}

// TileHashReaderWithContext returns a HashReader that satisfies requests by
// loading tiles of the given tree.
//
// It is equivalent to [tlog.TileHashReader], but passes the ctx argument to the
// TileReaderWithContext methods.
func TileHashReaderWithContext(ctx context.Context, tree tlog.Tree, tr TileReaderWithContext) tlog.HashReader {
	return tlog.HashReaderFunc(func(i []int64) ([]tlog.Hash, error) {
		return tlog.TileHashReader(tree, tileReaderAndContext{tr: tr, ctx: ctx}).ReadHashes(i)
	})
}

type tileReaderAndContext struct {
	tr  TileReaderWithContext
	ctx context.Context
}

func (tr tileReaderAndContext) Height() int { return TileHeight }
func (tr tileReaderAndContext) ReadTiles(tiles []tlog.Tile) (data [][]byte, err error) {
	return tr.tr.ReadTiles(tr.ctx, tiles)
}
func (tr tileReaderAndContext) SaveTiles(tiles []tlog.Tile, data [][]byte) {
	tr.tr.SaveTiles(tiles, data)
}
