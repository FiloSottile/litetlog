package torchwood

import (
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
