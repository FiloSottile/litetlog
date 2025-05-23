package main

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"filippo.io/torchwood"
	"github.com/cheggaaa/pb/v3"
	"golang.org/x/mod/sumdb/tlog"
)

func main() {
	latest, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}
	tree, err := tlog.ParseTree(latest)
	if err != nil {
		panic(err)
	}

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		panic(err)
	}
	cacheDir = filepath.Join(cacheDir, "sumdb-warmup")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		panic(err)
	}

	fetcher, err := torchwood.NewTileFetcher("https://sum.golang.org/",
		torchwood.WithTilePath(tlog.Tile.Path))
	if err != nil {
		panic(err)
	}
	dirCache, err := torchwood.NewPermanentCache(fetcher, cacheDir,
		torchwood.WithPermanentCacheTilePath(tlog.Tile.Path))
	if err != nil {
		panic(err)
	}
	client, err := torchwood.NewClient(dirCache, torchwood.WithSumDBEntries())
	if err != nil {
		panic(err)
	}

	bar := pb.Start64(tree.N)
	for range client.Entries(context.Background(), tree, 0) {
		bar.Increment()
	}
	bar.Finish()
	if err := client.Err(); err != nil {
		panic(err)
	}
}
