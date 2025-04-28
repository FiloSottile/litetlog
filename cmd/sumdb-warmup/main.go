package main

import (
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

	fetcher, err := torchwood.NewTileFetcher("https://sum.golang.org/",
		torchwood.WithTilePath(func(t tlog.Tile) string { return t.Path() }))
	if err != nil {
		panic(err)
	}
	dirCache, err := torchwood.NewPermanentCache(fetcher, cacheDir)
	if err != nil {
		panic(err)
	}
	client, err := torchwood.NewClient(dirCache, torchwood.WithSumDBEntries())
	if err != nil {
		panic(err)
	}

	bar := pb.Start64(tree.N)
	for range client.Entries(tree, 0) {
		bar.Increment()
	}
	bar.Finish()
	if err := client.Err(); err != nil {
		panic(err)
	}
}
