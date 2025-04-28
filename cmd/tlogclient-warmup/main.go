package main

import (
	"io"
	"os"
	"path/filepath"

	"filippo.io/litetlog/internal/tlogclient"
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
	cacheDir = filepath.Join(cacheDir, "tlogclient-warmup")

	fetcher := tlogclient.NewTileFetcher("https://sum.golang.org/")
	fetcher.SetTilePath(func(t tlog.Tile) string { return t.Path() })
	dirCache, err := tlogclient.NewPermanentCache(fetcher, cacheDir)
	if err != nil {
		panic(err)
	}
	client := tlogclient.NewClient(dirCache)
	client.SetCutEntry(tlogclient.CutSumDBEntry)

	bar := pb.Start64(tree.N)
	for range client.Entries(tree, 0) {
		bar.Increment()
	}
	bar.Finish()
	if err := client.Error(); err != nil {
		panic(err)
	}
}
