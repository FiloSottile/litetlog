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

	fetcher := tlogclient.NewSumDBFetcher("https://sum.golang.org/")
	dirCache := tlogclient.NewPermanentCache(fetcher, cacheDir)
	client := tlogclient.NewClient(dirCache)

	bar := pb.Start64(tree.N)
	for range client.EntriesSumDB(tree, 0) {
		bar.Increment()
	}
	bar.Finish()
	if err := client.Error(); err != nil {
		panic(err)
	}
}
