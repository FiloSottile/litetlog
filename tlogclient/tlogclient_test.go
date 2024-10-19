package tlogclient_test

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"

	"filippo.io/litetlog/tlogclient"
	"golang.org/x/mod/sumdb/tlog"
)

func TestSumDB(t *testing.T) {
	latest := []byte(`go.sum database tree
31048497
InZSsRXdXKTMF3W5wEcd9T6ro5zyOiRMGQsEPSTco6U=
`)
	tree, err := tlog.ParseTree(latest)
	if err != nil {
		t.Fatal(err)
	}

	handler, _ := testLogHandler(t)

	for _, start := range []int64{0, 100000} {
		t.Run(fmt.Sprintf("Start%d", start), func(t *testing.T) {
			t.Run("NoCache", func(t *testing.T) {
				fetcher := tlogclient.NewSumDBFetcher("https://sum.golang.org/")
				fetcher.SetLimit(1)
				fetcher.SetLogger(slog.New(handler))
				client := tlogclient.NewClient(fetcher)

				var ok bool
				for i := range client.EntriesSumDB(tree, start) {
					if i >= start+1000 {
						ok = true
						break
					}
				}
				if err := client.Error(); err != nil {
					t.Fatal(err)
				}
				if !ok {
					t.Error("did not reach 1000 entries")
				}
			})

			t.Run("DirCache", func(t *testing.T) {
				fetcher := tlogclient.NewSumDBFetcher("https://sum.golang.org/")
				fetcher.SetLimit(1)
				fetcher.SetLogger(slog.New(handler))
				dirCache := tlogclient.NewPermanentCache(fetcher, t.TempDir())
				dirCache.SetLogger(slog.New(handler))
				client := tlogclient.NewClient(dirCache)

				var ok bool
				for i := range client.EntriesSumDB(tree, start) {
					if i >= start+1000 {
						ok = true
						break
					}
				}
				if err := client.Error(); err != nil {
					t.Fatal(err)
				}
				if !ok {
					t.Error("did not reach 1000 entries")
				}
			})
		})
	}
}

func testLogHandler(t testing.TB) (slog.Handler, *slog.LevelVar) {
	level := &slog.LevelVar{}
	level.Set(slog.LevelDebug)
	h := slog.NewTextHandler(writerFunc(func(p []byte) (n int, err error) {
		t.Logf("%s", p)
		return len(p), nil
	}), &slog.HandlerOptions{
		AddSource: true,
		Level:     level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				src := a.Value.Any().(*slog.Source)
				a.Value = slog.StringValue(fmt.Sprintf("%s:%d", filepath.Base(src.File), src.Line))
			}
			return a
		},
	})
	return h, level
}

type writerFunc func(p []byte) (n int, err error)

func (f writerFunc) Write(p []byte) (n int, err error) {
	return f(p)
}
