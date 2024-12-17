package tlogclient_test

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"

	"filippo.io/litetlog/internal/tlogclient"
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

	tests := []struct {
		start  int64
		expect int
	}{
		{0, 1000},
		{100000, 1000},
		{31048497 - 1000, 1000 - 31048497%256},    // Stop before the partial.
		{31048497 - 31048497%256, 31048497 % 256}, // Consume the partial.
		{31048497, 0},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("Start%d", tt.start), func(t *testing.T) {
			t.Run("NoCache", func(t *testing.T) {
				fetcher := tlogclient.NewSumDBFetcher("https://sum.golang.org/")
				fetcher.SetLogger(slog.New(handler))
				client := tlogclient.NewClient(fetcher)

				count := 0
				for range client.EntriesSumDB(tree, tt.start) {
					count++
					if count >= 1000 {
						break
					}
				}
				if err := client.Error(); err != nil {
					t.Fatal(err)
				}
				if count != tt.expect {
					t.Errorf("got %d entries, want %d", count, tt.expect)
				}
			})

			t.Run("DirCache", func(t *testing.T) {
				fetcher := tlogclient.NewSumDBFetcher("https://sum.golang.org/")
				fetcher.SetLogger(slog.New(handler))
				dirCache := tlogclient.NewPermanentCache(fetcher, t.TempDir())
				dirCache.SetLogger(slog.New(handler))
				client := tlogclient.NewClient(dirCache)

				count := 0
				for range client.EntriesSumDB(tree, tt.start) {
					count++
					if count >= 1000 {
						break
					}
				}
				if err := client.Error(); err != nil {
					t.Fatal(err)
				}
				if count != tt.expect {
					t.Errorf("got %d entries, want %d", count, tt.expect)
				}

				// Again, from cache.
				client = tlogclient.NewClient(dirCache)
				count = 0
				for range client.EntriesSumDB(tree, tt.start) {
					count++
					if count >= 1000 {
						break
					}
				}
				if err := client.Error(); err != nil {
					t.Fatal(err)
				}
				if count != tt.expect {
					t.Errorf("got %d entries, want %d", count, tt.expect)
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
