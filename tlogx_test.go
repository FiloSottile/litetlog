package torchwood_test

import (
	"reflect"
	"testing"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/tlog"
)

func TestRightEdge(t *testing.T) {
	tests := []struct {
		n    int64
		want []int64
	}{
		{0, nil},
		{13, []int64{
			tlog.StoredHashIndex(3, 0),
			tlog.StoredHashIndex(2, 2),
			tlog.StoredHashIndex(0, 12),
		}},
		{16, []int64{
			tlog.StoredHashIndex(4, 0),
		}},
	}
	for _, test := range tests {
		if got := torchwood.RightEdge(test.n); !reflect.DeepEqual(got, test.want) {
			t.Errorf("RightEdge(%d) = %v; want %v", test.n, got, test.want)
		}
	}
}
