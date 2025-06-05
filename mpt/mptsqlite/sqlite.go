package mptsqlite

import (
	"context"
	"embed"
	"errors"
	"slices"

	"filippo.io/torchwood/mpt"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

type Storage struct {
	pool *sqlitex.Pool
}

//go:embed *.sql
var sql embed.FS

func NewSQLiteStorage(ctx context.Context, dbPath string) (*Storage, error) {
	pool, err := sqlitex.NewPool(dbPath, sqlitex.PoolOptions{
		PrepareConn: func(conn *sqlite.Conn) error {
			if err := conn.CreateFunction("sideof", &sqlite.FunctionImpl{
				NArgs:         4,
				Deterministic: true,
				Scalar: func(ctx sqlite.Context, args []sqlite.Value) (sqlite.Value, error) {
					if args[0].Type() != sqlite.TypeBlob || args[1].Type() != sqlite.TypeInteger ||
						args[2].Type() != sqlite.TypeBlob || args[3].Type() != sqlite.TypeInteger {
						return sqlite.Value{}, errors.New("invalid argument types for sideof")
					}

					labelBytes, labelBitLen := args[0].Blob(), uint32(args[1].Int64())
					prefixBytes, prefixBitLen := args[2].Blob(), uint32(args[3].Int64())

					label, err := mpt.NewLabel(labelBitLen, labelBytes)
					if err != nil {
						return sqlite.Value{}, err
					}
					prefix, err := mpt.NewLabel(prefixBitLen, prefixBytes)
					if err != nil {
						return sqlite.Value{}, err
					}

					return sqlite.IntegerValue(int64(label.SideOf(prefix))), nil
				},
			}); err != nil {
				return err
			}
			return sqlitex.ExecScript(conn, `
				PRAGMA strict_types = ON;
				PRAGMA foreign_keys = ON;
			`)
		},
	})
	if err != nil {
		return nil, err
	}

	conn, err := pool.Take(ctx)
	if err != nil {
		pool.Close()
		return nil, err
	}
	defer pool.Put(conn)

	if err := sqlitex.ExecuteTransientFS(conn, sql, "create.sql", nil); err != nil {
		pool.Close()
		return nil, err
	}

	return &Storage{pool: pool}, nil
}

func (s *Storage) Close() error {
	return s.pool.Close()
}

var _ mpt.Storage = (*Storage)(nil)

func (s *Storage) Load(ctx context.Context, label mpt.Label) (*mpt.Node, error) {
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return nil, err
	}
	defer s.pool.Put(conn)

	var node *mpt.Node
	if err := sqlitex.ExecuteFS(conn, sql, "load.sql", &sqlitex.ExecOptions{
		Args: []any{
			label.Bytes(),
			label.BitLen(),
		},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			var err error
			node, err = nodeFromRow(stmt)
			return err
		},
	}); err != nil {
		return nil, err
	}

	if node == nil {
		return nil, mpt.ErrNodeNotFound
	}
	return node, nil
}

func (s *Storage) LoadPath(ctx context.Context, label mpt.Label) ([]*mpt.Node, error) {
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return nil, err
	}
	defer s.pool.Put(conn)

	var nodes []*mpt.Node
	if err := sqlitex.ExecuteFS(conn, sql, "path.sql", &sqlitex.ExecOptions{
		Named: map[string]any{
			":root_label":         mpt.RootLabel.Bytes(),
			":root_label_bit_len": mpt.RootLabel.BitLen(),
			":label":              label.Bytes(),
			":label_bit_len":      label.BitLen(),
		},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			node, err := nodeFromRow(stmt)
			if err != nil {
				return err
			}
			nodes = append(nodes, node)
			return nil
		},
	}); err != nil {
		return nil, err
	}
	slices.Reverse(nodes)

	return nodes, nil
}

func nodeFromRow(stmt *sqlite.Stmt) (*mpt.Node, error) {
	labelBytes := make([]byte, 32)
	stmt.ColumnBytes(0, labelBytes)
	labelBitLen := stmt.ColumnInt64(1)
	label, err := mpt.NewLabel(uint32(labelBitLen), labelBytes)
	if err != nil {
		return nil, err
	}

	leftBytes := make([]byte, 32)
	stmt.ColumnBytes(2, leftBytes)
	leftBitLen := stmt.ColumnInt64(3)
	left, err := mpt.NewLabel(uint32(leftBitLen), leftBytes)
	if err != nil {
		return nil, err
	}

	rightBytes := make([]byte, 32)
	stmt.ColumnBytes(4, rightBytes)
	rightBitLen := stmt.ColumnInt64(5)
	right, err := mpt.NewLabel(uint32(rightBitLen), rightBytes)
	if err != nil {
		return nil, err
	}

	hashBytes := make([]byte, 32)
	stmt.ColumnBytes(6, hashBytes)

	return &mpt.Node{
		Label: label,
		Left:  left,
		Right: right,
		Hash:  [32]byte(hashBytes),
	}, nil
}

func (s *Storage) Store(ctx context.Context, nodes ...*mpt.Node) error {
	conn, err := s.pool.Take(ctx)
	if err != nil {
		return err
	}
	defer s.pool.Put(conn)

	for _, node := range nodes {
		if err := sqlitex.ExecuteFS(conn, sql, "insert.sql", &sqlitex.ExecOptions{
			Args: []any{
				node.Label.Bytes(), node.Label.BitLen(),
				node.Left.Bytes(), node.Left.BitLen(),
				node.Right.Bytes(), node.Right.BitLen(),
				node.Hash[:],
			},
		}); err != nil {
			return err
		}
	}

	return nil
}
