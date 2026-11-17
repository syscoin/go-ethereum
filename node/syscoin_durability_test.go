// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package node

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
)

// SYSCOIN: exercise the database handles returned to real node services. A
// normal close/reopen checks wrapper integration, not power-loss durability.
func TestSyscoinNodeDatabaseDurability(t *testing.T) {
	for _, engine := range []string{rawdb.DBLeveldb, rawdb.DBPebble} {
		for _, test := range []struct {
			name string
			open func(*Node) (ethdb.Database, error)
		}{
			{"hot", func(n *Node) (ethdb.Database, error) {
				return n.OpenDatabase("chaindata", 16, 16, "", false)
			}},
			{"freezer", func(n *Node) (ethdb.Database, error) {
				return n.OpenDatabaseWithFreezer("chaindata", 16, 16, "", "", false)
			}},
		} {
			t.Run(engine+"/"+test.name, func(t *testing.T) {
				config := &Config{Name: "syscoin-durability", DataDir: t.TempDir(), DBEngine: engine}
				newNode := func() *Node {
					t.Helper()
					stack, err := New(config)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := stack.Close(); err != nil && !errors.Is(err, ErrNodeStopped) {
							t.Error(err)
						}
					})
					return stack
				}
				stack := newNode()
				db, err := test.open(stack)
				if err != nil {
					t.Fatal(err)
				}
				key, value := []byte("syscoin-durability-test"), []byte("published endpoint")
				if err := db.Put(key, value); err != nil {
					t.Fatal(err)
				}
				if err := ethdb.SyncKeyValue(db); err != nil {
					t.Fatalf("node database hid its backend durability barrier: %v", err)
				}
				if err := stack.Close(); err != nil {
					t.Fatal(err)
				}
				reopened, err := test.open(newNode())
				if err != nil {
					t.Fatal(err)
				}
				if got, err := reopened.Get(key); err != nil || !bytes.Equal(got, value) {
					t.Fatalf("reopened value = %q, error %v; want %q", got, err, value)
				}
				if err := ethdb.SyncKeyValue(reopened); err != nil {
					t.Fatalf("reopened node database hid its durability barrier: %v", err)
				}
			})
		}
	}
}

// SYSCOIN: the optional barrier must preserve backend failures and must never
// turn an unsupported memory database into an acknowledged durable endpoint.
func TestSyscoinNodeDatabaseDurabilityErrors(t *testing.T) {
	t.Run("backend failure", func(t *testing.T) {
		failure := errors.New("injected hot-storage sync failure")
		backend := &syscoinNodeSyncDB{Database: rawdb.NewMemoryDatabase(), err: failure}
		t.Cleanup(func() { backend.Close() })
		db := &closeTrackingDB{Database: backend}
		if err := ethdb.SyncKeyValue(db); !errors.Is(err, failure) || backend.calls != 1 {
			t.Fatalf("wrapped sync = %v, backend calls %d; want injected failure and one call", err, backend.calls)
		}
		backend.err = nil
		if err := ethdb.SyncKeyValue(db); err != nil || backend.calls != 2 {
			t.Fatalf("wrapped sync retry = %v, backend calls %d; want success and two calls", err, backend.calls)
		}
	})
	t.Run("unsupported memory", func(t *testing.T) {
		backend := rawdb.NewMemoryDatabase()
		t.Cleanup(func() { backend.Close() })
		unsupported := ethdb.SyncKeyValue(backend)
		if unsupported == nil {
			t.Fatal("raw memory database acknowledged durability")
		}
		if err := ethdb.SyncKeyValue(&closeTrackingDB{Database: backend}); err == nil || err.Error() != unsupported.Error() {
			t.Fatalf("wrapped memory sync = %v, want unsupported error %v", err, unsupported)
		}
	})
}

type syscoinNodeSyncDB struct {
	ethdb.Database
	err   error
	calls int
}

func (db *syscoinNodeSyncDB) SyncKeyValue() error {
	db.calls++
	return db.err
}
