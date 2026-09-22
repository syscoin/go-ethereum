// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package pathdb

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
)

// SYSCOIN: Fail only the physical flush's atomic journal batch, after its trie
// nodes have already been staged. Direct checkpoint writes remain available.
type liveJournalFaultDB struct {
	ethdb.Database
	err                error
	failJournalPut     bool
	failWriteAt        int
	journalPuts        int
	journalBatchWrites int
}

func (db *liveJournalFaultDB) NewBatch() ethdb.Batch {
	return &liveJournalFaultBatch{Batch: db.Database.NewBatch(), db: db}
}

func (db *liveJournalFaultDB) NewBatchWithSize(size int) ethdb.Batch {
	return &liveJournalFaultBatch{Batch: db.Database.NewBatchWithSize(size), db: db}
}

type liveJournalFaultBatch struct {
	ethdb.Batch
	db         *liveJournalFaultDB
	hasJournal bool
}

func (batch *liveJournalFaultBatch) Put(key, value []byte) error {
	if bytes.Equal(key, []byte("TrieJournal")) {
		batch.hasJournal = true
		batch.db.journalPuts++
		if batch.db.failJournalPut {
			return batch.db.err
		}
	}
	return batch.Batch.Put(key, value)
}

func (batch *liveJournalFaultBatch) Write() error {
	if batch.hasJournal {
		batch.db.journalBatchWrites++
		if batch.db.journalBatchWrites == batch.db.failWriteAt {
			return batch.db.err
		}
	}
	return batch.Batch.Write()
}

// SYSCOIN: Reopen only persisted KV rows, without the original trie/cache or a
// clean shutdown journal. This retains every write, including those preceding
// the injected failure; no selective write loss manufactures the outcome.
func reopenLiveJournalImage(t *testing.T, source ethdb.Database) *Database {
	t.Helper()
	image := rawdb.NewMemoryDatabase()
	it := source.NewIterator(nil, nil)
	defer it.Release()
	for it.Next() {
		if err := image.Put(bytes.Clone(it.Key()), bytes.Clone(it.Value())); err != nil {
			t.Fatal(err)
		}
	}
	if err := it.Error(); err != nil {
		t.Fatal(err)
	}
	cold := New(image, nil, false)
	t.Cleanup(func() {
		cold.Close()
		image.Close()
	})
	return cold
}

func verifyLiveJournalRoots(t *testing.T, fixture *tester, db *Database, roots ...common.Hash) {
	t.Helper()
	check := *fixture
	check.db = db
	for _, root := range roots {
		if db.tree.get(root) == nil {
			t.Fatalf("cold restart lost checkpoint ancestry %x", root)
		}
		if err := check.verifyState(root); err != nil {
			t.Fatalf("cold restart changed account/storage state at %x: %v", root, err)
		}
	}
}

func TestLiveJournalAtomicFlushFailures(t *testing.T) {
	for _, mode := range []string{"journal-put", "batch-write"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newTester(t, 0, false, maxDiffLayers)
			defer fixture.release()
			acknowledged := fixture.lastHash()
			if err := fixture.db.Checkpoint(acknowledged); err != nil {
				t.Fatal(err)
			}
			oldRoot := bytes.Clone(rawdb.ReadAccountTrieNode(fixture.db.diskdb, nil))
			oldID := rawdb.ReadPersistentStateID(fixture.db.diskdb)
			oldJournal := bytes.Clone(rawdb.ReadTrieJournal(fixture.db.diskdb))
			injected := errors.New("injected live journal flush failure")
			store := &liveJournalFaultDB{Database: fixture.db.diskdb, err: injected}
			if mode == "journal-put" {
				store.failJournalPut = true
			} else {
				store.failWriteAt = 1
			}
			fixture.db.diskdb = store
			// Exercise ordinary Update/cap, accelerating only its normal dirty
			// buffer threshold. Keep the production number of retained layers.
			fixture.db.tree.bottom().buffer.limit = 1
			child, nodes, states := fixture.generate(acknowledged, false)
			if err := fixture.db.Update(child, acknowledged, uint64(maxDiffLayers), nodes, states); !errors.Is(err, injected) {
				t.Fatalf("ordinary physical flush returned %v, want injected failure", err)
			}
			if store.journalPuts != 1 {
				t.Fatalf("journal batch fault was not reached exactly once: %d", store.journalPuts)
			}
			if !bytes.Equal(oldRoot, rawdb.ReadAccountTrieNode(store, nil)) ||
				oldID != rawdb.ReadPersistentStateID(store) ||
				!bytes.Equal(oldJournal, rawdb.ReadTrieJournal(store)) {
				t.Fatal("failed atomic flush partially changed physical state or checkpoint")
			}
			cold := reopenLiveJournalImage(t, store)
			verifyLiveJournalRoots(t, fixture, cold, acknowledged)

			// A restarted checkpoint must keep protecting its endpoint during
			// another ordinary flush, without an explicit new Checkpoint call.
			cold.tree.bottom().buffer.limit = 1
			if err := cold.Update(child, acknowledged, uint64(maxDiffLayers), nodes, states); err != nil {
				t.Fatalf("retry after cold restart: %v", err)
			}
			if rawdb.ReadPersistentStateID(cold.diskdb) <= oldID {
				t.Fatal("restarted update did not advance the physical base")
			}
			verifyLiveJournalRoots(t, fixture, reopenLiveJournalImage(t, cold.diskdb), acknowledged, child)
		})
	}
}

func TestLiveJournalInterruptedFullCommit(t *testing.T) {
	fixture := newTester(t, 0, false, 3)
	defer fixture.release()
	acknowledged := fixture.lastHash()
	if err := fixture.db.Checkpoint(acknowledged); err != nil {
		t.Fatal(err)
	}
	oldJournal := bytes.Clone(rawdb.ReadTrieJournal(fixture.db.diskdb))
	injected := errors.New("injected second recursive flush failure")
	store := &liveJournalFaultDB{Database: fixture.db.diskdb, err: injected, failWriteAt: 2}
	fixture.db.diskdb = store
	// SYSCOIN: Full Commit recursively flushes multiple physical bases. Even
	// its first successful batch must retain the acknowledged upper layers if
	// the following batch fails, rather than waiting for Commit to finish.
	if err := fixture.db.Commit(acknowledged, false); !errors.Is(err, injected) {
		t.Fatalf("recursive commit returned %v, want injected failure", err)
	}
	if store.journalBatchWrites != 2 || rawdb.ReadPersistentStateID(store) != 1 {
		t.Fatalf("expected one committed base before failure; writes=%d stateID=%d", store.journalBatchWrites, rawdb.ReadPersistentStateID(store))
	}
	if bytes.Equal(oldJournal, rawdb.ReadTrieJournal(store)) {
		t.Fatal("successful intermediate flush did not replace the journal")
	}
	verifyLiveJournalRoots(t, fixture, reopenLiveJournalImage(t, store), fixture.roots...)
}
