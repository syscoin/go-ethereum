// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package pathdb

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
)

// SYSCOIN: a failed history sync must not replace the last usable journal or
// seal the database, including when the requested journal is for shutdown.
type journalHistorySyncStore struct {
	ethdb.ResettableAncientStore
	err   error
	calls int
}

func (store *journalHistorySyncStore) Sync() error {
	store.calls++
	if store.err != nil {
		return store.err
	}
	return store.ResettableAncientStore.Sync()
}

func TestJournalHistorySyncFailure(t *testing.T) {
	for _, mode := range []string{"checkpoint", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newTester(t, 0, false, 1)
			defer fixture.release()
			parent := fixture.lastHash()
			if err := fixture.db.Checkpoint(parent); err != nil {
				t.Fatal(err)
			}
			previous := bytes.Clone(rawdb.ReadTrieJournal(fixture.db.diskdb))
			head, nodes, states := fixture.generate(parent, false)
			if err := fixture.db.Update(head, parent, 2, nodes, states); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected history sync failure")
			store := &journalHistorySyncStore{ResettableAncientStore: fixture.db.freezer, err: injected}
			fixture.db.freezer = store
			journal := fixture.db.Checkpoint
			if mode == "shutdown" {
				journal = fixture.db.Journal
			}
			if err := journal(head); !errors.Is(err, injected) {
				t.Fatalf("journal returned %v, want history sync failure", err)
			}
			if store.calls != 1 || fixture.db.readOnly || !bytes.Equal(previous, rawdb.ReadTrieJournal(fixture.db.diskdb)) {
				t.Fatal("failed history sync changed the previous journal or disabled retry")
			}
			store.err = nil
			if err := journal(head); err != nil {
				t.Fatalf("journal retry: %v", err)
			}
			if store.calls != 2 || fixture.db.readOnly != (mode == "shutdown") {
				t.Fatal("successful retry did not sync history or set the expected write mode")
			}
			loaded, err := fixture.db.loadJournal(types.EmptyRootHash)
			if err != nil || loaded.rootHash() != head {
				t.Fatalf("retried journal did not restore the requested head: %v", err)
			}
			if mode == "shutdown" {
				if err := journal(head); !errors.Is(err, errDatabaseReadOnly) || store.calls != 2 {
					t.Fatalf("read-only journal attempted another sync: %v", err)
				}
			}
		})
	}
}

// SYSCOIN: preserve all current KV rows and freezer file bytes before Close.
// Opening the copy runs real freezer repair, including its persisted sync
// boundary; no dropped writes or manually truncated history create this case.
func TestShutdownJournalHistorySurvivesInterruptedClose(t *testing.T) {
	fixture := newTester(t, 0, false, 0)
	defer fixture.release()
	fixture.db.config.WriteBufferSize = maxBufferSize
	fixture.db.tree.bottom().buffer.limit = maxBufferSize
	appendLayer := func() {
		parent := types.EmptyRootHash
		if len(fixture.roots) != 0 {
			parent = fixture.lastHash()
		}
		root, nodes, states := fixture.generate(parent, false)
		if err := fixture.db.Update(root, parent, uint64(len(fixture.roots)+1), nodes, states); err != nil {
			t.Fatal(err)
		}
		fixture.roots = append(fixture.roots, root)
	}
	for i := 0; i < maxDiffLayers+1; i++ {
		appendLayer()
	}
	acknowledged := fixture.lastHash()
	if err := fixture.db.Checkpoint(acknowledged); err != nil {
		t.Fatal(err)
	}
	appendLayer()
	if id := fixture.db.tree.bottom().stateID(); id != 2 {
		t.Fatalf("logical base = %d, want 2", id)
	}
	if id := rawdb.ReadPersistentStateID(fixture.db.diskdb); id != 0 {
		t.Fatalf("unexpected physical flush to state %d", id)
	}
	if err := fixture.db.Journal(fixture.lastHash()); err != nil {
		t.Fatal(err)
	}
	ancient, err := fixture.db.diskdb.AncientDatadir()
	if err != nil {
		t.Fatal(err)
	}
	imageDir := t.TempDir()
	if err := os.CopyFS(imageDir, os.DirFS(ancient)); err != nil {
		t.Fatal(err)
	}
	// Check repaired history before New, whose production error path is fatal.
	history, err := rawdb.NewStateFreezer(imageDir, false, false)
	if err != nil {
		t.Fatal(err)
	}
	count, err := history.Ancients()
	if closeErr := history.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil || count != 2 {
		t.Fatalf("restarted history ends at %d, want journal base 2: %v", count, err)
	}
	kv := rawdb.NewMemoryDatabase()
	it := fixture.db.diskdb.NewIterator(nil, nil)
	defer it.Release()
	for it.Next() {
		if err := kv.Put(bytes.Clone(it.Key()), bytes.Clone(it.Value())); err != nil {
			t.Fatal(err)
		}
	}
	if err := it.Error(); err != nil {
		t.Fatal(err)
	}
	image, err := rawdb.NewDatabaseWithFreezer(kv, imageDir, "", false)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	cold := New(image, fixture.db.config, false)
	defer cold.Close()
	verifyLiveJournalRoots(t, fixture, cold, acknowledged, fixture.lastHash())
}
