// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package pathdb

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
)

type checkpointRootReadDB struct {
	ethdb.Database
	mu            sync.Mutex
	rootErr       error
	rootReads     int
	journalWrites int
}

func (db *checkpointRootReadDB) Get(key []byte) ([]byte, error) {
	if bytes.Equal(key, rawdb.TrieNodeAccountPrefix) {
		db.mu.Lock()
		db.rootReads++
		err := db.rootErr
		db.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	return db.Database.Get(key)
}

func (db *checkpointRootReadDB) Put(key, value []byte) error {
	if bytes.Equal(key, []byte("TrieJournal")) {
		db.mu.Lock()
		db.journalWrites++
		db.mu.Unlock()
	}
	return db.Database.Put(key, value)
}

func (db *checkpointRootReadDB) injectRootError(err error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.rootErr = err
}

func (db *checkpointRootReadDB) counts() (int, int) {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.rootReads, db.journalWrites
}

func TestCheckpointEmptyPhysicalRoot(t *testing.T) {
	for _, mode := range []string{"missing-key", "wrapped-missing-key", "empty-value"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newTester(t, 0, false, 1)
			defer fixture.release()
			store := &checkpointRootReadDB{Database: fixture.db.diskdb}
			fixture.db.diskdb = store
			if blob, err := store.Get(rawdb.TrieNodeAccountPrefix); len(blob) != 0 || !errors.Is(err, ethdb.ErrKeyNotFound) {
				t.Fatalf("physical base is not truly absent: %x, %v", blob, err)
			}
			switch mode {
			case "wrapped-missing-key":
				store.injectRootError(fmt.Errorf("physical root lookup: %w", ethdb.ErrKeyNotFound))
			case "empty-value":
				if err := store.Put(rawdb.TrieNodeAccountPrefix, []byte{}); err != nil {
					t.Fatal(err)
				}
			}
			head := fixture.lastHash()
			if head == types.EmptyRootHash {
				t.Fatal("fixture has no nonempty diff state")
			}
			if err := fixture.db.Checkpoint(head); err != nil {
				t.Fatalf("legitimate empty physical base refused: %v", err)
			}
			store.injectRootError(nil)
			loaded, err := fixture.db.loadJournal(types.EmptyRootHash)
			if err != nil || loaded.rootHash() != head {
				t.Fatalf("checkpoint over empty base did not restore the head: %v", err)
			}
			if err := fixture.db.Close(); err != nil {
				t.Fatal(err)
			}
			fixture.db = New(store, nil, false)
			if err := fixture.verifyState(head); err != nil {
				t.Fatalf("reopened empty-base checkpoint lost state: %v", err)
			}
		})
	}
}

func TestCheckpointPhysicalRootReadFailure(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(fmt.Sprintf("shutdown=%t", shutdown), func(t *testing.T) {
			testCheckpointPhysicalRootReadFailure(t, shutdown)
		})
	}
}

func testCheckpointPhysicalRootReadFailure(t *testing.T, shutdown bool) {
	fixture := newTester(t, 0, false, 1)
	defer fixture.release()
	store := &checkpointRootReadDB{Database: fixture.db.diskdb}
	fixture.db.diskdb = store
	base := fixture.lastHash()
	if err := fixture.db.Commit(base, false); err != nil {
		t.Fatal(err)
	}
	physical, err := store.Get(rawdb.TrieNodeAccountPrefix)
	if err != nil || len(physical) == 0 || crypto.Keccak256Hash(physical) != base {
		t.Fatalf("fixture did not persist the nonempty base: %x, %v", physical, err)
	}
	if err := fixture.db.Checkpoint(base); err != nil {
		t.Fatal(err)
	}
	previous := bytes.Clone(rawdb.ReadTrieJournal(store))
	if len(previous) == 0 {
		t.Fatal("fixture has no prior usable checkpoint")
	}
	head, nodes, states := fixture.generate(base, false)
	if err := fixture.db.Update(head, base, 1, nodes, states); err != nil {
		t.Fatal(err)
	}
	fixture.roots = append(fixture.roots, head)
	if head == base || fixture.db.tree.bottom().rootHash() != base {
		t.Fatal("fixture needs an unflushed head above a different physical base")
	}
	// SYSCOIN: a successful earlier state lookup cannot authenticate a later
	// failed physical-root read, even though all journal writes still work.
	if err := fixture.verifyState(head); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected physical root read failure")
	store.injectRootError(injected)
	reads, writes := store.counts()
	journal := fixture.db.Checkpoint
	if shutdown {
		journal = fixture.db.Journal
	}
	if err := journal(head); !errors.Is(err, injected) {
		t.Errorf("journal returned %v; want the original root-read failure", err)
	}
	afterReads, afterWrites := store.counts()
	if afterReads != reads+1 || afterWrites != writes {
		t.Errorf("failed checkpoint performed %d root reads and %d journal writes; want 1 and 0", afterReads-reads, afterWrites-writes)
	}
	if !bytes.Equal(previous, rawdb.ReadTrieJournal(store)) {
		t.Error("failed physical-root read replaced the prior usable checkpoint")
	}
	store.injectRootError(nil)
	loaded, err := fixture.db.loadJournal(base)
	if err != nil || loaded.rootHash() != base {
		t.Errorf("prior checkpoint no longer restores its base: %v", err)
	}
	// The requested head legitimately differs from the physical base. A retry
	// must preserve the diff hierarchy, without flattening it or sealing writes.
	if err := fixture.db.Checkpoint(head); err != nil {
		t.Fatalf("checkpoint retry failed: %v", err)
	}
	if fixture.db.tree.bottom().rootHash() != base {
		t.Fatal("checkpoint unexpectedly flattened the head into the physical base")
	}
	loaded, err = fixture.db.loadJournal(base)
	if err != nil || loaded.rootHash() != head {
		t.Fatalf("checkpoint retry did not restore the requested head: %v", err)
	}
	child, nodes, states := fixture.generate(head, false)
	if err := fixture.db.Update(child, head, 2, nodes, states); err != nil {
		t.Fatalf("successful checkpoint left the database unwritable: %v", err)
	}
	fixture.roots = append(fixture.roots, child)
	if err := fixture.db.Checkpoint(child); err != nil {
		t.Fatal(err)
	}
	if err := fixture.db.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.db = New(store, nil, false)
	for _, root := range fixture.roots {
		if err := fixture.verifyState(root); err != nil {
			t.Fatalf("reopened checkpoint lost state %x: %v", root, err)
		}
	}
}

func TestCheckpointEmptyVerklePhysicalRoot(t *testing.T) {
	disk := rawdb.NewMemoryDatabase()
	defer disk.Close()
	db := New(disk, nil, true)
	defer func() { db.Close() }()
	// Keep the production Verkle namespace below the fault/counting wrapper.
	store := &checkpointRootReadDB{Database: db.diskdb}
	db.diskdb = store
	if blob, err := store.Get(rawdb.TrieNodeAccountPrefix); len(blob) != 0 || !errors.Is(err, ethdb.ErrKeyNotFound) {
		t.Fatalf("Verkle physical root is not truly absent: %x, %v", blob, err)
	}
	if err := db.Checkpoint(types.EmptyVerkleHash); err != nil {
		t.Fatalf("legitimate empty Verkle base refused: %v", err)
	}
	loaded, err := db.loadJournal(types.EmptyVerkleHash)
	if err != nil || loaded.rootHash() != types.EmptyVerkleHash {
		t.Fatalf("empty Verkle checkpoint did not load: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = New(disk, nil, true)
	if db.tree.bottom().rootHash() != types.EmptyVerkleHash {
		t.Fatal("reopened empty Verkle checkpoint has the wrong root")
	}
}
