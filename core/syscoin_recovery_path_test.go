// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package core

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/ethdb/pebble"
	"github.com/ethereum/go-ethereum/triedb"
)

// SYSCOIN: a real state-history freezer is required to exercise Recover, rather
// than merely finding an older root still available in memory.
func openSyscoinRecoveryPathDB(t *testing.T, dir string) ethdb.Database {
	t.Helper()
	kv, err := pebble.New(dir, 0, 0, "", false, true)
	if err != nil {
		t.Fatal(err)
	}
	db, err := rawdb.NewDatabaseWithFreezer(kv, filepath.Join(dir, "ancient"), "", false)
	if err != nil {
		kv.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestSyscoinPathHistoryLiveRewindRefuses(t *testing.T) {
	db := openSyscoinRecoveryPathDB(t, t.TempDir())
	f := newSyscoinRecoveryFixture(t, rawdb.PathScheme, false, db)
	if err := f.chain.triedb.Commit(f.blocks[2].Root(), false); err != nil {
		t.Fatal(err)
	}
	if f.chain.HasState(f.blocks[0].Root()) || !f.chain.stateRecoverable(f.blocks[0].Root()) {
		t.Fatal("fixture did not require actual historical trie recovery")
	}
	err := f.chain.SetHead(1)
	if err == nil || !strings.Contains(err.Error(), "offline restart") {
		t.Fatalf("live mutating trie recovery: %v", err)
	}
	f.check(t, f.chain, db, 3)
	if !f.chain.HasState(f.blocks[2].Root()) || f.chain.HasState(f.blocks[0].Root()) {
		t.Fatal("refused live rewind changed trie state")
	}
}

func TestSyscoinPathHistoryStartupSameHead(t *testing.T) {
	dir := t.TempDir()
	db := openSyscoinRecoveryPathDB(t, dir)
	f := newSyscoinRecoveryFixture(t, rawdb.PathScheme, false, db)
	// Model the independent trie persistence boundary: head/metadata are at 1,
	// while a later trie state has reached disk before the process terminates.
	if err := f.chain.SetHead(1); err != nil {
		t.Fatal(err)
	}
	if err := f.chain.triedb.Commit(f.blocks[2].Root(), false); err != nil {
		t.Fatal(err)
	}
	if f.chain.HasState(f.blocks[0].Root()) || !f.chain.stateRecoverable(f.blocks[0].Root()) {
		t.Fatal("published head was not exclusively recoverable from disk history")
	}
	f.chain.stopWithoutSaving()
	if err := f.chain.triedb.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openSyscoinRecoveryPathDB(t, dir)
	chain, err := NewBlockChain(reopened, f.cache, f.genesis, nil, ethash.NewFaker(), vm.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	f.check(t, chain, reopened, 1)
	if !chain.HasState(f.blocks[0].Root()) {
		t.Fatal("constructor did not recover the unchanged published head")
	}
	f.replay(t, chain, reopened)
}

type syscoinPathHeadFailDB struct {
	ethdb.Database
	err error
}

func (db *syscoinPathHeadFailDB) NewBatch() ethdb.Batch {
	return &syscoinPathHeadFailBatch{Batch: db.Database.NewBatch(), db: db}
}

type syscoinPathHeadFailBatch struct {
	ethdb.Batch
	db      *syscoinPathHeadFailDB
	hasHead bool
}

func (b *syscoinPathHeadFailBatch) Put(key, value []byte) error {
	b.hasHead = b.hasHead || bytes.Equal(key, []byte("LastBlock"))
	return b.Batch.Put(key, value)
}

func (b *syscoinPathHeadFailBatch) Write() error {
	if b.hasHead && b.db.err != nil {
		return b.db.err
	}
	return b.Batch.Write()
}

func TestSyscoinPathHistoryRepairBatchFailureRetry(t *testing.T) {
	db := &syscoinPathHeadFailDB{Database: openSyscoinRecoveryPathDB(t, t.TempDir())}
	f := newSyscoinRecoveryFixture(t, rawdb.PathScheme, false, db)
	if err := f.chain.triedb.Commit(f.blocks[1].Root(), false); err != nil {
		t.Fatal(err)
	}
	if err := f.chain.triedb.Close(); err != nil {
		t.Fatal(err)
	}
	f.chain.triedb = triedb.NewDatabase(db, f.cache.triedbConfig(false))
	f.chain.statedb = state.NewDatabase(f.chain.triedb, nil)
	if f.chain.HasState(f.blocks[2].Root()) || f.chain.HasState(f.blocks[0].Root()) || !f.chain.stateRecoverable(f.blocks[0].Root()) {
		t.Fatal("fixture did not lose head state while retaining target disk history")
	}
	// Exercise the offline repair helper boundary with a reopened trie DB. The
	// root threshold models an older snapshot anchor. Only the final metadata
	// batch fails; real path-history Recover writes must succeed first.
	db.err = errors.New("injected final metadata batch failure")
	_, err := f.chain.setHeadBeyondRoot(3, 0, f.blocks[0].Root(), true)
	if !errors.Is(err, db.err) {
		t.Fatalf("repair error = %v, want metadata failure", err)
	}
	db.err = nil
	if !f.chain.HasState(f.blocks[0].Root()) {
		t.Fatal("test did not pass through mutating historical trie recovery")
	}
	f.check(t, f.chain, db, 3)
	for _, block := range f.blocks[1:] {
		if _, err := rawdb.ReadNEVMAddressUndo(db, block.NumberU64(), block.Hash(), common.BytesToHash([]byte(block.NevmBlockConnect.Sysblockhash))); err != nil {
			t.Fatalf("failed final batch lost retry journal: %v", err)
		}
	}
	if _, err := f.chain.setHeadBeyondRoot(3, 0, f.blocks[0].Root(), true); err != nil {
		t.Fatalf("retry after trie recovered but metadata commit failed: %v", err)
	}
	f.check(t, f.chain, db, 1)
	f.replay(t, f.chain, db)
}
