// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package core

import (
	"bytes"
	"errors"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
)

// SYSCOIN: rejected constructors must release their state-history freezer without
// closing the caller's database. Probe the lock before retrying, since retrying a
// leaked pathdb directly would terminate the test process through log.Crit.
func TestSyscoinConstructorFailureReleasesStateFreezer(t *testing.T) {
	for _, scenario := range []string{"split-markers", "missing-undo", "genesis-mismatch", "compatibility-rewind-before-snapshot"} {
		t.Run(scenario, func(t *testing.T) {
			source := openSyscoinRecoveryPathDB(t, t.TempDir())
			f := newSyscoinRecoveryFixture(t, rawdb.PathScheme, false, source)
			if scenario != "missing-undo" {
				// Keep the tip available on these cold starts so the refusal is
				// reached without an earlier missing-state repair.
				if err := f.chain.SyncSyscoinPair(3, []byte(f.blocks[2].NevmBlockConnect.Sysblockhash)); err != nil {
					t.Fatal(err)
				}
			}
			image := &syscoinConstructorDB{Database: copySyscoinRetentionDB(t, source)}
			cache := *f.cache
			genesis := f.genesis.copy()
			wantHead := uint64(3)
			var wantError string
			repair := func() {}
			switch scenario {
			case "split-markers":
				rawdb.WriteHeadHeaderHash(image, f.blocks[1].Hash())
				wantError = "inconsistent Syscoin head markers"
				repair = func() { rawdb.WriteHeadHeaderHash(image, f.blocks[2].Hash()) }
			case "missing-undo", "compatibility-rewind-before-snapshot":
				key := new(syscoinConstructorUndoKey)
				if err := rawdb.DeleteNEVMAddressUndo(key, 2); err != nil {
					t.Fatal(err)
				}
				undo, err := image.Get(key.key)
				if err != nil {
					t.Fatal(err)
				}
				if err := rawdb.DeleteNEVMAddressUndo(image, 2); err != nil {
					t.Fatal(err)
				}
				wantError, wantHead = "preflight Syscoin address rewind", 1
				repair = func() {
					if err := image.Put(key.key, undo); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "compatibility-rewind-before-snapshot" {
					// Enable a past optional fork to request a genuine config
					// rewind from 3 to 1, with the tip state still available.
					genesis.Config.NexusBlock = big.NewInt(2)
					compat := f.genesis.Config.CheckCompatible(genesis.Config, 3, f.blocks[2].Time())
					if compat == nil || compat.RewindToBlock != 1 {
						t.Fatalf("fixture did not request the intended config rewind: %v", compat)
					}
					cache.SnapshotLimit, cache.SnapshotWait = 16, false
					cache.SnapshotNoBuild = false
					if root := rawdb.ReadSnapshotRoot(image); root != (common.Hash{}) {
						t.Fatalf("fixture unexpectedly has a snapshot at %s", root)
					}
					image.snapshotRootReads.Store(0)
				}
			case "genesis-mismatch":
				genesis.ExtraData = []byte("different constructor genesis")
				wantError = "database contains incompatible genesis"
				repair = func() { genesis = f.genesis.copy() }
			}
			rejected, err := NewBlockChain(image, &cache, genesis, nil, ethash.NewFaker(), vm.Config{}, nil)
			if rejected != nil {
				rejected.Stop()
				t.Fatal("invalid constructor returned an owned blockchain")
			}
			if err == nil || !strings.Contains(err.Error(), wantError) {
				t.Fatalf("constructor error = %v, want original %q failure", err, wantError)
			}
			if scenario == "genesis-mismatch" {
				var mismatch *GenesisMismatchError
				if !errors.As(err, &mismatch) {
					t.Fatalf("constructor lost the typed genesis error: %v", err)
				}
			} else if scenario == "missing-undo" || scenario == "compatibility-rewind-before-snapshot" {
				if !errors.Is(err, ethdb.ErrKeyNotFound) {
					t.Fatalf("constructor lost the underlying missing-undo error: %v", err)
				}
			}
			assertSyscoinConstructorFreezerReleased(t, image)
			if scenario == "compatibility-rewind-before-snapshot" {
				if reads := image.snapshotRootReads.Load(); reads != 0 {
					t.Fatalf("rejected config rewind started snapshot loading/rebuilding (%d root reads)", reads)
				}
				if stored := rawdb.ReadChainConfig(image, f.genesis.ToBlock().Hash()); stored == nil || stored.NexusBlock != nil {
					t.Fatal("refused config rewind installed its new fork configuration")
				}
			}
			// A constructor owns the trie wrapper, not its caller's hot database.
			probeKey, probeValue := []byte("constructor-cleanup-probe"), []byte("still-open")
			if err := image.Put(probeKey, probeValue); err != nil {
				t.Fatalf("constructor closed caller database: %v", err)
			}
			if got, err := image.Get(probeKey); err != nil || !bytes.Equal(got, probeValue) {
				t.Fatalf("caller database cannot be reused: value=%q err=%v", got, err)
			}
			if err := image.Delete(probeKey); err != nil {
				t.Fatal(err)
			}
			repair()
			restarted, err := NewBlockChain(image, &cache, genesis, nil, ethash.NewFaker(), vm.Config{}, nil)
			if err != nil {
				t.Fatalf("healthy retry in the same process: %v", err)
			}
			stop := sync.OnceFunc(restarted.Stop)
			t.Cleanup(stop)
			f.check(t, restarted, image, wantHead)
			if !restarted.HasState(f.blocks[wantHead-1].Root()) {
				t.Fatal("healthy retry lost the selected EVM state")
			}
			if scenario == "compatibility-rewind-before-snapshot" {
				if restarted.snaps == nil || restarted.snaps.Snapshot(restarted.CurrentBlock().Root) == nil {
					t.Fatal("healthy retry did not initialize snapshots at the rewound head")
				}
			}
			ancient, err := image.AncientDatadir()
			if err != nil {
				t.Fatal(err)
			}
			if probe, err := rawdb.NewStateFreezer(ancient, false, false); err == nil {
				probe.Close()
				t.Fatal("successful constructor released the state-history lock prematurely")
			}
			stop()
			assertSyscoinConstructorFreezerReleased(t, image)
		})
	}
}

// SYSCOIN: counting the synchronous load entry avoids timing-based goroutine
// assertions. With no saved snapshot and NoBuild=false, reaching snapshot.New
// would load SnapshotRoot and start the asynchronous rebuild before returning.
type syscoinConstructorDB struct {
	ethdb.Database
	snapshotRootReads atomic.Int32
}

func (db *syscoinConstructorDB) Get(key []byte) ([]byte, error) {
	if bytes.Equal(key, rawdb.SnapshotRootKey) {
		db.snapshotRootReads.Add(1)
	}
	return db.Database.Get(key)
}

func (db *syscoinConstructorDB) SyncKeyValue() error { return ethdb.SyncKeyValue(db.Database) }

// SYSCOIN: obtain the undo key through its accessor, without copying its encoding.
type syscoinConstructorUndoKey struct{ key []byte }

func (*syscoinConstructorUndoKey) Put([]byte, []byte) error {
	return errors.New("unexpected put while identifying undo key")
}

func (w *syscoinConstructorUndoKey) Delete(key []byte) error {
	w.key = bytes.Clone(key)
	return nil
}

func assertSyscoinConstructorFreezerReleased(t *testing.T, db ethdb.Database) {
	t.Helper()
	ancient, err := db.AncientDatadir()
	if err != nil || ancient == "" {
		t.Fatalf("fixture requires a real state-history freezer: path=%q err=%v", ancient, err)
	}
	probe, err := rawdb.NewStateFreezer(ancient, false, false)
	if err != nil {
		t.Fatalf("failed constructor retained the state-history freezer lock: %v", err)
	}
	if err := probe.Close(); err != nil {
		t.Fatalf("close independent state-freezer probe: %v", err)
	}
}
