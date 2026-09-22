// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package core

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/triedb"
)

// SYSCOIN: snapshots are derived data. An older snapshot root or a stale
// snapshot recovery marker must not move startup below an available checkpoint.
func TestSyscoinSnapshotRecoveryPreservesCheckpoint(t *testing.T) {
	cases := []struct {
		name          string
		snapshots     bool
		noBuild       bool
		staleRecovery bool
		alreadyParent bool
	}{
		{name: "snapshots-off"},
		{name: "snapshots-on", snapshots: true},
		{name: "snapshots-stale-marker", snapshots: true, staleRecovery: true},
		{name: "snapshots-no-build", snapshots: true, noBuild: true},
		{name: "snapshots-no-build-stale-marker", snapshots: true, noBuild: true, staleRecovery: true},
		{name: "already-parent-stale-marker", snapshots: true, staleRecovery: true, alreadyParent: true},
		{name: "already-parent-no-build-stale-marker", snapshots: true, noBuild: true, staleRecovery: true, alreadyParent: true},
	}
	for _, scheme := range []string{rawdb.HashScheme, rawdb.PathScheme} {
		for _, test := range cases {
			t.Run(scheme+"/"+test.name, func(t *testing.T) {
				db := &syscoinDurabilityDB{Database: rawdb.NewMemoryDatabase()}
				t.Cleanup(func() { db.Close() })
				f := newSyscoinRecoveryFixture(t, scheme, test.snapshots, db)
				parent, child := f.blocks[1], f.blocks[2]
				if f.cache.TrieDirtyLimit != 256 {
					t.Fatalf("fixture requires the normal 256 MiB trie buffer, got %d", f.cache.TrieDirtyLimit)
				}
				// The metadata-rich fixture anchors trie and snapshot at block 1.
				// This supplies the same older snapshot root as a natural snapshot
				// cap after 128 imports, with only three genuine transaction blocks.
				if test.snapshots && rawdb.ReadSnapshotRoot(db) != f.blocks[0].Root() {
					t.Fatal("fixture snapshot is not anchored below the checkpoint")
				}
				disconnectSyscoinDurabilityChild(t, f)
				checkSyscoinDurabilityParent(t, f, f.chain, db)
				if err := f.chain.SyncSyscoinPair(parent.NumberU64(), []byte(parent.NevmBlockConnect.Sysblockhash)); err != nil {
					t.Fatalf("fence parent: %v", err)
				}
				journal := bytes.Clone(rawdb.ReadTrieJournal(db))
				physicalID := rawdb.ReadPersistentStateID(db)
				if !test.alreadyParent {
					// Reapply the authentic child through ordinary import without
					// checkpointing it or flushing the normal trie buffer.
					if _, err := f.chain.InsertChain(types.Blocks{child}); err != nil {
						t.Fatalf("ordinary child import: %v", err)
					}
					f.check(t, f.chain, db, child.NumberU64())
				}
				if db.calls() != 1 || !bytes.Equal(journal, rawdb.ReadTrieJournal(db)) || rawdb.ReadPersistentStateID(db) != physicalID {
					t.Fatal("ordinary import unexpectedly fenced or flushed the checkpoint")
				}
				// Copy every current KV row before any Stop. In the already-parent
				// cases, the image represents a crash after the paired head repair
				// but before stale snapshot recovery metadata was cleaned up.
				image := copySyscoinRecoveryDB(t, db)
				if test.staleRecovery {
					rawdb.WriteSnapshotRecoveryNumber(image, child.NumberU64())
				}
				cache := *f.cache
				cache.SnapshotNoBuild = test.noBuild
				coldTrie := triedb.NewDatabase(image, cache.triedbConfig(false))
				if _, err := coldTrie.NodeReader(parent.Root()); err != nil {
					t.Fatalf("cold trie lost the acknowledged parent before startup: %v", err)
				}
				if _, err := coldTrie.NodeReader(child.Root()); err == nil {
					t.Fatal("fixture accidentally persisted the uncheckpointed child state")
				}
				if err := coldTrie.Close(); err != nil {
					t.Fatal(err)
				}
				reopen := func(image ethdb.Database) (*BlockChain, *syscoinDurabilityDB) {
					t.Helper()
					store := &syscoinDurabilityDB{Database: image}
					chain, err := NewBlockChain(store, &cache, f.genesis, nil, ethash.NewFaker(), vm.Config{}, nil)
					if err != nil {
						t.Fatalf("cold blockchain restart: %v", err)
					}
					t.Cleanup(chain.Stop)
					return chain, store
				}
				restarted, restartedDB := reopen(image)
				checkSyscoinDurabilityParent(t, f, restarted, restartedDB)
				checkSyscoinRecoveredSnapshotState(t, restarted, parent, test.snapshots, test.noBuild)
				// A second cold start must retain the repaired pair even when the
				// initial image already had P as its head and skipped head repair.
				restarted, restartedDB = reopen(copySyscoinRecoveryDB(t, restartedDB))
				checkSyscoinDurabilityParent(t, f, restarted, restartedDB)
				checkSyscoinRecoveredSnapshotState(t, restarted, parent, test.snapshots, test.noBuild)
				if _, err := restarted.InsertChain(types.Blocks{child}); err != nil {
					t.Fatalf("reapply child after snapshot recovery: %v", err)
				}
				f.check(t, restarted, restartedDB, child.NumberU64())
				checkSyscoinRecoveredSnapshotState(t, restarted, child, test.snapshots, test.noBuild)
				if err := restarted.SyncSyscoinPair(child.NumberU64(), []byte(child.NevmBlockConnect.Sysblockhash)); err != nil {
					t.Fatalf("fence reapplied child: %v", err)
				}
				if restartedDB.calls() != 1 {
					t.Fatal("reapplied child did not reach the durability barrier")
				}
				final, finalDB := reopen(restartedDB.crashImage(t))
				f.check(t, final, finalDB, child.NumberU64())
				checkSyscoinRecoveredSnapshotState(t, final, child, test.snapshots, test.noBuild)
			})
		}
	}
}

// SYSCOIN: require actual account/code reads and, when enabled, a usable
// snapshot for the selected root. NoBuild may deliberately fall back to tries.
func checkSyscoinRecoveredSnapshotState(t *testing.T, chain *BlockChain, head *types.Block, snapshots, noBuild bool) {
	t.Helper()
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatal(err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	state, err := chain.StateAt(head.Root())
	if err != nil {
		t.Fatalf("read recovered trie state: %v", err)
	}
	if nonce := state.GetNonce(sender); nonce != head.NumberU64() {
		t.Fatalf("recovered sender nonce=%d, want %d", nonce, head.NumberU64())
	}
	balance := state.GetBalance(sender)
	if balance.IsZero() || !bytes.Equal(state.GetCode(common.HexToAddress("0x7777")), common.FromHex("0x60006000a000")) {
		t.Fatal("recovered sender balance or contract code is unavailable")
	}
	if err := state.Error(); err != nil {
		t.Fatalf("recovered account/code lookup: %v", err)
	}
	if !snapshots {
		if chain.snaps != nil {
			t.Fatal("disabled snapshots unexpectedly created a tree")
		}
		return
	}
	if chain.snaps == nil {
		if noBuild {
			return
		}
		t.Fatal("snapshot rebuilding did not produce a usable tree")
	}
	snap := chain.snaps.Snapshot(head.Root())
	if snap == nil {
		t.Fatalf("snapshot tree does not contain recovered root %s", head.Root())
	}
	account, err := snap.Account(crypto.Keccak256Hash(sender.Bytes()))
	if err != nil || account == nil {
		t.Fatalf("read recovered snapshot account: account=%v err=%v", account, err)
	}
	if account.Nonce != head.NumberU64() || account.Balance.Cmp(balance) != 0 {
		t.Fatalf("recovered snapshot account disagrees with trie at block %d", head.NumberU64())
	}
}
