// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package core

import (
	"bytes"
	"errors"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/syscoin/syscoinwire/syscoin/wire"
)

// SYSCOIN: small updates to the same accounts can leave the physical trie
// unchanged longer than the metadata undo window. Periodic checkpoints must
// keep cold recovery inside that window even without a capacity-driven flush.
func TestSyscoinCheckpointWithinRetainedUndo(t *testing.T) {
	config := *params.AllEthashProtocolChanges
	config.SyscoinBlock = big.NewInt(0)
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatal(err)
	}
	sender, recipient := crypto.PubkeyToAddress(key.PublicKey), common.HexToAddress("0x7777")
	genesis := &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: &config, Alloc: types.GenesisAlloc{
		sender: {Balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil)},
	}}
	const count = rawdb.DataBlockLimit + 2
	generated, blocks, _ := GenerateChainWithGenesis(genesis, ethash.NewFaker(), count, func(i int, block *BlockGen) {
		block.SetCoinbase(common.HexToAddress("0x8888"))
		block.AddTx(types.MustSignNewTx(key, block.Signer(), &types.LegacyTx{
			Nonce: uint64(i), To: &recipient, Gas: 21000, GasPrice: big.NewInt(params.InitialBaseFee),
		}))
	})
	defer generated.Close()
	for i, block := range blocks {
		sys := common.BigToHash(big.NewInt(int64(i + 1)))
		block.NevmBlockConnect = &types.NEVMBlockConnect{
			Block: block, Sysblockhash: string(sys.Bytes()), Diff: new(wire.NEVMAddressDiff),
		}
	}
	for _, snapshots := range []bool{false, true} {
		name := "snapshots-off"
		if snapshots {
			name = "snapshots-on"
		}
		t.Run(name, func(t *testing.T) {
			disk, err := rawdb.NewDatabaseWithFreezer(rawdb.NewMemoryDatabase(), t.TempDir(), "", false)
			if err != nil {
				t.Fatal(err)
			}
			db := &syscoinDurabilityDB{Database: disk}
			t.Cleanup(func() { db.Close() })
			cache := DefaultCacheConfigWithScheme(rawdb.PathScheme)
			cache.StateHistory = params.FullImmutabilityThreshold
			cache.SnapshotLimit = 0
			if snapshots {
				cache.SnapshotLimit = 256
				cache.SnapshotWait = true
			}
			if cache.TrieDirtyLimit != 256 {
				t.Fatalf("fixture requires the normal 256 MiB trie buffer, got %d", cache.TrieDirtyLimit)
			}
			chain, err := NewBlockChain(db, cache, genesis, nil, ethash.NewFaker(), vm.Config{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(chain.Stop)
			if _, err := chain.InsertChain(blocks[:1]); err != nil {
				t.Fatal(err)
			}
			if err := chain.SyncSyscoinPair(1, []byte(blocks[0].NevmBlockConnect.Sysblockhash)); err != nil {
				t.Fatal(err)
			}
			physicalID := rawdb.ReadPersistentStateID(db)
			physicalRoot := crypto.Keccak256Hash(rawdb.ReadAccountTrieNode(db, nil))
			// One batch crosses both checkpoint boundaries. A check only at the
			// entry to InsertChain would miss them and expire the original undo.
			if _, err := chain.InsertChain(blocks[1:]); err != nil {
				t.Fatalf("import beyond the retained undo window: %v", err)
			}
			const checkpoint = 1 + (count-2)/syscoinCheckpointInterval*syscoinCheckpointInterval
			if rawdb.ReadPersistentStateID(db) != physicalID || crypto.Keccak256Hash(rawdb.ReadAccountTrieNode(db, nil)) != physicalRoot {
				t.Fatal("fixture unexpectedly flushed the physical trie")
			}
			if calls := db.calls(); calls <= 1 || calls > 2+count/syscoinCheckpointInterval {
				t.Fatalf("checkpoint cadence must be bounded rather than per block: %d syncs for %d imports", calls, count)
			}
			// Block 2's undo is really gone. An implementation that retains only
			// the explicit fence at block 1 cannot repair this full current image.
			old := blocks[1]
			if _, err := rawdb.ReadNEVMAddressUndo(db, 2, old.Hash(), common.BytesToHash([]byte(old.NevmBlockConnect.Sysblockhash))); !errors.Is(err, ethdb.ErrKeyNotFound) {
				t.Fatalf("fixture did not expire the original recovery history: %v", err)
			}
			image := &syscoinDurabilityDB{Database: copySyscoinRetentionDB(t, db)}
			coldTrie := triedb.NewDatabase(image, cache.triedbConfig(false))
			if _, err := coldTrie.NodeReader(blocks[checkpoint-1].Root()); err != nil {
				t.Fatalf("cold trie lost the recent checkpoint: %v", err)
			}
			if _, err := coldTrie.NodeReader(blocks[count-1].Root()); err == nil {
				t.Fatal("fixture accidentally persisted the uncheckpointed tip")
			}
			if err := coldTrie.Close(); err != nil {
				t.Fatal(err)
			}
			restarted, err := NewBlockChain(image, cache, genesis, nil, ethash.NewFaker(), vm.Config{}, nil)
			if err != nil {
				t.Fatalf("cold restart beyond the original undo window: %v", err)
			}
			t.Cleanup(restarted.Stop)
			number, _, ok := restarted.CurrentSyscoinPair()
			if !ok || number < checkpoint || number >= count || count-number > syscoinCheckpointInterval {
				t.Fatalf("recovery endpoint %d/%t is not within the bounded checkpoint window", number, ok)
			}
			checkSyscoinRetentionHead(t, restarted, image, blocks[number-1], sender, snapshots)
			for _, block := range blocks[number:] {
				if _, err := restarted.InsertChain(types.Blocks{block}); err != nil {
					t.Fatalf("replay %d after cold recovery: %v", block.NumberU64(), err)
				}
			}
			tip := blocks[count-1]
			checkSyscoinRetentionHead(t, restarted, image, tip, sender, snapshots)
			if err := restarted.SyncSyscoinPair(tip.NumberU64(), []byte(tip.NevmBlockConnect.Sysblockhash)); err != nil {
				t.Fatalf("fence replayed tip: %v", err)
			}
		})
	}
}

// SYSCOIN: preserve every current KV row and every freezer file before Stop or
// Close can journal or sync the source. The image has independent file handles.
func copySyscoinRetentionDB(t *testing.T, source ethdb.Database) ethdb.Database {
	t.Helper()
	ancient, err := source.AncientDatadir()
	if err != nil || ancient == "" {
		t.Fatalf("state history requires a real freezer: path=%q err=%v", ancient, err)
	}
	target := t.TempDir()
	if err := os.CopyFS(target, os.DirFS(ancient)); err != nil {
		t.Fatal(err)
	}
	image, err := rawdb.NewDatabaseWithFreezer(copySyscoinRecoveryDB(t, source), target, "", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { image.Close() })
	return image
}

// SYSCOIN: recovery must publish a coherent pair with usable EVM state, then
// allow the retained authentic transactions to be replayed from that endpoint.
func checkSyscoinRetentionHead(t *testing.T, chain *BlockChain, db ethdb.Database, want *types.Block, sender common.Address, snapshots bool) {
	t.Helper()
	number, sys, ok := chain.CurrentSyscoinPair()
	if !ok || number != want.NumberU64() || !bytes.Equal(sys, []byte(want.NevmBlockConnect.Sysblockhash)) {
		t.Fatalf("recovered pair = %d/%x/%t, want %d", number, sys, ok, want.NumberU64())
	}
	if chain.CurrentBlock().Hash() != want.Hash() || chain.CurrentHeader().Hash() != want.Hash() ||
		chain.CurrentSnapBlock().Hash() != want.Hash() || rawdb.ReadHeadBlockHash(db) != want.Hash() ||
		rawdb.ReadHeadHeaderHash(db) != want.Hash() || rawdb.ReadHeadFastBlockHash(db) != want.Hash() {
		t.Fatal("recovered head markers disagree")
	}
	state, err := chain.StateAt(want.Root())
	if err != nil {
		t.Fatalf("read recovered state: %v", err)
	}
	if nonce := state.GetNonce(sender); nonce != number {
		t.Fatalf("recovered sender nonce %d, want %d", nonce, number)
	}
	if err := state.Error(); err != nil {
		t.Fatalf("read recovered sender: %v", err)
	}
	if snapshots {
		if chain.snaps == nil || chain.snaps.Snapshot(want.Root()) == nil {
			t.Fatal("recovered state has no usable snapshot")
		}
		account, err := chain.snaps.Snapshot(want.Root()).Account(crypto.Keccak256Hash(sender.Bytes()))
		if err != nil || account == nil || account.Nonce != number {
			t.Fatalf("recovered snapshot sender = %v, err=%v", account, err)
		}
	}
}
