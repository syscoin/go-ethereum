// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package core

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
)

// SYSCOIN: a rewind requires a durable baseline before another import can
// discard recovery history. Exercise both fresh execution and retained-block
// replay through InsertChain, with real paired state and metadata.
func TestSyscoinCheckpointBeforeImportFailureAndRetry(t *testing.T) {
	for _, scheme := range []string{rawdb.HashScheme, rawdb.PathScheme} {
		for _, known := range []bool{false, true} {
			for _, fault := range []string{"sync", "journal"} {
				if fault == "journal" && scheme != rawdb.PathScheme {
					continue
				}
				name := scheme + "/fresh/" + fault
				if known {
					name = scheme + "/known/" + fault
				}
				t.Run(name, func(t *testing.T) {
					db := &syscoinDurabilityDB{Database: rawdb.NewMemoryDatabase()}
					t.Cleanup(func() { db.Close() })
					f := newSyscoinRecoveryFixture(t, scheme, false, db)
					child := f.blocks[2]
					if !known {
						child = syscoinCheckpointFreshChild(t, f)
					}
					if err := f.chain.SetHead(2); err != nil {
						t.Fatal(err)
					}
					checkSyscoinDurabilityParent(t, f, f.chain, db)
					if f.chain.syscoinCheckpoint != nil {
						t.Fatal("rewind retained a checkpoint baseline from the old branch")
					}
					if f.chain.HasState(child.Root()) != known || f.chain.HasBlock(child.Hash(), 3) != known {
						t.Fatal("fixture did not distinguish fresh execution from known-block replay")
					}
					beforeSync := db.calls()
					beforeGeneration := f.chain.BeginSyscoinMetadataRead()
					headEvents := make(chan ChainHeadEvent, 2)
					chainEvents := make(chan ChainEvent, 2)
					for _, sub := range []interface{ Unsubscribe() }{
						f.chain.SubscribeChainHeadEvent(headEvents), f.chain.SubscribeChainEvent(chainEvents),
					} {
						t.Cleanup(sub.Unsubscribe)
					}
					failure := errors.New("injected implicit checkpoint " + fault + " failure")
					if fault == "journal" {
						db.setJournalError(failure)
					} else {
						db.setSyncError(failure)
					}
					_, err := f.chain.InsertChain(types.Blocks{child})
					db.setJournalError(nil)
					db.setSyncError(nil)
					if !errors.Is(err, failure) {
						t.Fatalf("import checkpoint error = %v, want injected local failure", err)
					}
					assertInvalidBlockClass(t, err, false)
					checkSyscoinDurabilityParent(t, f, f.chain, db)
					if f.chain.syscoinCheckpoint != nil {
						t.Fatal("failed fence advanced the checkpoint baseline")
					}
					if err := beforeGeneration(); err != nil || len(headEvents) != 0 || len(chainEvents) != 0 {
						t.Fatalf("failed checkpoint published a canonical change: %v", err)
					}
					if _, err := rawdb.ReadNEVMAddressUndo(db, 3, child.Hash(), common.BytesToHash([]byte(child.NevmBlockConnect.Sysblockhash))); !errors.Is(err, ethdb.ErrKeyNotFound) {
						t.Fatalf("failed checkpoint staged the child's address undo: %v", err)
					}
					if !known && (rawdb.ReadBlock(db, child.Hash(), 3) != nil || len(rawdb.ReadRawReceipts(db, child.Hash(), 3)) != 0 || f.chain.HasState(child.Root())) {
						t.Fatal("failed checkpoint persisted part of a fresh child")
					}
					wantSync := beforeSync
					if fault == "sync" {
						wantSync++
					}
					if db.calls() != wantSync {
						t.Fatalf("failed checkpoint sync calls = %d, want %d", db.calls(), wantSync)
					}
					if _, err := f.chain.InsertChain(types.Blocks{child}); err != nil {
						t.Fatalf("retry after checkpoint storage recovered: %v", err)
					}
					if db.calls() != wantSync+1 || f.chain.syscoinCheckpoint == nil || f.chain.syscoinCheckpoint.Hash() != f.blocks[1].Hash() {
						t.Fatal("retry did not fence the selected parent exactly once before import")
					}
					checked := *f
					checked.blocks = append(types.Blocks(nil), f.blocks...)
					checked.blocks[2] = child
					checked.check(t, f.chain, db, 3)
					// The successful implicit fence captures P before C. Its actual
					// durable image must restart at P with complete undo/pair state.
					image := db.crashImage(t)
					checkSyscoinDurabilityParent(t, f, reopenSyscoinDurabilityChain(t, f, image), image)
					if err := f.chain.SyncSyscoinPair(3, []byte(child.NevmBlockConnect.Sysblockhash)); err != nil {
						t.Fatal(err)
					}
					if f.chain.syscoinCheckpoint == nil || f.chain.syscoinCheckpoint.Hash() != child.Hash() {
						t.Fatal("explicit pair fence did not refresh the automatic checkpoint baseline")
					}
				})
			}
		}
	}
}

// SYSCOIN: use a genuinely different state root, not only a new header hash, so
// a failed parent fence must precede both the child block batch and state commit.
func syscoinCheckpointFreshChild(t *testing.T, f *syscoinRecoveryFixture) *types.Block {
	t.Helper()
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatal(err)
	}
	contract := common.HexToAddress("0x7777")
	db, blocks, _ := GenerateChainWithGenesis(f.genesis, ethash.NewFaker(), 3, func(i int, block *BlockGen) {
		coinbase := common.BigToAddress(big.NewInt(int64(i + 1)))
		if i == 2 {
			coinbase = common.HexToAddress("0xcafe")
		}
		block.SetCoinbase(coinbase)
		block.AddTx(types.MustSignNewTx(key, block.Signer(), &types.LegacyTx{
			Nonce: uint64(i), To: &contract, Gas: 100_000, GasPrice: big.NewInt(params.InitialBaseFee),
		}))
	})
	t.Cleanup(func() { db.Close() })
	if blocks[1].Hash() != f.blocks[1].Hash() || blocks[2].Root() == f.blocks[2].Root() {
		t.Fatal("alternate child must share the genuine parent and change the state root")
	}
	connect := *f.blocks[2].NevmBlockConnect
	connect.Block = blocks[2]
	blocks[2].NevmBlockConnect = &connect
	return blocks[2]
}

// SYSCOIN: internal retention checkpoints cover pre-activation state, while the
// remote durability command continues to require a real, nonzero Core pairing.
func TestSyscoinCheckpointBeforeActivation(t *testing.T) {
	for _, scheme := range []string{rawdb.HashScheme, rawdb.PathScheme} {
		t.Run(scheme, func(t *testing.T) {
			config := *params.AllEthashProtocolChanges
			config.SyscoinBlock = big.NewInt(100)
			genesis := &Genesis{Config: &config}
			generated, blocks, _ := GenerateChainWithGenesis(genesis, ethash.NewFaker(), 2, nil)
			t.Cleanup(func() { generated.Close() })
			db := &syscoinDurabilityDB{Database: rawdb.NewMemoryDatabase()}
			t.Cleanup(func() { db.Close() })
			cache := DefaultCacheConfigWithScheme(scheme)
			cache.SnapshotLimit = 0
			chain, err := NewBlockChain(db, cache, genesis, nil, ethash.NewFaker(), vm.Config{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(chain.Stop)
			if _, err := chain.InsertChain(blocks); err != nil {
				t.Fatal(err)
			}
			if err := chain.SetHead(1); err != nil {
				t.Fatal(err)
			}
			beforeSync := db.calls()
			for _, hash := range [][]byte{make([]byte, common.HashLength), bytes.Repeat([]byte{1}, common.HashLength)} {
				if err := chain.SyncSyscoinPair(1, hash); err == nil {
					t.Fatal("remote pair fence accepted an unpaired pre-activation block")
				}
			}
			if db.calls() != beforeSync {
				t.Fatal("invalid remote pair reached storage sync")
			}
			if _, err := chain.InsertChain(blocks[1:]); err != nil {
				t.Fatalf("pre-activation internal checkpoint/replay: %v", err)
			}
			if db.calls() != beforeSync+1 || chain.CurrentBlock().Hash() != blocks[1].Hash() || len(rawdb.ReadSYSHash(db, 1)) != 0 || len(rawdb.ReadSYSHash(db, 2)) != 0 {
				t.Fatal("pre-activation checkpoint did not preserve unpaired chain semantics")
			}
		})
	}
}

// SYSCOIN: ordinary Ethereum imports, including replay after a rewind, must not
// start calling the additional Syscoin durability barrier.
func TestSyscoinCheckpointDoesNotFenceEthereum(t *testing.T) {
	for _, scheme := range []string{rawdb.HashScheme, rawdb.PathScheme} {
		t.Run(scheme, func(t *testing.T) {
			genesis := &Genesis{Config: params.AllEthashProtocolChanges}
			generated, blocks, _ := GenerateChainWithGenesis(genesis, ethash.NewFaker(), 2, nil)
			t.Cleanup(func() { generated.Close() })
			db := &syscoinDurabilityDB{Database: rawdb.NewMemoryDatabase()}
			t.Cleanup(func() { db.Close() })
			cache := DefaultCacheConfigWithScheme(scheme)
			cache.SnapshotLimit = 0
			chain, err := NewBlockChain(db, cache, genesis, nil, ethash.NewFaker(), vm.Config{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(chain.Stop)
			db.setSyncError(errors.New("Ethereum must not reach the Syscoin sync barrier"))
			if _, err := chain.InsertChain(blocks); err != nil {
				t.Fatal(err)
			}
			if err := chain.SetHead(1); err != nil {
				t.Fatal(err)
			}
			if _, err := chain.InsertChain(blocks[1:]); err != nil {
				t.Fatal(err)
			}
			if db.calls() != 0 || chain.syscoinCheckpoint != nil {
				t.Fatal("Ethereum import acquired a Syscoin checkpoint baseline")
			}
		})
	}
}

// SYSCOIN: metadata height, not trie state ID or root changes, bounds recovery.
// Empty PoS blocks before Syscoin activation have an identical state root and
// still advance DA/undo records. Active Syscoin blocks mint rewards, so they
// cannot supply this repeated-root control without changing consensus rules.
func TestSyscoinCheckpointRepeatedRootsInOneBatch(t *testing.T) {
	config := *params.MergedTestChainConfig
	config.SyscoinBlock = new(big.Int).SetUint64(syscoinCheckpointInterval + 100)
	config.ShanghaiTime, config.CancunTime, config.PragueTime = nil, nil, nil
	genesis := &Genesis{Config: &config, BaseFee: big.NewInt(params.InitialBaseFee), GasLimit: 5_000_000}
	engine := beacon.New(ethash.NewFaker())
	generated, blocks, _ := GenerateChainWithGenesis(genesis, engine, int(syscoinCheckpointInterval+2), nil)
	t.Cleanup(func() { generated.Close() })
	for _, block := range blocks {
		if block.Root() != types.EmptyRootHash || len(block.Transactions()) != 0 {
			t.Fatalf("block %d is not an unchanged empty state", block.NumberU64())
		}
	}
	db := &syscoinDurabilityDB{Database: rawdb.NewMemoryDatabase()}
	t.Cleanup(func() { db.Close() })
	cache := DefaultCacheConfigWithScheme(rawdb.PathScheme)
	cache.SnapshotLimit = 0
	chain, err := NewBlockChain(db, cache, genesis, nil, engine, vm.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(chain.Stop)
	if cache.TrieDirtyLimit != 256 {
		t.Fatal("repeated-root fixture must keep the normal trie buffer")
	}
	checkDurable := func() {
		t.Helper()
		last := blocks[len(blocks)-1]
		if chain.CurrentBlock().Hash() != last.Hash() {
			t.Fatal("single batch did not publish its complete canonical suffix")
		}
		if rawdb.ReadPersistentStateID(db) != 0 {
			t.Fatal("unchanged empty roots unexpectedly advanced the physical trie state")
		}
		image := db.crashImage(t)
		want := blocks[syscoinCheckpointInterval-1]
		if rawdb.ReadHeadBlockHash(image) != want.Hash() || rawdb.ReadHeadHeaderHash(image) != want.Hash() || rawdb.ReadHeadFastBlockHash(image) != want.Hash() {
			t.Fatal("periodic sync did not capture all head markers at the metadata-height boundary")
		}
		if len(rawdb.ReadSYSHash(image, want.NumberU64())) != 0 {
			t.Fatal("pre-activation checkpoint invented a Core pairing")
		}
		if undo, err := rawdb.ReadNEVMAddressUndo(image, want.NumberU64(), want.Hash(), common.Hash{}); err != nil || len(undo) != 0 {
			t.Fatalf("durable tip's explicit empty undo record = %v, error %v", undo, err)
		}
		// Empty DA lists intentionally omit the per-height value. The index
		// watermark must still distinguish this tip from its unfenced child.
		if err := rawdb.EnsureDataHashIndex(image, want.NumberU64()); err != nil {
			t.Fatalf("durable DA index does not reconstruct at the captured head: %v", err)
		}
		if err := rawdb.EnsureDataHashIndex(image, want.NumberU64()+1); err == nil {
			t.Fatal("durable DA index unexpectedly includes the unfenced next block")
		}
		cold, err := NewBlockChain(image, cache, genesis, nil, beacon.New(ethash.NewFaker()), vm.Config{}, nil)
		if err != nil {
			t.Fatalf("reopen periodic metadata checkpoint: %v", err)
		}
		t.Cleanup(cold.Stop)
		if cold.CurrentBlock().Hash() != want.Hash() || cold.CurrentHeader().Hash() != want.Hash() || cold.CurrentSnapBlock().Hash() != want.Hash() || !cold.HasState(want.Root()) {
			t.Fatal("cold restart did not retain the complete unpaired checkpoint")
		}
	}
	beforeSync := db.calls()
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("import repeated-root batch: %v", err)
	}
	if db.calls() != beforeSync+2 {
		t.Fatalf("empty batch performed %d syncs, want one baseline and one periodic fence", db.calls()-beforeSync)
	}
	checkDurable()

	// SetHead retains bodies and the identical root. Reimport therefore takes
	// the known-block path for the whole batch, which must enforce the same bound.
	if err := chain.SetHead(0); err != nil {
		t.Fatal(err)
	}
	if !chain.HasBlock(blocks[0].Hash(), 1) || !chain.HasState(blocks[0].Root()) {
		t.Fatal("rewind did not retain the known-block replay fixture")
	}
	beforeSync = db.calls()
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("replay repeated-root batch: %v", err)
	}
	if db.calls() != beforeSync+2 {
		t.Fatalf("known empty batch performed %d syncs, want one baseline and one periodic fence", db.calls()-beforeSync)
	}
	checkDurable()
}
