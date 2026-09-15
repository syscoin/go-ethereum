// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/syscoin/syscoinwire/syscoin/wire"
)

// SYSCOIN: exercise local recovery with real state changes, retained block
// bodies, duplicate DA/BTC entries, and address additions, moves and removals.
type syscoinRecoveryFixture struct {
	genesis *Genesis
	cache   *CacheConfig
	chain   *BlockChain
	blocks  types.Blocks
	da      [3]common.Hash
	btc     [2]common.Hash
	addr    [3]common.Address
}

func newSyscoinRecoveryFixture(t *testing.T, scheme string, snapshots bool, db ethdb.Database) *syscoinRecoveryFixture {
	t.Helper()
	config := *params.AllEthashProtocolChanges
	config.SyscoinBlock = big.NewInt(0)
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatal(err)
	}
	contract := common.HexToAddress("0x7777")
	f := &syscoinRecoveryFixture{
		genesis: &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: &config, Alloc: types.GenesisAlloc{
			crypto.PubkeyToAddress(key.PublicKey): {Balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)},
			contract:                              {Code: common.FromHex("0x60006000a000")}, // LOG0, then STOP.
		}},
		cache: DefaultCacheConfigWithScheme(scheme),
		da:    [3]common.Hash{common.HexToHash("0xd1"), common.HexToHash("0xd2"), common.HexToHash("0xd3")},
		btc:   [2]common.Hash{common.HexToHash("0xb1"), common.HexToHash("0xb3")},
		addr:  [3]common.Address{common.HexToAddress("0xa1"), common.HexToAddress("0xa2"), common.HexToAddress("0xa3")},
	}
	f.cache.SnapshotLimit = 0
	if snapshots {
		f.cache.SnapshotLimit = 16
		f.cache.SnapshotWait = true
	}
	engine := ethash.NewFaker()
	generatedDB, blocks, _ := GenerateChainWithGenesis(f.genesis, engine, 3, func(i int, block *BlockGen) {
		block.SetCoinbase(common.BigToAddress(big.NewInt(int64(i + 1))))
		block.AddTx(types.MustSignNewTx(key, block.Signer(), &types.LegacyTx{
			Nonce: uint64(i), To: &contract, Gas: 100_000, GasPrice: big.NewInt(params.InitialBaseFee),
		}))
	})
	t.Cleanup(func() { generatedDB.Close() })
	f.blocks = blocks
	f.chain, err = NewBlockChain(db, f.cache, f.genesis, nil, engine, vm.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.chain.Stop)
	for i, block := range blocks {
		connect := &types.NEVMBlockConnect{
			Block: block, Sysblockhash: string(bytes.Repeat([]byte{byte(i + 1)}, common.HashLength)),
			VersionHashes: []*common.Hash{&f.da[i]}, Diff: new(wire.NEVMAddressDiff),
		}
		switch i {
		case 0:
			connect.BTCPrevHash = f.btc[0]
			connect.Diff.AddedMNNEVM = []wire.NEVMAddressEntry{
				{Address: f.addr[0].Bytes(), CollateralHeight: 0},
				{Address: f.addr[2].Bytes(), CollateralHeight: 10},
			}
		case 1:
			connect.BTCPrevHash = f.btc[0] // Existing BTC checkpoint has no new carrier index.
			connect.VersionHashes = append(connect.VersionHashes, &f.da[0])
			connect.Diff.UpdatedMNNEVM = []wire.NEVMAddressUpdateEntry{{
				OldAddress: f.addr[0].Bytes(), NewAddress: f.addr[1].Bytes(), CollateralHeight: 20,
			}}
			connect.Diff.RemovedMNNEVM = []wire.NEVMRemoveEntry{{Address: f.addr[2].Bytes()}}
		case 2:
			connect.BTCPrevHash = f.btc[1]
			connect.Diff.AddedMNNEVM = []wire.NEVMAddressEntry{{Address: f.addr[0].Bytes(), CollateralHeight: 40}}
			connect.Diff.UpdatedMNNEVM = []wire.NEVMAddressUpdateEntry{{
				OldAddress: f.addr[1].Bytes(), NewAddress: f.addr[1].Bytes(), CollateralHeight: 30,
			}}
		}
		block.NevmBlockConnect = connect
		if _, err := f.chain.InsertChain(types.Blocks{block}); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if err := f.chain.TrieDB().Commit(block.Root(), false); err != nil {
				t.Fatal(err)
			}
			if snapshots {
				if err := f.chain.snaps.Cap(block.Root(), 0); err != nil {
					t.Fatal(err)
				}
				if f.chain.snaps.DiskRoot() != block.Root() {
					t.Fatal("snapshot was not durably anchored at block 1")
				}
			}
		}
	}
	return f
}

// Copy before a clean Stop flushes/journals cached state: only these key/value
// entries survive the simulated crash, not the generating chain's trie cache.
func copySyscoinRecoveryDB(t *testing.T, db ethdb.Database) ethdb.Database {
	t.Helper()
	copy := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { copy.Close() })
	it := db.NewIterator(nil, nil)
	defer it.Release()
	for it.Next() {
		if err := copy.Put(it.Key(), it.Value()); err != nil {
			t.Fatal(err)
		}
	}
	if err := it.Error(); err != nil {
		t.Fatal(err)
	}
	return copy
}

func (f *syscoinRecoveryFixture) check(t *testing.T, chain *BlockChain, db ethdb.Database, head uint64) {
	t.Helper()
	want := f.blocks[head-1]
	if chain.CurrentBlock().Hash() != want.Hash() || chain.CurrentHeader().Hash() != want.Hash() ||
		chain.CurrentSnapBlock().Hash() != want.Hash() || rawdb.ReadHeadBlockHash(db) != want.Hash() ||
		rawdb.ReadHeadHeaderHash(db) != want.Hash() || rawdb.ReadHeadFastBlockHash(db) != want.Hash() {
		t.Fatalf("head markers disagree with recovery target %d", head)
	}
	if number, sys, ok := chain.CurrentSyscoinPair(); !ok || number != head || string(sys) != want.NevmBlockConnect.Sysblockhash {
		t.Fatalf("current Core pairing = %d/%x/%t", number, sys, ok)
	}
	for i, block := range f.blocks {
		present := block.NumberU64() <= head
		if (chain.GetCanonicalHash(block.NumberU64()) == block.Hash()) != present ||
			(len(rawdb.ReadSYSHash(db, block.NumberU64())) > 0) != present ||
			(len(chain.ReadSYSHash(block.NumberU64())) > 0) != present ||
			(len(rawdb.ReadDataHash(db, f.da[i])) > 0) != present ||
			(len(chain.ReadDataHash(f.da[i])) > 0) != present ||
			(rawdb.ReadTxLookupEntry(db, block.Transactions()[0].Hash()) != nil) != present {
			t.Errorf("canonical metadata mismatch at block %d for target %d", block.NumberU64(), head)
		}
		lookup, _, err := chain.GetTransactionLookup(block.Transactions()[0].Hash())
		if err != nil || (lookup != nil) != present {
			t.Errorf("transaction cache mismatch at block %d: %v", block.NumberU64(), err)
		}
		if rawdb.ReadBlock(db, block.Hash(), block.NumberU64()) == nil || len(rawdb.ReadRawReceipts(db, block.Hash(), block.NumberU64())) != 1 {
			t.Errorf("replay body/receipts missing at block %d", block.NumberU64())
		}
	}
	wantLast := uint64(1)
	wantAddress := [][]byte{{0, 0, 0, 0}, nil, {0, 0, 0, 10}}
	if head == 3 {
		wantLast = 2
		wantAddress = [][]byte{{0, 0, 0, 40}, {0, 0, 0, 30}, nil}
	}
	if rawdb.ReadBTCCheckpointLastIndex(db) != wantLast || chain.ReadBTCCheckpointLastIndex() != wantLast ||
		chain.BTCCheckpointIndex(f.btc[0]) != 1 || rawdb.ReadBTCCheckpointIndexByBlockNumber(db, 1) != 1 ||
		rawdb.ReadBTCCheckpointIndexByBlockNumber(db, 2) != 0 ||
		(chain.BTCCheckpointIndex(f.btc[1]) == 2) != (head == 3) ||
		(rawdb.ReadBTCCheckpointIndexByHash(db, f.btc[1]) == 2) != (head == 3) ||
		(rawdb.ReadBTCCheckpointIndexByBlockNumber(db, 3) == 2) != (head == 3) ||
		(len(chain.ReadBTCCheckpointHashByIndex(2)) > 0) != (head == 3) {
		t.Errorf("BTC checkpoint metadata disagrees with target %d", head)
	}
	for i, address := range f.addr {
		if got := chain.GetNEVMAddress(address); !bytes.Equal(got, wantAddress[i]) {
			t.Errorf("address %s after target %d = %x, want %x", address, head, got, wantAddress[i])
		}
		if got := rawdb.GetNEVMAddress(db, address); !bytes.Equal(got, wantAddress[i]) {
			t.Errorf("durable address %s = %x, want %x", address, got, wantAddress[i])
		}
	}
}

func (f *syscoinRecoveryFixture) replay(t *testing.T, chain *BlockChain, db ethdb.Database) {
	t.Helper()
	// Core must still supply transient pairing metadata: stored RLP alone is not
	// an authenticated replay input, even when the body and receipts survived.
	bare := rawdb.ReadBlock(db, f.blocks[1].Hash(), 2)
	if _, err := chain.InsertChain(types.Blocks{bare}); err == nil {
		t.Fatal("replay without Core metadata was accepted")
	}
	f.check(t, chain, db, 1)
	if _, err := chain.InsertChain(f.blocks[1:]); err != nil {
		t.Fatalf("authenticated replay: %v", err)
	}
	f.check(t, chain, db, 3)
	if !chain.HasState(f.blocks[2].Root()) {
		t.Fatal("replay did not restore the original final state root")
	}
}

func TestSyscoinCrashRecoveryAndReplay(t *testing.T) {
	for _, scheme := range []string{rawdb.HashScheme, rawdb.PathScheme} {
		for _, snapshots := range []bool{false, true} {
			name := scheme + "/no-snapshots"
			if snapshots {
				name = scheme + "/snapshots"
			}
			t.Run(name, func(t *testing.T) {
				db := rawdb.NewMemoryDatabase()
				t.Cleanup(func() { db.Close() })
				f := newSyscoinRecoveryFixture(t, scheme, snapshots, db)
				f.check(t, f.chain, db, 3)
				crashed := copySyscoinRecoveryDB(t, db)
				f.chain.Stop()
				restarted, err := NewBlockChain(crashed, f.cache, f.genesis, nil, ethash.NewFaker(), vm.Config{}, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer restarted.Stop()
				f.check(t, restarted, crashed, 1)
				f.replay(t, restarted, crashed)
			})
		}
	}
}

func TestSyscoinSetHeadLocalRecovery(t *testing.T) {
	for _, scheme := range []string{rawdb.HashScheme, rawdb.PathScheme} {
		t.Run(scheme, func(t *testing.T) {
			db := rawdb.NewMemoryDatabase()
			t.Cleanup(func() { db.Close() })
			f := newSyscoinRecoveryFixture(t, scheme, false, db)
			f.check(t, f.chain, db, 3) // Populate metadata/transaction caches first.
			if err := f.chain.SetHead(1); err != nil {
				t.Fatal(err)
			}
			f.check(t, f.chain, db, 1)
			f.replay(t, f.chain, db)
		})
	}
}

func TestSyscoinRecoveryMissingUndoDoesNotMutate(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	f := newSyscoinRecoveryFixture(t, rawdb.HashScheme, false, db)
	if err := rawdb.DeleteNEVMAddressUndo(db, 2); err != nil {
		t.Fatal(err)
	}
	if err := f.chain.SetHead(1); err == nil {
		t.Fatal("rewind accepted a missing intermediate address undo record")
	}
	f.check(t, f.chain, db, 3)
	if _, err := rawdb.ReadNEVMAddressUndo(db, 3, f.blocks[2].Hash(), common.BytesToHash([]byte(f.blocks[2].NevmBlockConnect.Sysblockhash))); err != nil {
		t.Fatalf("failed preflight consumed later undo history: %v", err)
	}
	// The same preflight must precede missing-state startup repair, not merely
	// explicit SetHead. A legacy database without coverage must refuse intact.
	crashed := copySyscoinRecoveryDB(t, db)
	restarted, err := NewBlockChain(crashed, f.cache, f.genesis, nil, ethash.NewFaker(), vm.Config{}, nil)
	if err == nil {
		restarted.Stop()
		t.Fatal("startup repair accepted missing address undo history")
	}
	f.check(t, f.chain, crashed, 3)
}

func TestSyscoinRecoveryWrongPairUndoDoesNotMutate(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	f := newSyscoinRecoveryFixture(t, rawdb.HashScheme, false, db)
	if err := rawdb.DeleteNEVMAddressUndo(db, 2); err != nil {
		t.Fatal(err)
	}
	if err := rawdb.WriteNEVMAddressUndo(db, db, 2, common.HexToHash("0xbad"), common.BytesToHash([]byte(f.blocks[1].NevmBlockConnect.Sysblockhash)), nil); err != nil {
		t.Fatal(err)
	}
	if err := f.chain.SetHead(1); err == nil || !strings.Contains(err.Error(), "block pair mismatch") {
		t.Fatalf("rewind with wrong-pair journal: %v", err)
	}
	f.check(t, f.chain, db, 3)
}

func TestSyscoinHeaderOnlyRewindDoesNotMutate(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	f := newSyscoinRecoveryFixture(t, rawdb.HashScheme, false, db)
	update := func(ethdb.KeyValueWriter, *types.Header) (*types.Header, bool) {
		t.Fatal("header-only rewind invoked mutating callback")
		return nil, false
	}
	if err := f.chain.hc.SetHead(1, update, nil); err == nil {
		t.Fatal("direct header-only rewind was accepted")
	}
	if err := f.chain.hc.SetHeadWithTimestamp(f.blocks[0].Time(), update, nil); err == nil {
		t.Fatal("direct timestamp header-only rewind was accepted")
	}
	if err := f.chain.hc.SetHead(3, update, nil); err != nil {
		t.Fatalf("current-height no-op: %v", err)
	}
	f.check(t, f.chain, db, 3)
}

func TestSyscoinRecoveryDAHistoryPreflight(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	f := newSyscoinRecoveryFixture(t, rawdb.HashScheme, false, db)
	// Restore the complete fixture chain before Stop's recent-state flush, which
	// deliberately assumes a full chain rather than the sparse tail below.
	t.Cleanup(func() { f.chain.writeHeadBlock(f.blocks[2]) })
	// Seed only the relevant tail of an aged chain. A retained floor of 2 at
	// Limit+1 is reachable after earlier successful rollbacks; the next rewind
	// needs the already-pruned height 1. No 100k-block generation is necessary.
	header := f.blocks[0].Header()
	header.Number = new(big.Int).SetUint64(rawdb.DataBlockLimit)
	target := types.NewBlockWithHeader(header)
	header = f.blocks[2].Header()
	header.Number = new(big.Int).SetUint64(rawdb.DataBlockLimit + 1)
	header.ParentHash = target.Hash()
	tip := types.NewBlockWithHeader(header)
	for _, block := range []*types.Block{target, tip} {
		rawdb.WriteBlock(db, block)
		rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
		rawdb.WriteSYSHash(db, string(block.Hash().Bytes()), block.NumberU64())
	}
	batch := db.NewBatch()
	f.chain.writeHeadBlockMarkers(batch, tip)
	if err := batch.Write(); err != nil {
		t.Fatal(err)
	}
	f.chain.publishHeadBlock(tip)
	// Match rawdb's versioned index encoding without exporting a test-only API.
	index := make([]byte, 17)
	index[0] = 1
	binary.BigEndian.PutUint64(index[1:9], tip.NumberU64())
	binary.BigEndian.PutUint64(index[9:17], 2)
	if err := db.Put([]byte("datahash-index-state"), index); err != nil {
		t.Fatal(err)
	}
	err := f.chain.SetHead(target.NumberU64())
	if err == nil || !strings.Contains(err.Error(), "data-hash history unavailable") {
		t.Fatalf("DA history-floor rewind: %v", err)
	}
	if f.chain.CurrentBlock().Hash() != tip.Hash() || f.chain.CurrentHeader().Hash() != tip.Hash() ||
		rawdb.ReadHeadBlockHash(db) != tip.Hash() || rawdb.ReadHeadHeaderHash(db) != tip.Hash() ||
		rawdb.ReadHeadFastBlockHash(db) != tip.Hash() || rawdb.ReadCanonicalHash(db, tip.NumberU64()) != tip.Hash() {
		t.Fatal("DA history failure committed lower head markers")
	}
	if got, err := db.Get([]byte("datahash-index-state")); err != nil || !bytes.Equal(got, index) {
		t.Fatalf("DA history failure changed index state: %x, %v", got, err)
	}
}

type syscoinRecoveryAncientDB struct {
	ethdb.Database
	frozen uint64
}

func (db *syscoinRecoveryAncientDB) Ancients() (uint64, error) { return db.frozen, nil }

func TestSyscoinRecoveryFrozenBoundaryDoesNotMutate(t *testing.T) {
	db := &syscoinRecoveryAncientDB{Database: rawdb.NewMemoryDatabase()}
	t.Cleanup(func() { db.Close() })
	f := newSyscoinRecoveryFixture(t, rawdb.HashScheme, false, db)
	db.frozen = 3 // Rewinding to 1 would cross immutable height 2.
	err := f.chain.SetHead(1)
	db.frozen = 0
	if err == nil || !strings.Contains(err.Error(), "ancient history") {
		t.Fatalf("rewind across frozen boundary: %v", err)
	}
	f.check(t, f.chain, db, 3)
}

type syscoinRecoveryFailDB struct {
	ethdb.Database
	fail atomic.Bool
	err  error
}

func (db *syscoinRecoveryFailDB) NewBatch() ethdb.Batch {
	batch := db.Database.NewBatch()
	if db.fail.Load() {
		return &failingBTCCheckpointBatch{Batch: batch, err: db.err}
	}
	return batch
}

func TestSyscoinRecoveryFailedWriteDoesNotPublish(t *testing.T) {
	db := &syscoinRecoveryFailDB{Database: rawdb.NewMemoryDatabase(), err: errors.New("injected recovery batch failure")}
	t.Cleanup(func() { db.Close() })
	f := newSyscoinRecoveryFixture(t, rawdb.HashScheme, false, db)
	f.check(t, f.chain, db, 3)
	f.chain.SetFinalized(f.blocks[2].Header())
	f.chain.SetSafe(f.blocks[2].Header())
	events := make(chan ChainHeadEvent, 1)
	sub := f.chain.SubscribeChainHeadEvent(events)
	defer sub.Unsubscribe()
	db.fail.Store(true)
	err := f.chain.SetHead(1)
	db.fail.Store(false)
	if !errors.Is(err, db.err) {
		t.Fatalf("rewind error = %v, want injected write failure", err)
	}
	f.check(t, f.chain, db, 3)
	if rawdb.ReadFinalizedBlockHash(db) != f.blocks[2].Hash() || f.chain.currentFinalBlock.Load().Hash() != f.blocks[2].Hash() ||
		f.chain.currentSafeBlock.Load().Hash() != f.blocks[2].Hash() {
		t.Fatal("failed rewind published finalized/safe marker changes")
	}
	select {
	case <-events:
		t.Fatal("failed rewind published head event")
	default:
	}
	if err := f.chain.SetHead(1); err != nil {
		t.Fatalf("retry after write failure: %v", err)
	}
	if rawdb.ReadFinalizedBlockHash(db) != (common.Hash{}) || f.chain.currentFinalBlock.Load() != nil || f.chain.currentSafeBlock.Load() != nil {
		t.Fatal("successful rewind retained finalized/safe marker above target")
	}
	select {
	case <-events: // Drain the successful SetHead event before replay.
	default:
		t.Fatal("successful SetHead did not publish a head event")
	}
	sub.Unsubscribe()
	f.check(t, f.chain, db, 1)
	f.replay(t, f.chain, db)
}
