// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package eth

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/syscoin/syscoinwire/syscoin/wire"
)

func newNEVMPairTestEthereum(t *testing.T, flushEveryBlock bool) (*Ethereum, *core.Genesis, *ethash.Ethash) {
	t.Helper()
	gspec := &core.Genesis{
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.AllEthashProtocolChanges,
	}
	engine := ethash.NewFaker()
	db := rawdb.NewMemoryDatabase()
	chain, err := core.NewBlockChain(db, core.DefaultCacheConfigWithScheme(rawdb.HashScheme), gspec, nil, engine, vm.Config{}, nil)
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}
	t.Cleanup(func() { chain.Stop() })

	eth := &Ethereum{
		blockchain:         chain,
		chainDb:            db,
		engine:             engine,
		blockConnectBuffer: make([]*types.NEVMBlockConnect, 0, 8),
		handler:            &handler{peers: &peerSet{closed: true}},
	}
	if flushEveryBlock {
		oldBatch := batchSize
		batchSize = 1
		t.Cleanup(func() { batchSize = oldBatch })
	} else {
		// Keep peers.closed so AddBlock buffers until batchSize.
		oldBatch := batchSize
		batchSize = 8
		t.Cleanup(func() { batchSize = oldBatch })
	}
	return eth, gspec, engine
}

func makeNEVMConnect(block *types.Block, sysHash []byte) *types.NEVMBlockConnect {
	return &types.NEVMBlockConnect{
		Sysblockhash:  string(sysHash),
		Block:         block,
		VersionHashes: []*common.Hash{},
		Diff:          &wire.NEVMAddressDiff{},
	}
}

func makeNEVMDisconnect(sysHash []byte) *types.NEVMBlockDisconnect {
	return &types.NEVMBlockDisconnect{
		Sysblockhash: string(sysHash),
		Diff:         &wire.NEVMAddressDiff{},
	}
}

// TestDuplicateNEVMConnectRejectsUnpairedReplay ensures a second Core pairing of an
// already-canonical NEVM block is rejected, and a mismatched disconnect does not
// rewind the real tip (invalidateblock-style unpaired disconnect).
func TestDuplicateNEVMConnectRejectsUnpairedReplay(t *testing.T) {
	eth, gspec, engine := newNEVMPairTestEthereum(t, true)

	_, blocks, _ := core.GenerateChainWithGenesis(gspec, engine, 1, nil)
	e1 := blocks[0]
	sysB1 := bytes.Repeat([]byte{0xb1}, 32)
	sysB2 := bytes.Repeat([]byte{0xb2}, 32)

	if err := eth.AddBlock(makeNEVMConnect(e1, sysB1)); err != nil {
		t.Fatalf("first connect: %v", err)
	}
	if eth.blockchain.CurrentBlock().Hash() != e1.Hash() {
		t.Fatalf("tip after first connect: got %x want %x", eth.blockchain.CurrentBlock().Hash(), e1.Hash())
	}
	if got := eth.blockchain.ReadSYSHash(1); !bytes.Equal(got, sysB1) {
		t.Fatalf("SYSHash(1)=%x want %x", got, sysB1)
	}

	// Same NEVM block, different Core pairing — must not be a successful no-op.
	if err := eth.AddBlock(makeNEVMConnect(e1, sysB2)); err == nil {
		t.Fatal("duplicate NEVM connect with different Syscoin hash unexpectedly succeeded")
	}
	if eth.blockchain.CurrentBlock().Hash() != e1.Hash() {
		t.Fatalf("tip moved after rejected duplicate connect")
	}
	if got := eth.blockchain.ReadSYSHash(1); !bytes.Equal(got, sysB1) {
		t.Fatalf("SYSHash changed after rejected duplicate: %x", got)
	}

	// Disconnect for the unpaired Core hash must fail closed (no rewind).
	if err := eth.DeleteBlock(makeNEVMDisconnect(sysB2)); err == nil {
		t.Fatal("unpaired disconnect unexpectedly succeeded")
	}
	if eth.blockchain.CurrentBlock().Hash() != e1.Hash() {
		t.Fatalf("tip rewound by unpaired disconnect: got %x", eth.blockchain.CurrentBlock().Hash())
	}
	if got := eth.blockchain.ReadSYSHash(1); !bytes.Equal(got, sysB1) {
		t.Fatalf("SYSHash cleared by unpaired disconnect: %x", got)
	}

	// Matched disconnect still rewinds the real tip.
	if err := eth.DeleteBlock(makeNEVMDisconnect(sysB1)); err != nil {
		t.Fatalf("matched disconnect: %v", err)
	}
	if eth.blockchain.CurrentBlock().Number.Uint64() != 0 {
		t.Fatalf("tip after matched disconnect: %d", eth.blockchain.CurrentBlock().Number.Uint64())
	}
	if got := eth.blockchain.ReadSYSHash(1); len(got) != 0 {
		t.Fatalf("SYSHash(1) left after matched disconnect: %x", got)
	}
}

func TestExactNEVMPairRetryAllowed(t *testing.T) {
	eth, gspec, engine := newNEVMPairTestEthereum(t, true)

	_, blocks, _ := core.GenerateChainWithGenesis(gspec, engine, 1, nil)
	e1 := blocks[0]
	sysB1 := bytes.Repeat([]byte{0x11}, 32)

	if err := eth.AddBlock(makeNEVMConnect(e1, sysB1)); err != nil {
		t.Fatalf("first connect: %v", err)
	}
	if err := eth.AddBlock(makeNEVMConnect(e1, sysB1)); err != nil {
		t.Fatalf("exact pair retry: %v", err)
	}
	if eth.blockchain.CurrentBlock().Hash() != e1.Hash() {
		t.Fatalf("tip changed on exact retry")
	}
}

func TestReplayOlderCanonicalNEVMRejected(t *testing.T) {
	eth, gspec, engine := newNEVMPairTestEthereum(t, true)

	_, blocks, _ := core.GenerateChainWithGenesis(gspec, engine, 2, nil)
	e1, e2 := blocks[0], blocks[1]
	sysB1 := bytes.Repeat([]byte{0xc1}, 32)
	sysB2 := bytes.Repeat([]byte{0xc2}, 32)
	sysBx := bytes.Repeat([]byte{0xcc}, 32)

	if err := eth.AddBlock(makeNEVMConnect(e1, sysB1)); err != nil {
		t.Fatalf("connect e1: %v", err)
	}
	if err := eth.AddBlock(makeNEVMConnect(e2, sysB2)); err != nil {
		t.Fatalf("connect e2: %v", err)
	}
	if eth.blockchain.CurrentBlock().Hash() != e2.Hash() {
		t.Fatalf("tip want e2")
	}

	if err := eth.AddBlock(makeNEVMConnect(e1, sysBx)); err == nil {
		t.Fatal("replay of older canonical e1 unexpectedly succeeded")
	}
	if eth.blockchain.CurrentBlock().Hash() != e2.Hash() {
		t.Fatalf("tip moved after older replay")
	}
	if got := eth.blockchain.ReadSYSHash(1); !bytes.Equal(got, sysB1) {
		t.Fatalf("SYSHash(1) changed: %x", got)
	}
	if got := eth.blockchain.ReadSYSHash(2); !bytes.Equal(got, sysB2) {
		t.Fatalf("SYSHash(2) changed: %x", got)
	}
}

func TestBufferedPairDifferentSysHashRejected(t *testing.T) {
	eth, gspec, engine := newNEVMPairTestEthereum(t, false)

	_, blocks, _ := core.GenerateChainWithGenesis(gspec, engine, 1, nil)
	e1 := blocks[0]
	sysB1 := bytes.Repeat([]byte{0xd1}, 32)
	sysB2 := bytes.Repeat([]byte{0xd2}, 32)

	if err := eth.AddBlock(makeNEVMConnect(e1, sysB1)); err != nil {
		t.Fatalf("buffer e1/b1: %v", err)
	}
	if len(eth.blockConnectBuffer) != 1 {
		t.Fatalf("expected 1 buffered block, got %d", len(eth.blockConnectBuffer))
	}
	if eth.blockchain.CurrentBlock().Number.Uint64() != 0 {
		t.Fatalf("tip should still be genesis while buffered")
	}

	if err := eth.AddBlock(makeNEVMConnect(e1, sysB2)); err == nil {
		t.Fatal("buffered e1/b2 retry unexpectedly succeeded")
	}
	if len(eth.blockConnectBuffer) != 1 {
		t.Fatalf("buffer changed after rejected retry: %d", len(eth.blockConnectBuffer))
	}
	gotSys := []byte(eth.blockConnectBuffer[0].Sysblockhash)
	if !bytes.Equal(gotSys, sysB1) {
		t.Fatalf("buffered SYSHash changed: %x", gotSys)
	}
}

func TestPersistedPairZeroSysHashRetryRejected(t *testing.T) {
	eth, gspec, engine := newNEVMPairTestEthereum(t, true)

	_, blocks, _ := core.GenerateChainWithGenesis(gspec, engine, 1, nil)
	e1 := blocks[0]
	sysB1 := bytes.Repeat([]byte{0xe1}, 32)

	if err := eth.AddBlock(makeNEVMConnect(e1, sysB1)); err != nil {
		t.Fatalf("connect e1: %v", err)
	}
	if err := eth.AddBlock(makeNEVMConnect(e1, nil)); err == nil {
		t.Fatal("exact-height retry with zero SYS hash unexpectedly succeeded")
	}
	if eth.blockchain.CurrentBlock().Hash() != e1.Hash() {
		t.Fatalf("tip moved after zero-SYS retry")
	}
	if got := eth.blockchain.ReadSYSHash(1); !bytes.Equal(got, sysB1) {
		t.Fatalf("SYSHash changed: %x", got)
	}
}

func TestUnpairedTipZeroSysHashRetryRejected(t *testing.T) {
	eth, gspec, engine := newNEVMPairTestEthereum(t, true)

	_, blocks, _ := core.GenerateChainWithGenesis(gspec, engine, 1, nil)
	e1 := blocks[0]
	if _, err := eth.blockchain.InsertChain([]*types.Block{e1}); err != nil {
		t.Fatalf("insert unpaired tip: %v", err)
	}
	if got := eth.blockchain.ReadSYSHash(1); len(got) != 0 {
		t.Fatalf("expected empty SYSHash(1), got %x", got)
	}

	// Same NEVM tip with zero SYS must not succeed as an exact-pair retry.
	if err := eth.AddBlock(makeNEVMConnect(e1, nil)); err == nil {
		t.Fatal("zero-SYS retry on unpaired tip unexpectedly succeeded")
	}
	if eth.blockchain.CurrentBlock().Hash() != e1.Hash() {
		t.Fatalf("tip moved after zero-SYS unpaired retry")
	}
}

func TestDisconnectZeroSysHashRejected(t *testing.T) {
	eth, gspec, engine := newNEVMPairTestEthereum(t, true)

	_, blocks, _ := core.GenerateChainWithGenesis(gspec, engine, 1, nil)
	e1 := blocks[0]
	// Insert without NevmBlockConnect so tip has no SYSHash pairing.
	if _, err := eth.blockchain.InsertChain([]*types.Block{e1}); err != nil {
		t.Fatalf("insert unpaired tip: %v", err)
	}
	if eth.blockchain.CurrentBlock().Hash() != e1.Hash() {
		t.Fatalf("tip want e1")
	}
	if got := eth.blockchain.ReadSYSHash(1); len(got) != 0 {
		t.Fatalf("expected empty SYSHash(1), got %x", got)
	}

	// Empty disconnect must not rewind an unpaired tip (zero == zero was the hole).
	if err := eth.DeleteBlock(makeNEVMDisconnect(nil)); err == nil {
		t.Fatal("zero SYS disconnect on unpaired tip unexpectedly succeeded")
	}
	if eth.blockchain.CurrentBlock().Hash() != e1.Hash() {
		t.Fatalf("tip rewound by zero disconnect: got %x", eth.blockchain.CurrentBlock().Hash())
	}
}
