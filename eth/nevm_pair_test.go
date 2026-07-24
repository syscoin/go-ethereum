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
	"github.com/ethereum/go-ethereum/crypto"
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

// TestKnownNEVMBlockReassociatedAfterRollbackRejectsStaleSYSDependentState ensures
// that after a matched Core disconnect, reconnecting the same NEVM bytes under a
// different SYSBLOCKHASH forces re-execution. E2's state root commits to A1, so
// re-pairing under B1 must fail closed instead of keeping A1 state with B1 metadata.
func TestKnownNEVMBlockReassociatedAfterRollbackRejectsStaleSYSDependentState(t *testing.T) {
	config := *params.AllEthashProtocolChanges
	config.SyscoinBlock = big.NewInt(0)
	config.NexusBlock = big.NewInt(0)

	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("test key: %v", err)
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	probe := common.HexToAddress("0x0000000000000000000000000000000000001000")
	// Runtime: call SYSBLOCKHASH precompile (0x61) with uint64(1), SSTORE result in slot 0.
	probeCode := common.FromHex("6700000000000000016000526020602060086018606161fffffa5060205160005500")
	gspec := &core.Genesis{
		Config:   &config,
		BaseFee:  big.NewInt(params.InitialBaseFee),
		GasLimit: 5_000_000,
		Alloc: types.GenesisAlloc{
			sender: {Balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)},
			probe:  {Code: probeCode},
		},
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
	oldBatch := batchSize
	batchSize = 1
	t.Cleanup(func() { batchSize = oldBatch })

	genDB, first, _ := core.GenerateChainWithGenesis(gspec, engine, 1, nil)
	e1 := first[0]
	sysA1 := bytes.Repeat([]byte{0xa1}, common.HashLength)
	sysA2 := bytes.Repeat([]byte{0xa2}, common.HashLength)
	sysB1 := bytes.Repeat([]byte{0xb1}, common.HashLength)
	sysB2 := bytes.Repeat([]byte{0xb2}, common.HashLength)
	if err := eth.AddBlock(makeNEVMConnect(e1, sysA1)); err != nil {
		t.Fatalf("connect e1/A1: %v", err)
	}

	var sysDependentTx *types.Transaction
	second, _ := core.GenerateChain(&config, e1, engine, genDB, 1, func(_ int, b *core.BlockGen) {
		sysDependentTx = types.MustSignNewTx(key, b.Signer(), &types.LegacyTx{
			Nonce:    b.TxNonce(sender),
			To:       &probe,
			Gas:      100_000,
			GasPrice: new(big.Int).Mul(b.BaseFee(), big.NewInt(2)),
		})
		b.AddTxWithChain(eth.blockchain, sysDependentTx)
	})
	e2 := second[0]
	if err := eth.AddBlock(makeNEVMConnect(e2, sysA2)); err != nil {
		t.Fatalf("connect e2/A2: %v", err)
	}
	stateA, err := eth.blockchain.State()
	if err != nil {
		t.Fatalf("state A: %v", err)
	}
	if got := stateA.GetState(probe, common.Hash{}); got != common.BytesToHash(sysA1) {
		t.Fatalf("probe after first execution=%x want A1=%x", got, sysA1)
	}

	if err := eth.DeleteBlock(makeNEVMDisconnect(sysA2)); err != nil {
		t.Fatalf("disconnect e2/A2: %v", err)
	}
	if err := eth.DeleteBlock(makeNEVMDisconnect(sysA1)); err != nil {
		t.Fatalf("disconnect e1/A1: %v", err)
	}
	if !eth.blockchain.HasBlockAndState(e2.Hash(), e2.NumberU64()) {
		t.Fatal("rollback unexpectedly removed the known E2 block/state")
	}

	// Same Core history after rollback must still be accepted (re-exec under A1).
	if err := eth.AddBlock(makeNEVMConnect(e1, sysA1)); err != nil {
		t.Fatalf("reconnect e1/A1: %v", err)
	}
	if err := eth.AddBlock(makeNEVMConnect(e2, sysA2)); err != nil {
		t.Fatalf("reconnect e2/A2: %v", err)
	}
	if err := eth.DeleteBlock(makeNEVMDisconnect(sysA2)); err != nil {
		t.Fatalf("disconnect e2/A2 (2): %v", err)
	}
	if err := eth.DeleteBlock(makeNEVMDisconnect(sysA1)); err != nil {
		t.Fatalf("disconnect e1/A1 (2): %v", err)
	}

	if err := eth.AddBlock(makeNEVMConnect(e1, sysB1)); err != nil {
		t.Fatalf("reconnect known e1/B1: %v", err)
	}
	expectedB, _ := core.GenerateChain(&config, e1, engine, genDB, 1, func(_ int, b *core.BlockGen) {
		b.AddTxWithChain(eth.blockchain, sysDependentTx)
	})
	if expectedB[0].Root() == e2.Root() {
		t.Fatalf("test contexts did not diverge: A-root=%x B-root=%x", e2.Root(), expectedB[0].Root())
	}
	if err := eth.AddBlock(makeNEVMConnect(e2, sysB2)); err == nil {
		t.Fatal("reconnect known e2/B2 unexpectedly succeeded with stale A1 state root")
	}
	if len(eth.blockConnectBuffer) != 0 {
		t.Fatalf("rejected e2/B2 left %d buffered entries; replacement connects would wedge", len(eth.blockConnectBuffer))
	}
	if eth.blockchain.CurrentBlock().Hash() != e1.Hash() {
		t.Fatalf("tip after rejected e2/B2: got %x want e1 %x", eth.blockchain.CurrentBlock().Hash(), e1.Hash())
	}
	if got := eth.blockchain.ReadSYSHash(1); !bytes.Equal(got, sysB1) {
		t.Fatalf("SYSHash(1) after e1/B1=%x want B1=%x", got, sysB1)
	}
	if got := eth.blockchain.ReadSYSHash(2); len(got) != 0 {
		t.Fatalf("SYSHash(2) should remain unset after rejected e2/B2, got %x", got)
	}

	// Valid B-context successor must still be connectable after the reject.
	e2b := expectedB[0]
	if err := eth.AddBlock(makeNEVMConnect(e2b, sysB2)); err != nil {
		t.Fatalf("connect valid e2b/B2 after stale reject: %v", err)
	}
	if eth.blockchain.CurrentBlock().Hash() != e2b.Hash() {
		t.Fatalf("tip after e2b/B2: got %x want e2b %x", eth.blockchain.CurrentBlock().Hash(), e2b.Hash())
	}
	stateB, err := eth.blockchain.State()
	if err != nil {
		t.Fatalf("state after e2b: %v", err)
	}
	if got := stateB.GetState(probe, common.Hash{}); got != common.BytesToHash(sysB1) {
		t.Fatalf("probe after valid e2b=%x want B1=%x", got, sysB1)
	}
}
