// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package core

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/syscoin/syscoinwire/syscoin/wire"
)

func TestDataHashIndexBlockCommitAndRestart(t *testing.T) {
	config := *params.AllEthashProtocolChanges
	config.SyscoinBlock = big.NewInt(0)
	genesis := &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: &config}
	engine := ethash.NewFaker()
	db, blocks, _ := GenerateChainWithGenesis(genesis, engine, 1, nil)
	t.Cleanup(func() { db.Close() })

	dataHash := common.HexToHash("0x1234")
	block := blocks[0]
	block.NevmBlockConnect = &types.NEVMBlockConnect{
		Block:         block,
		Sysblockhash:  string(bytes.Repeat([]byte{0x42}, common.HashLength)),
		VersionHashes: []*common.Hash{&dataHash},
		Diff:          new(wire.NEVMAddressDiff),
	}
	chain, err := NewBlockChain(db, DefaultCacheConfigWithScheme(rawdb.HashScheme), genesis, nil, engine, vm.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.InsertChain([]*types.Block{block}); err != nil {
		chain.Stop()
		t.Fatal(err)
	}
	if got := chain.ReadDataHash(dataHash); !bytes.Equal(got, dataHash.Bytes()) {
		chain.Stop()
		t.Fatalf("membership after block commit = %x", got)
	}
	chain.Stop()

	restarted, err := NewBlockChain(db, DefaultCacheConfigWithScheme(rawdb.HashScheme), genesis, nil, engine, vm.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Stop()
	if got := restarted.ReadDataHash(dataHash); !bytes.Equal(got, dataHash.Bytes()) {
		t.Fatalf("membership after restart = %x", got)
	}
	if got := rawdb.ReadRawDataHashes(db, 1); len(got) != 1 || *got[0] != dataHash {
		t.Fatalf("canonical block journal after restart = %v", got)
	}
}

func TestSyscoinBlockRejectsMissingNEVMConnectMetadata(t *testing.T) {
	config := *params.AllEthashProtocolChanges
	config.SyscoinBlock = big.NewInt(0)
	genesis := &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: &config}
	engine := ethash.NewFaker()
	db, blocks, _ := GenerateChainWithGenesis(genesis, engine, 1, nil)
	t.Cleanup(func() { db.Close() })
	chain, err := NewBlockChain(db, DefaultCacheConfigWithScheme(rawdb.HashScheme), genesis, nil, engine, vm.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()

	if _, err := chain.InsertChain(blocks); err == nil {
		t.Fatal("Syscoin block without Core NEVM connect metadata was accepted")
	}
	if got := chain.CurrentBlock().Number.Uint64(); got != 0 {
		t.Fatalf("head advanced to %d after rejected unpaired block", got)
	}

	// The known-block path used to move the canonical head before discovering
	// that transient Core metadata was missing. It must reject first as well.
	if err := chain.writeBlockWithoutState(blocks[0]); err != nil {
		t.Fatal(err)
	}
	if err := chain.writeKnownBlock(blocks[0]); err == nil {
		t.Fatal("known Syscoin block without Core metadata was accepted")
	}
	if got := chain.CurrentBlock().Number.Uint64(); got != 0 {
		t.Fatalf("known-block rejection advanced head to %d", got)
	}

	// Supplying the missing transient metadata still permits normal recovery of
	// the stored block and proves that the rejected attempts left the index at 0.
	dataHash := common.HexToHash("0x5678")
	blocks[0].NevmBlockConnect = &types.NEVMBlockConnect{
		Block:         blocks[0],
		Sysblockhash:  string(bytes.Repeat([]byte{0x43}, common.HashLength)),
		VersionHashes: []*common.Hash{&dataHash},
		Diff:          new(wire.NEVMAddressDiff),
	}
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("paired known-block recovery failed: %v", err)
	}
	if got := chain.ReadDataHash(dataHash); !bytes.Equal(got, dataHash.Bytes()) {
		t.Fatalf("recovered block membership = %x", got)
	}
}
