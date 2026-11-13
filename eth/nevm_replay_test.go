// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package eth

import (
	"bytes"
	"math/big"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
)

func nevmReplayDatabaseSnapshot(t *testing.T, eth *Ethereum) map[string]string {
	t.Helper()
	entries := make(map[string]string)
	it := eth.ChainDb().NewIterator(nil, nil)
	defer it.Release()
	for it.Next() {
		entries[string(it.Key())] = string(it.Value())
	}
	if err := it.Error(); err != nil {
		t.Fatal(err)
	}
	return entries
}

func assertNEVMReplayUnchanged(t *testing.T, eth *Ethereum, head common.Hash, lastBlock int64, before map[string]string) {
	t.Helper()
	if eth.blockchain.CurrentBlock().Hash() != head {
		t.Fatal("replay changed the chain head/state root")
	}
	if len(eth.blockConnectBuffer) != 0 || eth.timeLastBlock != lastBlock {
		t.Fatal("replay changed the import buffer or last-block timestamp")
	}
	if after := nevmReplayDatabaseSnapshot(t, eth); !reflect.DeepEqual(before, after) {
		t.Fatal("replay changed the persisted chain or auxiliary metadata")
	}
}

func TestCanonicalNEVMReplayAfterSixBlockCoreLag(t *testing.T) {
	eth, gspec, engine := newNEVMPairTestEthereum(t, true)
	_, blocks, _ := core.GenerateChainWithGenesis(gspec, engine, 8, nil)
	pairs := make([][]byte, 7)
	for i, block := range blocks[:7] {
		pairs[i] = bytes.Repeat([]byte{byte(i + 1)}, common.HashLength)
		connect := makeNEVMConnect(block, pairs[i])
		vh := common.BytesToHash([]byte{byte(i + 11)})
		connect.VersionHashes = []*common.Hash{&vh}
		connect.BTCPrevHash = common.BytesToHash([]byte{byte(i + 21)})
		if err := eth.AddBlock(connect); err != nil {
			t.Fatalf("initial connect %d: %v", i+1, err)
		}
	}
	head, lastBlock := eth.blockchain.CurrentBlock().Hash(), eth.timeLastBlock
	before := nevmReplayDatabaseSnapshot(t, eth)
	// Geth persisted height 7 while Core only persisted height 1. Its six
	// reconnects must acknowledge the existing pairs without executing again.
	for i := 1; i < 7; i++ {
		replay := makeNEVMConnect(blocks[i], pairs[i])
		// Supplied sidecars must not replace the already committed metadata.
		otherVH := common.HexToHash("0xffff")
		replay.VersionHashes = []*common.Hash{&otherVH}
		replay.BTCPrevHash = common.HexToHash("0xeeee")
		if err := eth.AddBlock(replay); err != nil {
			t.Fatalf("Core catch-up replay %d: %v", i+1, err)
		}
		assertNEVMReplayUnchanged(t, eth, head, lastBlock, before)
	}
	// After catching up, the next block still follows ordinary import and
	// writes its own pairing. Replay handling must not stall forward progress.
	nextPair := bytes.Repeat([]byte{8}, common.HashLength)
	if err := eth.AddBlock(makeNEVMConnect(blocks[7], nextPair)); err != nil {
		t.Fatalf("new block after catch-up: %v", err)
	}
	if eth.blockchain.CurrentBlock().Hash() != blocks[7].Hash() || !bytes.Equal(eth.blockchain.ReadSYSHash(8), nextPair) {
		t.Fatal("new block did not become the paired canonical head")
	}
}

func TestCanonicalNEVMReplayRejectsMismatches(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Ethereum, *types.Block, []byte) *types.NEVMBlockConnect
	}{
		{"different Core hash", func(_ *Ethereum, block *types.Block, _ []byte) *types.NEVMBlockConnect {
			return makeNEVMConnect(block, bytes.Repeat([]byte{0xff}, common.HashLength))
		}},
		{"zero Core hash", func(_ *Ethereum, block *types.Block, _ []byte) *types.NEVMBlockConnect {
			return makeNEVMConnect(block, make([]byte, common.HashLength))
		}},
		{"oversized Core hash", func(_ *Ethereum, block *types.Block, pair []byte) *types.NEVMBlockConnect {
			return makeNEVMConnect(block, append([]byte{0xff}, pair...))
		}},
		{"unknown block", func(_ *Ethereum, block *types.Block, pair []byte) *types.NEVMBlockConnect {
			header := block.Header()
			header.Extra = []byte("unknown branch")
			return makeNEVMConnect(types.NewBlockWithHeader(header).WithBody(*block.Body()), pair)
		}},
		{"known noncanonical block", func(eth *Ethereum, block *types.Block, pair []byte) *types.NEVMBlockConnect {
			header := block.Header()
			header.Extra = []byte("stored side branch")
			other := types.NewBlockWithHeader(header).WithBody(*block.Body())
			rawdb.WriteBlock(eth.ChainDb(), other)
			return makeNEVMConnect(other, pair)
		}},
		{"same header different body", func(_ *Ethereum, block *types.Block, pair []byte) *types.NEVMBlockConnect {
			body := *block.Body()
			body.Transactions = []*types.Transaction{types.NewTransaction(0, common.Address{}, big.NewInt(1), 21000, big.NewInt(1), nil)}
			return makeNEVMConnect(block.WithBody(body), pair)
		}},
		{"missing stored pairing", func(eth *Ethereum, block *types.Block, pair []byte) *types.NEVMBlockConnect {
			eth.blockchain.ReadSYSHash(block.NumberU64()) // Warm cache must not mask missing persisted metadata.
			rawdb.DeleteSYSHash(eth.ChainDb(), block.NumberU64())
			return makeNEVMConnect(block, pair)
		}},
		{"zero stored pairing", func(eth *Ethereum, block *types.Block, pair []byte) *types.NEVMBlockConnect {
			rawdb.WriteSYSHash(eth.ChainDb(), string(make([]byte, common.HashLength)), block.NumberU64())
			return makeNEVMConnect(block, pair)
		}},
		{"missing stored body", func(eth *Ethereum, block *types.Block, pair []byte) *types.NEVMBlockConnect {
			rawdb.DeleteBody(eth.ChainDb(), block.Hash(), block.NumberU64())
			return makeNEVMConnect(block, pair)
		}},
		{"inconsistent canonical head", func(eth *Ethereum, block *types.Block, pair []byte) *types.NEVMBlockConnect {
			rawdb.WriteCanonicalHash(eth.ChainDb(), common.HexToHash("0xbad"), eth.blockchain.CurrentBlock().Number.Uint64())
			return makeNEVMConnect(block, pair)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			eth, gspec, engine := newNEVMPairTestEthereum(t, true)
			_, blocks, _ := core.GenerateChainWithGenesis(gspec, engine, 3, nil)
			pair := bytes.Repeat([]byte{0x11}, common.HashLength)
			for _, block := range blocks {
				if err := eth.AddBlock(makeNEVMConnect(block, pair)); err != nil {
					t.Fatal(err)
				}
			}
			// Restore deliberate canonical-index corruption before the fixture's
			// Stop cleanup, including when an assertion below fails.
			originalHead := eth.blockchain.CurrentBlock()
			defer rawdb.WriteCanonicalHash(eth.ChainDb(), originalHead.Hash(), originalHead.Number.Uint64())
			replay := tc.change(eth, blocks[0], pair)
			head, lastBlock := eth.blockchain.CurrentBlock().Hash(), eth.timeLastBlock
			before := nevmReplayDatabaseSnapshot(t, eth)
			if err := eth.AddBlock(replay); err == nil {
				t.Fatal("invalid historical replay was acknowledged")
			}
			assertNEVMReplayUnchanged(t, eth, head, lastBlock, before)
		})
	}
}
