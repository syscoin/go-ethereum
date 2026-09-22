// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package miner

import (
	"bytes"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/syscoin/syscoinwire/syscoin/wire"
)

// SYSCOIN: pending-work fixtures simulate the storage barrier explicitly;
// they do not assert persistence across a storage restart.
type syscoinPendingTestDB struct{ ethdb.Database }

func (*syscoinPendingTestDB) SyncKeyValue() error { return nil }

// Pause only the miner's engine after assembly. Canonical import uses the
// underlying engine and must be able to publish while pending work is paused.
type syscoinPendingEngine struct {
	consensus.Engine
	assembled chan struct{}
	resume    chan struct{}
	once      sync.Once
}

func (engine *syscoinPendingEngine) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, statedb *state.StateDB, body *types.Body, receipts []*types.Receipt) (*types.Block, error) {
	block, err := engine.Engine.FinalizeAndAssemble(chain, header, statedb, body, receipts)
	engine.once.Do(func() {
		close(engine.assembled)
		<-engine.resume
	})
	return block, err
}

func TestSyscoinPendingBuildAcrossMetadataPublication(t *testing.T) {
	config := *params.AllEthashProtocolChanges
	config.SyscoinBlock, config.NexusBlock = big.NewInt(0), big.NewInt(0)
	db, engine := &syscoinPendingTestDB{Database: rawdb.NewMemoryDatabase()}, ethash.NewFaker()
	backend := newTestWorkerBackend(t, &config, engine, db, 0)
	t.Cleanup(func() { backend.txPool.Close(); backend.chain.Stop(); db.Close() })
	genDB, blocks, _ := core.GenerateChainWithGenesis(backend.genesis, engine, 1, nil)
	t.Cleanup(func() { genDB.Close() })
	block := blocks[0]
	block.NevmBlockConnect = &types.NEVMBlockConnect{
		Block: block, Sysblockhash: string(bytes.Repeat([]byte{0x11}, common.HashLength)),
		Diff: new(wire.NEVMAddressDiff),
	}
	if _, err := backend.chain.InsertChain(blocks); err != nil {
		t.Fatal(err)
	}
	gate := &syscoinPendingEngine{Engine: engine, assembled: make(chan struct{}), resume: make(chan struct{})}
	miner := New(backend, testConfig, gate)
	var release sync.Once
	defer release.Do(func() { close(gate.resume) })
	result := make(chan *types.Block, 1)
	go func() { pending, _, _ := miner.Pending(); result <- pending }()
	select {
	case <-gate.assembled:
	case <-time.After(5 * time.Second):
		t.Fatal("pending build did not reach assembly")
	}
	updated := make(chan error, 1)
	go func() {
		if err := backend.chain.SetHead(0); err != nil {
			updated <- err
			return
		}
		block.NevmBlockConnect = &types.NEVMBlockConnect{
			Block: block, Sysblockhash: string(bytes.Repeat([]byte{0x22}, common.HashLength)),
			Diff: new(wire.NEVMAddressDiff),
		}
		_, err := backend.chain.InsertChain(blocks)
		updated <- err
	}()
	select {
	case err := <-updated:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pending build prevented canonical publication")
	}
	if backend.chain.CurrentBlock().Hash() != block.Hash() || string(backend.chain.ReadSYSHash(1)) != block.NevmBlockConnect.Sysblockhash {
		t.Fatal("fixture did not reconnect the same NEVM parent with a new SYS pair")
	}
	release.Do(func() { close(gate.resume) })
	select {
	case pending := <-result:
		if pending != nil {
			t.Fatal("pending work spanning metadata publication was returned")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pending build did not finish after publication")
	}
	if cached := miner.pending.resolve(block.Hash()); cached != nil {
		t.Fatal("pending work spanning metadata publication was cached")
	}
	rebuilt, _, _ := miner.Pending()
	if rebuilt == nil || rebuilt.ParentHash() != block.Hash() {
		t.Fatal("pending retry did not rebuild on the reconnected parent")
	}
	if reused, _, _ := miner.Pending(); reused != rebuilt {
		t.Fatal("stable pending retry did not reuse the rebuilt result")
	}
}
