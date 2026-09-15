// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package miner

import (
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// StateDB.Copy opens another reader even on a pending cache hit. Gate that
// existing database interface separately from construction to test both users.
type pendingShutdownStateDatabase struct {
	state.Database
	armed           atomic.Bool
	entered, resume chan struct{}
}

func (db *pendingShutdownStateDatabase) Reader(root common.Hash) (state.Reader, error) {
	if db.armed.CompareAndSwap(true, false) {
		close(db.entered)
		<-db.resume
	}
	return db.Database.Reader(root)
}

func TestSyscoinPendingShutdownDrainsAndRejects(t *testing.T) {
	for _, phase := range []string{"assembly", "cached_state_copy"} {
		t.Run(phase, func(t *testing.T) {
			config := *params.AllEthashProtocolChanges
			config.SyscoinBlock, config.NexusBlock = big.NewInt(0), big.NewInt(0)
			db, engine := rawdb.NewMemoryDatabase(), ethash.NewFaker()
			backend := newTestWorkerBackend(t, &config, engine, db, 0)
			t.Cleanup(func() { backend.txPool.Close(); backend.chain.Stop(); db.Close() })
			miner := New(backend, testConfig, engine)
			entered, resume := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(resume) }) }
			defer release()
			if phase == "assembly" {
				miner.engine = &syscoinPendingEngine{Engine: engine, assembled: entered, resume: resume}
			} else {
				block, _, copied := miner.Pending()
				if block == nil || copied == nil {
					t.Fatal("pending positive control failed")
				}
				if reused, _, nextCopy := miner.Pending(); reused != block || nextCopy == nil || nextCopy == copied {
					t.Fatal("stable pending result did not reuse the block and copy its state")
				}
				// Commit the independent returned copy so the same valid pending
				// state can be reopened through the gated database interface.
				root, err := copied.Commit(block.NumberU64(), true, false)
				if err != nil || root != block.Root() {
					t.Fatalf("pending state commit: root=%s want=%s error=%v", root, block.Root(), err)
				}
				gated := &pendingShutdownStateDatabase{Database: copied.Database(), entered: entered, resume: resume}
				cachedState, err := state.New(root, gated)
				if err != nil {
					t.Fatal(err)
				}
				miner.pending.result.stateDB = cachedState
				gated.armed.Store(true)
			}
			type response struct {
				block *types.Block
				state *state.StateDB
			}
			callPending := func(results chan<- response) {
				block, _, state := miner.Pending()
				results <- response{block, state}
			}
			active := make(chan response, 1)
			go callPending(active)
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("pending call did not reach its resource access")
			}
			stopped := make(chan struct{}, 2)
			for i := 0; i < cap(stopped); i++ {
				go func() { miner.StopPending(); stopped <- struct{}{} }()
			}
			deadline := time.After(5 * time.Second)
			for !miner.pendingStopped.Load() {
				select {
				case <-deadline:
					t.Fatal("shutdown did not close pending admission")
				case <-time.After(time.Millisecond):
				}
			}
			queued := make(chan response, 4)
			for i := 0; i < cap(queued); i++ {
				go callPending(queued)
			}
			select {
			case <-stopped:
				t.Fatal("shutdown returned during pending resource access")
			case <-time.After(25 * time.Millisecond):
			}
			release()
			select {
			case got := <-active:
				if got.block == nil || got.state == nil {
					t.Fatal("already admitted pending call failed to finish")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("admitted pending call did not finish")
			}
			for i := 0; i < cap(stopped); i++ {
				select {
				case <-stopped:
				case <-time.After(5 * time.Second):
					t.Fatal("concurrent shutdown did not finish")
				}
			}
			for i := 0; i < cap(queued); i++ {
				select {
				case got := <-queued:
					if got.block != nil || got.state != nil {
						t.Fatal("pending call entered after shutdown admission closed")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("queued pending call did not return")
				}
			}
			miner.StopPending()
			if block, receipts, state := miner.Pending(); block != nil || receipts != nil || state != nil {
				t.Fatal("stopped miner returned a cached pending result")
			}
		})
	}
}
