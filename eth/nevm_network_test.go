// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package eth

import (
	"math/big"
	"runtime"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
)

// newNEVMNetworkTestEthereum exercises New's own subscription and the real
// command handler, before listener startup can mask the registration race.
func newNEVMNetworkTestEthereum(t *testing.T, stopBeforeRequest bool) (*Ethereum, *event.TypeMuxSubscription) {
	t.Helper()
	stack, err := node.New(&node.Config{P2P: p2p.Config{
		ListenAddr: "127.0.0.1:0", NoDiscovery: true, NoDial: true, MaxPeers: 1,
	}})
	if err != nil {
		t.Fatal(err)
	}
	genesis := core.DeveloperGenesisBlock(30_000_000, nil)
	chainConfig := *genesis.Config
	chainConfig.SyscoinBlock = big.NewInt(0)
	genesis.Config = &chainConfig
	config := ethconfig.Defaults
	config.Genesis, config.SyncMode = genesis, ethconfig.FullSync
	config.TrieCleanCache, config.TrieDirtyCache, config.SnapshotCache = 16, 16, 0
	config.TxPool.Journal, config.BlobPool.Datadir = "", ""
	config.TxPool.NoLocals = true
	config.LogNoHistory = true
	done := stack.EventMux().Subscribe(downloader.DoneEvent{})
	eth, err := New(stack, &config)
	if err != nil {
		done.Unsubscribe()
		stack.Close()
		t.Fatal(err)
	}
	// Keep activation parked until the test explicitly ages the last block.
	eth.lock.Lock()
	eth.timeLastBlock = time.Now().Add(time.Hour).Unix()
	eth.lock.Unlock()
	eth.handler.peers.SetClosed()
	if stopBeforeRequest {
		eth.closeHandlerOnce.Do(func() { close(eth.closeHandler) })
	}
	// Send in this goroutine immediately after New, without starting a listener
	// or posting from a separate goroutine that could hide the registration race.
	reply := eth.zmqRep.handleNEVMComms("\fstartnetwork")

	// The fixture deliberately stops at constructor/command admission, so clean
	// up constructed components without invoking the unstarted service lifecycle.
	t.Cleanup(func() {
		eth.closeHandlerOnce.Do(func() { close(eth.closeHandler) })
		done.Unsubscribe()
		eth.eventMux.Stop()
		eth.wg.Wait()
		if eth.handler.running.Load() {
			eth.handler.Stop()
		} else {
			eth.Downloader().Terminate()
		}
		eth.p2pServer.Stop()
		eth.discmix.Close()
		eth.dropper.Stop()
		eth.txPool.Close()
		eth.blockchain.Stop()
		eth.engine.Close()
		eth.zmqRep.cancel()
		eth.zmqRep.rep.Close()
		stack.Close()
	})
	if reply != "ack" {
		t.Fatalf("startnetwork reply: %q", reply)
	}
	return eth, done
}

func TestNEVMStartNetworkInitialization(t *testing.T) {
	// Favor the caller continuing from New to command admission, reproducing
	// the old startup window without adding scheduling hooks to production.
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	for _, scenario := range []string{"activate", "duplicate_while_waiting", "stop_while_waiting", "stop_before_request"} {
		t.Run(scenario, func(t *testing.T) {
			eth, done := newNEVMNetworkTestEthereum(t, scenario == "stop_before_request")
			finished := make(chan struct{})
			go func() { eth.wg.Wait(); close(finished) }()
			// Recent block activity must still keep the peer gate and handler closed.
			select {
			case <-done.Chan():
				t.Fatal("network started before block activity settled")
			case <-time.After(150 * time.Millisecond):
			}
			if eth.handler.running.Load() || eth.handler.synced.Load() {
				t.Fatal("networking became active while block activity was pending")
			}
			eth.handler.peers.lock.RLock()
			closed := eth.handler.peers.closed
			eth.handler.peers.lock.RUnlock()
			if !closed {
				t.Fatal("peer gate opened while block activity was pending")
			}

			var duplicate chan string
			if scenario == "duplicate_while_waiting" || scenario == "stop_while_waiting" {
				duplicate = make(chan string, 1)
				go func() { duplicate <- eth.zmqRep.handleNEVMComms("\fstartnetwork") }()
				select {
				case <-duplicate:
					t.Fatal("duplicate was consumed while the one-shot worker was settling")
				case <-time.After(150 * time.Millisecond):
				}
			}
			stopping := scenario == "stop_while_waiting" || scenario == "stop_before_request"
			if stopping {
				eth.closeHandlerOnce.Do(func() { close(eth.closeHandler) })
			} else {
				eth.lock.Lock()
				eth.timeLastBlock = time.Now().Add(-6 * time.Second).Unix()
				eth.lock.Unlock()
				select {
				case ev := <-done.Chan():
					if ev == nil {
						t.Fatal("network completion subscription closed")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("acknowledged startnetwork was lost at initialization")
				}
			}
			select {
			case <-finished:
			case <-time.After(3 * time.Second):
				t.Fatal("network worker did not finish")
			}
			if duplicate != nil {
				select {
				case reply := <-duplicate:
					if reply != "ack" {
						t.Fatalf("duplicate reply: %q", reply)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("worker exit did not release the duplicate command")
				}
			}
			if eth.handler.synced.Load() != !stopping || eth.handler.running.Load() != !stopping {
				t.Fatal("unexpected networking state after worker exit")
			}
			eth.handler.peers.lock.RLock()
			closed = eth.handler.peers.closed
			eth.handler.peers.lock.RUnlock()
			if closed != stopping {
				t.Fatal("unexpected peer gate state after worker exit")
			}
			// A duplicate after completion or cancellation must not create a worker.
			if reply := eth.zmqRep.handleNEVMComms("\fstartnetwork"); reply != "ack" {
				t.Fatalf("completed startnetwork reply: %q", reply)
			}
			select {
			case <-done.Chan():
				t.Fatal("unexpected additional networking completion")
			default:
			}
		})
	}
}
