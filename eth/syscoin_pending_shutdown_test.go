// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package eth

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/rpc"
)

func newSyscoinPendingRPCClient(t *testing.T, eth *Ethereum, transport string) (*rpc.Client, func()) {
	t.Helper()
	if transport == "inproc" {
		client := eth.stack.Attach()
		t.Cleanup(client.Close)
		return client, func() {} // Node.Close owns this endpoint.
	}
	server := rpc.NewServer()
	if err := server.RegisterName("eth", ethapi.NewBlockChainAPI(&EthAPIBackend{eth: eth})); err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewServer(server.WebsocketHandler([]string{"*"}))
	t.Cleanup(func() { server.Stop(); endpoint.Close() })
	client, err := rpc.DialWebsocket(context.Background(), "ws"+strings.TrimPrefix(endpoint.URL, "http"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client, server.Stop
}

// Both persistent transports wake the caller without joining the pending
// builder dispatched by the server callback. Ethereum must join the miner
// before closing its execution dependencies.
func TestSyscoinPendingRPCShutdownWaitsForBuilder(t *testing.T) {
	for _, transport := range []string{"inproc", "websocket"} {
		t.Run(transport, func(t *testing.T) { testSyscoinPendingRPCShutdown(t, transport) })
	}
}

func testSyscoinPendingRPCShutdown(t *testing.T, transport string) {
	var engine *nevmListenerEngine
	var db *nevmListenerDatabase
	eth, stack, _, _ := newNEVMDiscoveryLifecycleEthereum(t, func(eth *Ethereum) {
		engine = &nevmListenerEngine{Engine: eth.engine, entered: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{}), closed: make(chan struct{})}
		db = &nevmListenerDatabase{Database: eth.chainDb, closed: make(chan struct{})}
		eth.engine, eth.chainDb = engine, db
		eth.miner = miner.New(eth, eth.config.Miner, engine)
	})
	var once sync.Once
	release := func() { once.Do(func() { close(engine.release) }) }
	t.Cleanup(release)
	client, stopEndpoint := newSyscoinPendingRPCClient(t, eth, transport)
	engine.armed.Store(true)
	rpcDone := make(chan error, 1)
	go func() {
		var block map[string]interface{}
		rpcDone <- client.CallContext(context.Background(), &block, "eth_getBlockByNumber", "pending", false)
	}()
	waitNEVMListenerSignal(t, engine.entered, "pending RPC did not enter block assembly")
	stopped := make(chan error, 1)
	// Match Node.Close's endpoint-before-lifecycle shutdown order for the
	// separate WebSocket test endpoint; Node owns the in-process endpoint.
	go func() { stopEndpoint(); stopped <- stack.Close() }()
	waitNEVMListenerSignal(t, eth.closeHandler, "independent node shutdown did not start")
	select {
	case err := <-rpcDone:
		if err == nil {
			t.Error("RPC succeeded while its pending builder was still blocked")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("node shutdown did not close the persistent RPC connection")
	}
	// A broken shutdown closes the engine/database with assembly still paused.
	// The existing engine wrapper rescues that baseline on release, so the test
	// reports the ordering error without continuing against closed chain state.
	overtaken := false
	select {
	case <-engine.closed:
		t.Error("consensus engine closed while a dispatched pending RPC was still building")
		overtaken = true
	case <-db.closed:
		t.Error("chain database closed while a dispatched pending RPC was still building")
		overtaken = true
	case err := <-stopped:
		t.Fatalf("shutdown returned before pending assembly completed: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	release()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not join the released pending builder")
	}
	waitNEVMListenerSignal(t, engine.finished, "pending assembly remained active after shutdown")
	if !overtaken {
		calls := engine.calls.Load()
		block, receipts, state := eth.miner.Pending()
		if block != nil || receipts != nil || state != nil {
			t.Error("pending work remained available after shutdown")
		}
		if engine.calls.Load() != calls {
			t.Error("pending request entered assembly after miner shutdown")
		}
	}
}

func TestSyscoinPendingEndpointCloseKeepsMinerAvailable(t *testing.T) {
	eth, _, _, _ := newNEVMDiscoveryLifecycleEthereum(t)
	client, stopEndpoint := newSyscoinPendingRPCClient(t, eth, "websocket")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var block map[string]interface{}
	if err := client.CallContext(ctx, &block, "eth_getBlockByNumber", "pending", false); err != nil || block == nil {
		t.Fatalf("pending RPC before endpoint closure: block=%v err=%v", block, err)
	}
	stopEndpoint()
	// An RPC endpoint may be disabled/replaced without stopping the Ethereum
	// service. A new endpoint must still admit pending work through its miner.
	replacement, _ := newSyscoinPendingRPCClient(t, eth, "websocket")
	block = nil
	if err := replacement.CallContext(ctx, &block, "eth_getBlockByNumber", "pending", false); err != nil || block == nil {
		t.Fatalf("pending RPC after endpoint replacement: block=%v err=%v", block, err)
	}
}
