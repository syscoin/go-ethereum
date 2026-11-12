// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package eth

import (
	"context"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// Observe candidates reaching the real dial scheduler without making connections.
type nevmDiscoveryDialer struct{ attempts chan enode.ID }

func (d *nevmDiscoveryDialer) Dial(ctx context.Context, dest *enode.Node) (net.Conn, error) {
	select {
	case d.attempts <- dest.ID():
	case <-ctx.Done():
	}
	return nil, errors.New("test dial completed")
}

// A source remains blocked between explicitly supplied candidates, so duplicate
// authorization can be checked without natural iterator exhaustion masking closure.
type nevmDiscoverySource struct {
	nodes  chan *enode.Node
	closed chan struct{}
	once   sync.Once
	cur    *enode.Node
}

func (s *nevmDiscoverySource) Next() bool {
	select {
	case s.cur = <-s.nodes:
		return true
	case <-s.closed:
		return false
	}
}

func (s *nevmDiscoverySource) Node() *enode.Node { return s.cur }
func (s *nevmDiscoverySource) Close()            { s.once.Do(func() { close(s.closed) }) }

// The configured logger provides a gate inside real server startup without
// adding a production hook or depending on scheduler timing.
type nevmDiscoveryStartupGate struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *nevmDiscoveryStartupGate) Enabled(context.Context, slog.Level) bool { return true }
func (g *nevmDiscoveryStartupGate) WithAttrs([]slog.Attr) slog.Handler       { return g }
func (g *nevmDiscoveryStartupGate) WithGroup(string) slog.Handler            { return g }
func (g *nevmDiscoveryStartupGate) Handle(_ context.Context, record slog.Record) error {
	if record.Message == "UDP listener up" {
		g.once.Do(func() {
			close(g.entered)
			select {
			case <-g.release:
			case <-time.After(10 * time.Second):
			}
		})
	}
	return nil
}

func newNEVMDiscoveryLifecycleEthereum(t *testing.T, prepare ...func(*Ethereum)) (*Ethereum, *node.Node, *event.TypeMuxSubscription, *nevmDiscoveryDialer) {
	t.Helper()
	dialer := &nevmDiscoveryDialer{attempts: make(chan enode.ID, 4)}
	stack, err := node.New(&node.Config{P2P: p2p.Config{
		ListenAddr: "127.0.0.1:0", DiscAddr: "127.0.0.1:0", MaxPeers: 4,
		DiscoveryV5: true, Dialer: dialer,
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
	config.TxPool.NoLocals, config.LogNoHistory = true, true
	config.EthDiscoveryURLs, config.SnapDiscoveryURLs = nil, nil
	config.NEVMPubEP = "tcp://127.0.0.1:0"
	done := stack.EventMux().Subscribe(downloader.DoneEvent{})
	eth, err := New(stack, &config)
	if err != nil {
		done.Unsubscribe()
		stack.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stack.Close()
		done.Unsubscribe()
	})
	eth.lock.Lock()
	eth.timeLastBlock = time.Now().Add(time.Hour).Unix()
	eth.lock.Unlock()
	for _, setup := range prepare {
		setup(eth)
	}
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}
	return eth, stack, done, dialer
}

func waitNEVMDiscoveryWorker(t *testing.T, eth *Ethereum) {
	t.Helper()
	finished := make(chan struct{})
	go func() { eth.wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("networking worker did not finish")
	}
}

func TestNEVMDiscoverySurvivesAuthorizedStartup(t *testing.T) {
	eth, _, done, dialer := newNEVMDiscoveryLifecycleEthereum(t)
	if reply := eth.zmqRep.handleNEVMComms("\fstartnetwork"); reply != "ack" {
		t.Fatalf("startnetwork reply: %q", reply)
	}
	select {
	case <-done.Chan():
		t.Fatal("network completed while block activity was pending")
	case <-time.After(150 * time.Millisecond):
	}
	if eth.handler.running.Load() || eth.handler.synced.Load() {
		t.Fatal("networking activated while block activity was pending")
	}
	eth.handler.peers.lock.RLock()
	closed := eth.handler.peers.closed
	eth.handler.peers.lock.RUnlock()
	if !closed {
		t.Fatal("peer gate opened while block activity was pending")
	}
	eth.lock.Lock()
	eth.timeLastBlock = time.Now().Add(-6 * time.Second).Unix()
	eth.lock.Unlock()
	select {
	case ev := <-done.Chan():
		if ev == nil {
			t.Fatal("network completion subscription closed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("authorized network did not start")
	}
	waitNEVMDiscoveryWorker(t, eth)
	if eth.p2pServer.LocalNode() == nil || eth.p2pServer.DiscoveryV5() == nil {
		t.Fatal("authorized startup did not initialize discovery v5")
	}
	if !eth.handler.running.Load() || !eth.handler.synced.Load() {
		t.Fatal("authorized networking handler did not start")
	}
	source := &nevmDiscoverySource{nodes: make(chan *enode.Node, 1), closed: make(chan struct{})}
	t.Cleanup(source.Close)
	// Keep the backend's real mixer and protocol registrations. Replacing the
	// mixer here would hide the initial server shutdown closing DialCandidates.
	eth.discmix.AddSource(source)
	for attempt := 0; attempt < 2; attempt++ {
		if attempt == 1 {
			if reply := eth.zmqRep.handleNEVMComms("\fstartnetwork"); reply != "ack" {
				t.Fatalf("duplicate startnetwork reply: %q", reply)
			}
			select {
			case <-source.closed:
				t.Fatal("duplicate authorization closed discovery candidates")
			default:
			}
			select {
			case <-done.Chan():
				t.Fatal("duplicate authorization published another completion")
			default:
			}
		}
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		candidate := enode.NewV4(&key.PublicKey, net.IPv4(127, 0, 0, 1), 30303, 30303)
		source.nodes <- candidate
		select {
		case got := <-dialer.attempts:
			if got != candidate.ID() {
				t.Fatalf("dialed unexpected candidate %s, want %s", got, candidate.ID())
			}
		case <-time.After(5 * time.Second):
			t.Fatal("authorized discovery candidate did not reach the dial scheduler")
		}
	}
}

func TestNEVMDiscoveryPreauthorizationRPC(t *testing.T) {
	eth, stack, _, _ := newNEVMDiscoveryLifecycleEthereum(t)
	if eth.p2pServer.LocalNode() != nil || eth.p2pServer.DiscoveryV5() != nil {
		t.Fatal("P2P initialized before networking authorization")
	}
	client := stack.Attach()
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var count hexutil.Uint
	if err := client.CallContext(ctx, &count, "net_peerCount"); err != nil || count != 0 {
		t.Fatalf("preauthorization net_peerCount: count=%d error=%v", count, err)
	}
	var peers []interface{}
	if err := client.CallContext(ctx, &peers, "admin_peers"); err != nil || len(peers) != 0 {
		t.Fatalf("preauthorization admin_peers: peers=%v error=%v", peers, err)
	}
	var info interface{}
	if err := client.CallContext(ctx, &info, "admin_nodeInfo"); err != nil {
		t.Fatalf("preauthorization admin_nodeInfo: %v", err)
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	url := enode.NewV4(&key.PublicKey, net.IPv4(127, 0, 0, 1), 30303, 30303).URLv4()
	for _, method := range []string{"admin_addPeer", "admin_removePeer", "admin_addTrustedPeer", "admin_removeTrustedPeer"} {
		var changed bool
		err := client.CallContext(ctx, &changed, method, url)
		if err == nil || err.Error() != node.ErrNodeStopped.Error() || changed {
			t.Fatalf("preauthorization %s: changed=%v error=%v", method, changed, err)
		}
	}
}

func assertNEVMDiscoveryNotAuthorized(t *testing.T, eth *Ethereum, done *event.TypeMuxSubscription) {
	t.Helper()
	finished := make(chan struct{})
	go func() { eth.wg.Wait(); close(finished) }()
	select {
	case ev := <-done.Chan():
		if ev != nil {
			t.Fatal("failed or cancelled authorization published networking completion")
		}
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Fatal("cancelled networking worker did not finish")
		}
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("failed networking worker did not finish")
	}
	if eth.handler.running.Load() || eth.handler.synced.Load() {
		t.Fatal("failed or cancelled authorization activated networking")
	}
	eth.handler.peers.lock.RLock()
	closed := eth.handler.peers.closed
	eth.handler.peers.lock.RUnlock()
	if !closed {
		t.Fatal("failed or cancelled authorization opened the peer gate")
	}
}

func closeNEVMDiscoveryStack(t *testing.T, stack *node.Node) {
	t.Helper()
	stopped := make(chan error, 1)
	go func() { stopped <- stack.Close() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("node shutdown did not finish")
	}
}

func TestNEVMDiscoveryActivationFailure(t *testing.T) {
	for _, failure := range []string{"listen", "discovery_configuration"} {
		t.Run(failure, func(t *testing.T) {
			var prepare func(*Ethereum)
			if failure == "listen" {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				prepare = func(eth *Ethereum) { eth.p2pServer.ListenAddr = listener.Addr().String() }
			} else {
				prepare = func(eth *Ethereum) { eth.config.EthDiscoveryURLs = []string{"invalid-discovery-url"} }
			}
			eth, stack, done, dialer := newNEVMDiscoveryLifecycleEthereum(t, prepare)
			if reply := eth.zmqRep.handleNEVMComms("\fstartnetwork"); reply != "ack" {
				t.Fatalf("startnetwork reply: %q", reply)
			}
			eth.lock.Lock()
			eth.timeLastBlock = time.Now().Add(-6 * time.Second).Unix()
			eth.lock.Unlock()
			assertNEVMDiscoveryNotAuthorized(t, eth, done)
			stopped := make(chan struct{})
			go func() { stack.Wait(); close(stopped) }()
			select {
			case <-stopped:
			case <-time.After(5 * time.Second):
				t.Fatal("failed network activation did not shut down the node")
			}
			select {
			case <-dialer.attempts:
				t.Fatal("failed authorization dialed a peer")
			default:
			}
		})
	}
}

func TestNEVMDiscoveryCancelledBeforeFirstAuthorization(t *testing.T) {
	eth, stack, done, dialer := newNEVMDiscoveryLifecycleEthereum(t)
	eth.closeHandlerOnce.Do(func() { close(eth.closeHandler) })
	if reply := eth.zmqRep.handleNEVMComms("\fstartnetwork"); reply != "ack" {
		t.Fatalf("cancelled startnetwork reply: %q", reply)
	}
	assertNEVMDiscoveryNotAuthorized(t, eth, done)
	if eth.p2pServer.LocalNode() != nil || eth.p2pServer.DiscoveryV5() != nil {
		t.Fatal("cancelled authorization initialized P2P")
	}
	closeNEVMDiscoveryStack(t, stack)
	select {
	case <-dialer.attempts:
		t.Fatal("cancelled authorization dialed a peer")
	default:
	}
}

func TestNEVMDiscoveryShutdownDuringP2PStartup(t *testing.T) {
	gate := &nevmDiscoveryStartupGate{entered: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate.release) }) }
	eth, stack, done, dialer := newNEVMDiscoveryLifecycleEthereum(t, func(eth *Ethereum) {
		eth.p2pServer.Logger = log.NewLogger(gate)
	})
	t.Cleanup(release)
	if reply := eth.zmqRep.handleNEVMComms("\fstartnetwork"); reply != "ack" {
		t.Fatalf("startnetwork reply: %q", reply)
	}
	eth.lock.Lock()
	eth.timeLastBlock = time.Now().Add(-6 * time.Second).Unix()
	eth.lock.Unlock()
	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not reach UDP listener startup")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- stack.Close() }()
	select {
	case <-eth.closeHandler:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not cancel delayed network startup")
	}
	release()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown did not join in-progress P2P startup")
	}
	assertNEVMDiscoveryNotAuthorized(t, eth, done)
	select {
	case <-dialer.attempts:
		t.Fatal("cancelled startup dialed a peer")
	default:
	}
}

func TestNEVMDiscoveryShutdownWhileAuthorizationWaits(t *testing.T) {
	eth, stack, done, dialer := newNEVMDiscoveryLifecycleEthereum(t)
	if reply := eth.zmqRep.handleNEVMComms("\fstartnetwork"); reply != "ack" {
		t.Fatalf("startnetwork reply: %q", reply)
	}
	duplicate := make(chan string, 1)
	go func() { duplicate <- eth.zmqRep.handleNEVMComms("\fstartnetwork") }()
	select {
	case <-duplicate:
		t.Fatal("duplicate authorization completed while the worker was settling")
	case <-time.After(150 * time.Millisecond):
	}
	stopped := make(chan error, 1)
	go func() { stopped <- stack.Close() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("node shutdown did not cancel pending networking authorization")
	}
	waitNEVMDiscoveryWorker(t, eth)
	select {
	case reply := <-duplicate:
		if reply != "ack" {
			t.Fatalf("cancelled duplicate reply: %q", reply)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown stranded a duplicate authorization command")
	}
	if eth.handler.running.Load() || eth.handler.synced.Load() {
		t.Fatal("cancelled authorization activated networking")
	}
	eth.handler.peers.lock.RLock()
	closed := eth.handler.peers.closed
	eth.handler.peers.lock.RUnlock()
	if !closed {
		t.Fatal("cancelled authorization opened the peer gate")
	}
	for ev := range done.Chan() {
		if ev != nil {
			t.Fatal("cancelled authorization published a networking completion")
		}
	}
	select {
	case <-dialer.attempts:
		t.Fatal("cancelled authorization dialed a peer")
	default:
	}
}
