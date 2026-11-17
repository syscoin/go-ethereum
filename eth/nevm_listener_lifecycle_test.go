// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package eth

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/node"
	"github.com/go-zeromq/zmq4"
)

// Gate actual template assembly, after CreateBlock's preliminary buffer flush
// has released bufferLock. This checks request lifetime without injecting a
// fatal database error into the test process.
type nevmListenerEngine struct {
	consensus.Engine
	entered, release, finished, closed chan struct{}
	armed                              atomic.Bool
	calls                              atomic.Int32
}

func (e *nevmListenerEngine) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, body *types.Body, receipts []*types.Receipt) (*types.Block, error) {
	e.calls.Add(1)
	if e.armed.CompareAndSwap(true, false) {
		close(e.entered)
		defer close(e.finished)
		<-e.release
		select {
		case <-e.closed:
			// Rescue the old ordering without using already closed chain state.
			return nil, errors.New("engine closed during template request")
		default:
		}
	}
	return e.Engine.FinalizeAndAssemble(chain, header, state, body, receipts)
}

func (e *nevmListenerEngine) Close() error {
	close(e.closed)
	return e.Engine.Close()
}

type nevmListenerDatabase struct {
	ethdb.Database
	closed chan struct{}
}

// SYSCOIN: preserve the wrapped store's optional durability capability.
func (db *nevmListenerDatabase) SyncKeyValue() error {
	return ethdb.SyncKeyValue(db.Database)
}

func (db *nevmListenerDatabase) Close() error {
	close(db.closed)
	return db.Database.Close()
}

func nevmListenerClient(t *testing.T, server *ZMQRep) zmq4.Socket {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	client := zmq4.NewReq(ctx, zmq4.WithTimeout(3*time.Second))
	t.Cleanup(func() { cancel(); client.Close() })
	if err := client.Dial("tcp://" + server.rep.Addr().String()); err != nil {
		t.Fatal(err)
	}
	return client
}

func sendNEVMListenerRequest(t *testing.T, client zmq4.Socket, topic, body string) {
	t.Helper()
	if err := client.SendMulti(zmq4.NewMsgFrom([]byte(topic), []byte(body))); err != nil {
		t.Fatal(err)
	}
}

func waitNEVMListenerSignal(t *testing.T, signal <-chan struct{}, failure string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatal(failure)
	}
}

func TestNEVMListenerShutdownWaitsForTemplate(t *testing.T) {
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
	client := nevmListenerClient(t, eth.zmqRep)
	queued := nevmListenerClient(t, eth.zmqRep)
	// Prove this is a usable real template before introducing the overlap.
	sendNEVMListenerRequest(t, client, "nevmblock", "nevmblock")
	reply, err := client.Recv()
	if err != nil || len(reply.Frames) != 2 || string(reply.Frames[0]) != "nevmblock" || len(reply.Frames[1]) == 0 {
		t.Fatalf("template positive control: frames=%q err=%v", reply.Frames, err)
	}
	engine.armed.Store(true)
	sendNEVMListenerRequest(t, client, "nevmblock", "nevmblock")
	waitNEVMListenerSignal(t, engine.entered, "template did not enter assembly")
	sendNEVMListenerRequest(t, queued, "nevmblock", "nevmblock")
	stopped := make(chan error, 1)
	go func() { stopped <- stack.Close() }()
	waitNEVMListenerSignal(t, eth.closeHandler, "independent shutdown did not start")
	select {
	case <-engine.closed:
		t.Error("consensus engine closed while listener template was still executing")
		// Do not let the baseline admit the queued request against closed
		// resources (or reuse its old template WaitGroup during Wait).
		eth.zmqRep.cancel()
	case <-db.closed:
		t.Error("chain database closed while listener template was still executing")
		eth.zmqRep.cancel()
	case err := <-stopped:
		t.Fatalf("shutdown returned before active template completed: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	release()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not join the released template")
	}
	select {
	case <-engine.finished:
	default:
		t.Error("shutdown returned before template completion")
	}
	if got := engine.calls.Load(); got != 2 {
		t.Errorf("queued template entered after admission stopped: assembly calls=%d, want 2", got)
	}
	if eth.zmqRep.ctx.Err() == nil {
		t.Error("listener context still active after node shutdown")
	}
	if err := stack.Close(); !errors.Is(err, node.ErrNodeStopped) {
		t.Errorf("repeated node close: %v", err)
	}
	eth.zmqRep.Close()
}

// Socket is an existing interface. Model transport backpressure at SendMulti,
// including a delayed return after cancellation, without relying on TCP buffer
// sizes or adding a production test hook.
type nevmListenerBlockedSend struct {
	zmq4.Socket
	ctx                         context.Context
	entered, cancelled, release chan struct{}
}

func (s *nevmListenerBlockedSend) SendMulti(msg zmq4.Msg) error {
	close(s.entered)
	<-s.ctx.Done()
	close(s.cancelled)
	<-s.release
	return s.ctx.Err()
}

func TestNEVMListenerShutdownJoinsBlockedSend(t *testing.T) {
	var transport *nevmListenerBlockedSend
	var db *nevmListenerDatabase
	eth, stack, _, _ := newNEVMDiscoveryLifecycleEthereum(t, func(eth *Ethereum) {
		transport = &nevmListenerBlockedSend{Socket: eth.zmqRep.rep, ctx: eth.zmqRep.ctx, entered: make(chan struct{}), cancelled: make(chan struct{}), release: make(chan struct{})}
		eth.zmqRep.rep = transport
		db = &nevmListenerDatabase{Database: eth.chainDb, closed: make(chan struct{})}
		eth.chainDb = db
	})
	var once sync.Once
	release := func() { once.Do(func() { close(transport.release) }) }
	t.Cleanup(release)
	client := nevmListenerClient(t, eth.zmqRep)
	sendNEVMListenerRequest(t, client, "nevmblockinfo", "nevmblockinfo")
	waitNEVMListenerSignal(t, transport.entered, "dispatcher did not reach response send")
	stopped := make(chan error, 1)
	go func() { stopped <- stack.Close() }()
	waitNEVMListenerSignal(t, transport.cancelled, "shutdown did not cancel blocked send")
	closedAgain := make(chan struct{})
	go func() { eth.zmqRep.Close(); close(closedAgain) }()
	select {
	case <-closedAgain:
		t.Error("concurrent repeated Close returned before its dispatcher")
	case <-time.After(150 * time.Millisecond):
	}
	select {
	case <-db.closed:
		t.Error("database closed before response dispatcher returned")
	case err := <-stopped:
		t.Errorf("shutdown returned before response dispatcher returned: %v", err)
		stopped <- err // Allow shared cleanup path to consume the result.
	case <-time.After(150 * time.Millisecond):
	}
	release()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not join response dispatcher")
	}
	waitNEVMListenerSignal(t, closedAgain, "concurrent repeated Close did not finish")
}

func TestNEVMListenerShutdownReleasesStartNetworkPost(t *testing.T) {
	eth, stack, done, _ := newNEVMDiscoveryLifecycleEthereum(t, func(eth *Ethereum) {
		eth.p2pServer.NoDiscovery = true
		eth.timeLastBlock = time.Now().Add(-6 * time.Second).Unix()
	})
	client := nevmListenerClient(t, eth.zmqRep)
	sendNEVMListenerRequest(t, client, "nevmcomms", "\fstartnetwork")
	if reply, err := client.Recv(); err != nil || len(reply.Frames) != 2 || string(reply.Frames[1]) != "ack" {
		t.Fatalf("first authorization: %q, %v", reply.Frames, err)
	}
	select {
	case <-done.Chan():
	case <-time.After(5 * time.Second):
		t.Fatal("first authorization did not finish")
	}
	waitNEVMDiscoveryWorker(t, eth)
	// Ordered subscriptions prove that the duplicate command entered Post and
	// cannot return until the later, unconsumed subscription is released.
	probe := eth.eventMux.Subscribe(downloader.StartNetworkEvent{})
	blocked := eth.eventMux.Subscribe(downloader.StartNetworkEvent{})
	t.Cleanup(probe.Unsubscribe)
	t.Cleanup(blocked.Unsubscribe)
	sendNEVMListenerRequest(t, client, "nevmcomms", "\fstartnetwork")
	select {
	case <-probe.Chan():
	case <-time.After(5 * time.Second):
		t.Fatal("duplicate authorization did not reach event mux")
	}
	closeNEVMDiscoveryStack(t, stack)
	if eth.zmqRep.ctx.Err() == nil {
		t.Error("listener still active after blocked authorization shutdown")
	}
}

func TestNEVMListenerDisconnectShutsDownWithoutSelfJoin(t *testing.T) {
	eth, stack, _, _ := newNEVMDiscoveryLifecycleEthereum(t)
	client := nevmListenerClient(t, eth.zmqRep)
	sendNEVMListenerRequest(t, client, "nevmcomms", "\ndisconnect")
	stopped := make(chan struct{})
	go func() { stack.Wait(); close(stopped) }()
	waitNEVMListenerSignal(t, stopped, "disconnect command deadlocked its own listener join")
	eth.zmqRep.Close()
}

func TestNEVMListenerCloseWithoutRequests(t *testing.T) {
	for _, mode := range []string{"unstarted", "idle", "failed_listen"} {
		t.Run(mode, func(t *testing.T) {
			server := NewZMQRep(nil, nil, "tcp://127.0.0.1:0")
			// Also reclaim the baseline's unstarted socket when asserting its bug.
			t.Cleanup(func() { server.cancel(); server.rep.Close() })
			switch mode {
			case "idle":
				if err := server.InitZMQListener(); err != nil {
					t.Fatal(err)
				}
			case "failed_listen":
				occupied, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { occupied.Close() })
				server.NEVMPubEP = "tcp://" + occupied.Addr().String()
				if err := server.InitZMQListener(); err == nil {
					t.Fatal("listen unexpectedly succeeded on occupied endpoint")
				}
			}
			closed := make(chan struct{})
			go func() { server.Close(); server.Close(); close(closed) }()
			waitNEVMListenerSignal(t, closed, "idle or repeated listener close blocked")
			if server.ctx.Err() == nil {
				t.Error("listener close did not cancel its resources")
			}
		})
	}
}
