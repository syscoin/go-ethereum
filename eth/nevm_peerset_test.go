// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package eth

import (
	"errors"
	"testing"
	"time"

	ethproto "github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/eth/protocols/snap"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

func newNEVMSnapBarrierPeers(t *testing.T, caps []p2p.Cap) (*ethproto.Peer, *snap.Peer) {
	t.Helper()
	if caps == nil {
		caps = []p2p.Cap{{Name: ethproto.ProtocolName, Version: ethproto.ProtocolVersions[0]},
			{Name: snap.ProtocolName, Version: snap.ProtocolVersions[0]}}
	}
	ethRW, snapRW := p2p.MsgPipe()
	t.Cleanup(func() { ethRW.Close(); snapRW.Close() })
	base := p2p.NewPeer(enode.ID{1}, "barrier-test", caps)
	ethPeer := ethproto.NewPeer(ethproto.ProtocolVersions[0], base, ethRW, nil)
	t.Cleanup(ethPeer.Close)
	return ethPeer, snap.NewPeer(snap.ProtocolVersions[0], base, snapRW)
}

type nevmSnapBarrierResult struct {
	peer *snap.Peer
	err  error
}

func startNEVMSnapWaiter(t *testing.T, ps *peerSet, peer *ethproto.Peer) <-chan nevmSnapBarrierResult {
	t.Helper()
	result := make(chan nevmSnapBarrierResult, 1)
	go func() { p, err := ps.waitSnapExtension(peer); result <- nevmSnapBarrierResult{p, err} }()
	deadline := time.After(2 * time.Second)
	for {
		ps.lock.RLock()
		_, waiting := ps.snapWait[peer.ID()]
		ps.lock.RUnlock()
		if waiting {
			return result
		}
		select {
		case <-deadline:
			ps.close()
			t.Fatal("ETH waiter did not enter the SNAP barrier")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestNEVMSnapBarrierClosedProducerDoesNotStrandHandlers(t *testing.T) {
	_, extension := newNEVMSnapBarrierPeers(t, nil)
	ps := newPeerSet()
	// Capture the reachable state after shutdown wakes an ETH waiter but
	// before that cancelled waiter has acquired ps.lock to remove its entry.
	wait := make(chan *snap.Peer)
	ps.snapWait[extension.ID()] = wait
	h := &handler{handlerStartCh: make(chan struct{}), handlerDoneCh: make(chan struct{}), quitSync: make(chan struct{})}
	h.wg.Add(1)
	go h.protoTracker()
	if !h.incHandlers() {
		t.Fatal("protocol handler was not admitted")
	}
	close(h.quitSync)
	ps.close()
	result := make(chan error, 1)
	go func() {
		err := ps.registerSnapExtension(extension)
		h.decHandlers()
		result <- err
	}()
	joined := make(chan struct{})
	go func() { h.wg.Wait(); close(joined) }()
	var err error
	select {
	case err = <-result:
	case <-time.After(time.Second):
		t.Error("late SNAP producer blocked on a cancelled ETH waiter")
		// Rescue the buggy baseline's send so this regression reports a failure
		// without leaving its mutex and protocol tracker permanently blocked.
		select {
		case <-wait:
		case <-time.After(2 * time.Second):
			t.Fatal("could not release blocked baseline producer")
		}
		select {
		case err = <-result:
		case <-time.After(2 * time.Second):
			t.Fatal("rescued producer did not finish handler accounting")
		}
	}
	if !errors.Is(err, errPeerSetClosed) {
		t.Errorf("late producer returned %v, want peerset closed", err)
	}
	select {
	case <-joined:
	case <-time.After(2 * time.Second):
		t.Fatal("protocol tracker did not join after barrier rejection")
	}
}

func TestNEVMSnapBarrierClosedWaiterRejectsPendingExtension(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		main, extension := newNEVMSnapBarrierPeers(t, nil)
		ps := newPeerSet()
		if err := ps.registerSnapExtension(extension); err != nil {
			t.Fatal(err)
		}
		if shutdown {
			ps.close()
		} else {
			ps.SetClosed()
		}
		peer, err := ps.waitSnapExtension(main)
		if peer != nil || !errors.Is(err, errPeerSetClosed) {
			t.Errorf("closed waiter consumed pending extension: peer=%v error=%v shutdown=%v", peer != nil, err, shutdown)
		}
	}
}

func TestNEVMSnapBarrierPairsBothProtocolOrders(t *testing.T) {
	for _, order := range []string{"eth_first", "snap_first"} {
		t.Run(order, func(t *testing.T) {
			main, extension := newNEVMSnapBarrierPeers(t, nil)
			ps := newPeerSet()
			defer ps.close()
			var paired *snap.Peer
			if order == "eth_first" {
				result := startNEVMSnapWaiter(t, ps, main)
				if _, err := ps.waitSnapExtension(main); !errors.Is(err, errPeerAlreadyRegistered) {
					t.Fatalf("duplicate ETH waiter: %v", err)
				}
				if err := ps.registerSnapExtension(extension); err != nil {
					t.Fatal(err)
				}
				select {
				case got := <-result:
					if got.err != nil {
						t.Fatal(got.err)
					}
					paired = got.peer
				case <-time.After(2 * time.Second):
					t.Fatal("ETH-first pairing did not complete")
				}
			} else {
				if err := ps.registerSnapExtension(extension); err != nil {
					t.Fatal(err)
				}
				if err := ps.registerSnapExtension(extension); !errors.Is(err, errPeerAlreadyRegistered) {
					t.Fatalf("duplicate pending SNAP extension: %v", err)
				}
				var err error
				if paired, err = ps.waitSnapExtension(main); err != nil {
					t.Fatal(err)
				}
			}
			if paired != extension || len(ps.snapWait) != 0 || len(ps.snapPend) != 0 {
				t.Fatal("pairing did not return and remove the matching extension")
			}
			if err := ps.registerPeer(main, paired); err != nil || ps.snapLen() != 1 {
				t.Fatalf("paired peer registration: %v", err)
			}
			if err := ps.registerSnapExtension(extension); !errors.Is(err, errPeerAlreadyRegistered) {
				t.Fatalf("duplicate registered SNAP extension: %v", err)
			}
		})
	}
}

func TestNEVMSnapBarrierCancellationAndCapabilityShortcuts(t *testing.T) {
	main, _ := newNEVMSnapBarrierPeers(t, nil)
	ps := newPeerSet()
	result := startNEVMSnapWaiter(t, ps, main)
	ps.close()
	select {
	case got := <-result:
		if got.peer != nil || !errors.Is(got.err, errPeerSetClosed) || len(ps.snapWait) != 0 {
			t.Fatalf("cancelled waiter did not clean up: %v", got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not release the ETH waiter")
	}
	ethOnly, _ := newNEVMSnapBarrierPeers(t, []p2p.Cap{{Name: ethproto.ProtocolName, Version: ethproto.ProtocolVersions[0]}})
	if peer, err := ps.waitSnapExtension(ethOnly); peer != nil || err != nil {
		t.Fatalf("non-SNAP ETH capability shortcut changed: %v", err)
	}
	_, snapOnly := newNEVMSnapBarrierPeers(t, []p2p.Cap{{Name: snap.ProtocolName, Version: snap.ProtocolVersions[0]}})
	if err := ps.registerSnapExtension(snapOnly); !errors.Is(err, errSnapWithoutEth) {
		t.Fatalf("SNAP without ETH capability shortcut changed: %v", err)
	}
}
