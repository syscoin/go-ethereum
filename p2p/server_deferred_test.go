// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package p2p

import (
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
)

func TestServerDeferredAPIs(t *testing.T) {
	srv := &Server{Config: Config{PrivateKey: newkey(), NoDial: true, NoDiscovery: true}}
	for name, read := range map[string]func(){
		"peers":      func() { srv.Peers() },
		"peer-count": func() { srv.PeerCount() },
		"peer-info":  func() { srv.PeersInfo() },
	} {
		t.Run(name, func(t *testing.T) {
			done := make(chan struct{})
			go func() { defer close(done); read() }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("query blocked before first P2P start")
			}
		})
	}
}

func TestServerFirstStartConcurrentGetters(t *testing.T) {
	srv := &Server{Config: Config{
		PrivateKey: newkey(), NoDial: true, ListenAddr: "127.0.0.1:0", DiscoveryV4: true, DiscoveryV5: true,
	}}
	var wg sync.WaitGroup
	done := make(chan struct{})
	for _, read := range []func(){
		func() { srv.Self() },
		func() { srv.LocalNode() },
		func() { srv.DiscoveryV4() },
		func() { srv.DiscoveryV5() },
		func() { srv.NodeInfo() },
	} {
		ready := make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			read()
			close(ready)
			for {
				select {
				case <-done:
					return
				default:
					read()
				}
			}
		}()
		<-ready
	}
	if err := srv.Start(); err != nil {
		close(done)
		wg.Wait()
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)
	close(done)
	wg.Wait()
}

func TestServerFirstStartFailureCleanup(t *testing.T) {
	srv := &Server{Config: Config{
		PrivateKey: newkey(), NoDial: true, NoDiscovery: true,
		ListenAddr: "127.0.0.1:0", NodeDatabase: t.TempDir(),
	}}
	wantErr := errors.New("injected listener failure")
	srv.listenFunc = func(string, string) (net.Listener, error) { return nil, wantErr }
	if err := srv.Start(); !errors.Is(err, wantErr) {
		t.Fatalf("startup error = %v, want %v", err, wantErr)
	}
	if srv.running {
		t.Error("failed first startup still reports running")
	}
	srv.Stop()
	db, err := enode.OpenDB(srv.NodeDatabase)
	if err != nil {
		if srv.nodedb != nil {
			srv.nodedb.Close()
		}
		t.Fatalf("failed startup retained node database lock: %v", err)
	}
	db.Close()
}

func TestServerFirstStartDiscoveryFailureCleanup(t *testing.T) {
	for _, version := range []string{"v4", "v5-after-v4"} {
		t.Run(version, func(t *testing.T) {
			invalidBootnode := enode.NewV4(&newkey().PublicKey, nil, 0, 0)
			srv := &Server{Config: Config{
				PrivateKey: newkey(), NoDial: true, ListenAddr: "127.0.0.1:0",
				NodeDatabase: t.TempDir(), DiscoveryV4: true,
			}}
			if version == "v4" {
				srv.BootstrapNodes = []*enode.Node{invalidBootnode}
			} else {
				srv.Config.DiscoveryV5 = true
				srv.BootstrapNodesV5 = []*enode.Node{invalidBootnode}
			}
			t.Cleanup(func() {
				// Clean the old implementation's partial startup after asserting its leaks.
				srv.Stop()
				if srv.discv4 != nil {
					srv.discv4.Close()
				}
				if srv.discv5 != nil {
					srv.discv5.Close()
				}
				if srv.discmix != nil {
					srv.discmix.Close()
				}
				if srv.nodedb != nil {
					srv.nodedb.Close()
				}
				// A v4 setup failure loses the raw UDPConn before assigning srv.discv4.
				runtime.GC()
			})
			if err := srv.Start(); err == nil {
				t.Fatal("startup accepted incomplete discovery bootnode")
			}
			if srv.running {
				t.Error("failed discovery startup still reports running")
			}
			listener, err := net.Listen("tcp", srv.ListenAddr)
			if err != nil {
				t.Errorf("failed discovery startup retained TCP listener: %v", err)
			} else {
				listener.Close()
			}
			addr, err := net.ResolveUDPAddr("udp", srv.ListenAddr)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := net.ListenUDP("udp", addr)
			if err != nil {
				t.Errorf("failed discovery startup retained UDP socket: %v", err)
			} else {
				conn.Close()
			}
			db, err := enode.OpenDB(srv.NodeDatabase)
			if err != nil {
				t.Errorf("failed discovery startup retained node database lock: %v", err)
			} else {
				db.Close()
			}
		})
	}
}
