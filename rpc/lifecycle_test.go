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

// SYSCOIN: Security regression coverage.
package rpc

import (
	"context"
	"errors"
	"testing"
	"time"
)

type disconnectWaitService struct {
	started chan struct{}
	done    chan error
	abort   chan struct{}
}

func (s *disconnectWaitService) Wait(ctx context.Context) error {
	close(s.started)
	select {
	case <-ctx.Done():
	case <-s.abort:
	}
	s.done <- ctx.Err()
	return ctx.Err()
}

// Persistent transports must cancel running methods on disconnect, rather than
// waiting for the methods before canceling their contexts.
func TestServerCancelCallsOnDisconnect(t *testing.T) {
	for _, transport := range []string{"inproc", "ipc", "ws"} {
		t.Run(transport, func(t *testing.T) {
			t.Parallel()
			svc := &disconnectWaitService{
				started: make(chan struct{}),
				done:    make(chan error, 1),
				abort:   make(chan struct{}),
			}
			server := NewServer()
			defer server.Stop()
			if err := server.RegisterName("test", svc); err != nil {
				t.Fatal(err)
			}
			var client *Client
			switch transport {
			case "inproc":
				client = DialInProc(server)
			case "ipc":
				c, listener := ipcTestClient(server, nil)
				defer listener.Close()
				client = c
			case "ws":
				c, httpServer := httpTestClient(server, transport, nil)
				defer httpServer.Close()
				client = c
			}
			defer client.Close()
			defer close(svc.abort)
			returned := make(chan error, 1)
			go func() { returned <- client.Call(nil, "test_wait") }()
			select {
			case <-svc.started:
			case <-time.After(5 * time.Second):
				t.Fatal("call did not start")
			}
			client.Close()
			select {
			case err := <-svc.done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("call context error = %v, want context.Canceled", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("call context not canceled after the client disconnected")
			}
			select {
			case err := <-returned:
				if err == nil {
					t.Fatal("disconnected call returned no error")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("disconnected client call did not return")
			}
		})
	}
}

type httpCompletionService struct {
	started chan struct{}
	release chan struct{}
}

func (s *httpCompletionService) Wait(ctx context.Context) (string, error) {
	close(s.started)
	select {
	case <-s.release:
		return "completed", ctx.Err()
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Unlike disconnecting persistent transports, finishing an HTTP request must
// wait for its call goroutine to write the response before canceling its context.
func TestServerHTTPCallsCompleteBeforeCancel(t *testing.T) {
	for _, batch := range []bool{false, true} {
		name := "single"
		if batch {
			name = "batch"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			svc := &httpCompletionService{started: make(chan struct{}), release: make(chan struct{}, 1)}
			server := NewServer()
			defer server.Stop()
			if err := server.RegisterName("test", svc); err != nil {
				t.Fatal(err)
			}
			client, httpServer := httpTestClient(server, "http", nil)
			defer httpServer.Close()
			defer client.Close()
			defer close(svc.release)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var result string
			returned := make(chan error, 1)
			go func() {
				if batch {
					elems := []BatchElem{{Method: "test_wait", Result: &result}}
					if err := client.BatchCallContext(ctx, elems); err != nil {
						returned <- err
					} else {
						returned <- elems[0].Error
					}
				} else {
					returned <- client.CallContext(ctx, &result, "test_wait")
				}
			}()
			select {
			case <-svc.started:
			case <-ctx.Done():
				t.Fatal("HTTP call did not start")
			}
			svc.release <- struct{}{}
			select {
			case err := <-returned:
				if err != nil || result != "completed" {
					t.Fatalf("HTTP call result = %q, error = %v", result, err)
				}
			case <-ctx.Done():
				t.Fatal("HTTP call did not complete")
			}
		})
	}
}
