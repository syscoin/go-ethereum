// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// SYSCOIN: Gate write completion independently of reads, so shutdown and
// reconnect ordering is exercised without depending on transport scheduling.
type shutdownTestCodec struct {
	reads       chan shutdownTestRead
	writes      chan *jsonrpcMessage
	writeResult chan error
	closedCh    chan interface{}
	closeOnce   sync.Once
}

type shutdownTestRead struct {
	msg *jsonrpcMessage
	err error
}

func newShutdownTestCodec() *shutdownTestCodec {
	return &shutdownTestCodec{
		reads:       make(chan shutdownTestRead),
		writes:      make(chan *jsonrpcMessage, 1),
		writeResult: make(chan error, 1),
		closedCh:    make(chan interface{}),
	}
}

func (c *shutdownTestCodec) peerInfo() PeerInfo         { return PeerInfo{} }
func (c *shutdownTestCodec) remoteAddr() string         { return "shutdown-test" }
func (c *shutdownTestCodec) closed() <-chan interface{} { return c.closedCh }
func (c *shutdownTestCodec) close()                     { c.closeOnce.Do(func() { close(c.closedCh) }) }
func (c *shutdownTestCodec) readBatch() ([]*jsonrpcMessage, bool, error) {
	select {
	case read := <-c.reads:
		if read.err != nil {
			return nil, false, read.err
		}
		return []*jsonrpcMessage{read.msg}, false, nil
	case <-c.closedCh:
		return nil, false, io.EOF
	}
}

func (c *shutdownTestCodec) writeJSON(ctx context.Context, msg interface{}, _ bool) error {
	c.writes <- msg.(*jsonrpcMessage)
	select {
	case err := <-c.writeResult:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func waitShutdownTest[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for RPC shutdown ordering")
		var zero T
		return zero
	}
}

// SYSCOIN: A successful write can be reported after dispatch has already
// processed its connection's read error. That request must not be orphaned.
func TestClientSuccessfulWriteAfterReadError(t *testing.T) {
	for _, mode := range []string{"call", "response", "notification", "close"} {
		t.Run(mode, func(t *testing.T) {
			codec := newShutdownTestCodec()
			client := initClient(codec, new(serviceRegistry), new(clientConfig))
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if mode == "notification" {
					done <- client.Notify(ctx, "test_notify")
					return
				}
				var result string
				err := client.CallContext(ctx, &result, "test_call")
				if mode == "response" && err == nil && result != "delivered" {
					err = errors.New("delivered response was replaced")
				}
				done <- err
			}()
			request := waitShutdownTest(t, codec.writes)
			if mode == "response" {
				// The read loop sends messages to dispatch in order, so this
				// response is processed before the subsequent read error.
				codec.reads <- shutdownTestRead{msg: &jsonrpcMessage{
					Version: vsn, ID: request.ID, Result: json.RawMessage(`"delivered"`),
				}}
			}
			readErr := errors.New("connection closed after request write")
			codec.reads <- shutdownTestRead{err: readErr}
			// close() runs at the end of dispatch's read-error handler.
			waitShutdownTest(t, codec.closedCh)
			wantErr := readErr
			if mode == "close" {
				client.Close()
				wantErr = ErrClientQuit
			} else if mode == "response" || mode == "notification" {
				wantErr = nil
			}
			codec.writeResult <- nil
			if err := waitShutdownTest(t, done); err != wantErr {
				t.Fatalf("call error = %v, want %v", err, wantErr)
			}
		})
	}
}

// SYSCOIN: A failed write still transfers its request to the replacement
// connection; the old connection's read error must not cancel that retry.
func TestClientFailedWriteAfterReadErrorReconnects(t *testing.T) {
	first, second := newShutdownTestCodec(), newShutdownTestCodec()
	client := initClient(first, new(serviceRegistry), new(clientConfig))
	client.reconnectFunc = func(context.Context) (ServerCodec, error) { return second, nil }
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		var result string
		err := client.CallContext(ctx, &result, "test_retry")
		if err == nil && result != "retried" {
			err = errors.New("incorrect retry response")
		}
		done <- err
	}()
	request := waitShutdownTest(t, first.writes)
	first.reads <- shutdownTestRead{err: io.EOF}
	waitShutdownTest(t, first.closedCh)
	first.writeResult <- io.ErrClosedPipe
	retry := waitShutdownTest(t, second.writes)
	if string(retry.ID) != string(request.ID) {
		t.Fatalf("retry ID = %s, want %s", retry.ID, request.ID)
	}
	second.reads <- shutdownTestRead{msg: &jsonrpcMessage{
		Version: vsn, ID: retry.ID, Result: json.RawMessage(`"retried"`),
	}}
	second.writeResult <- nil
	if err := waitShutdownTest(t, done); err != nil {
		t.Fatal(err)
	}
}
