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
package downloader

import (
	"sync"
	"testing"
	"time"
)

// Unsubscribe must drain pending broadcasts before the event loop can accept its
// removal request, then wait until removal is acknowledged. Concurrent callers
// must all wait for that acknowledgement and submit only one removal request.
func TestSyncStatusSubscriptionUnsubscribe(t *testing.T) {
	for _, test := range []struct {
		name   string
		events int
	}{
		{"single event", 1},
		{"multiple events", 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			api := &DownloaderAPI{
				uninstallSyncSubscription: make(chan *uninstallSyncSubscriptionRequest),
			}
			status := make(chan interface{})
			sub := &SyncStatusSubscription{api: api, c: status}
			accepted := make(chan *uninstallSyncSubscriptionRequest, 1)
			acknowledge := make(chan struct{})
			cleanup := make(chan struct{})
			loopDone := make(chan struct{})

			// Model the event loop's blocking broadcasts followed by removal.
			go func() {
				defer close(loopDone)
				for i := 0; i < test.events; i++ {
					select {
					case status <- false:
					case <-cleanup:
					}
				}
				req := <-api.uninstallSyncSubscription
				accepted <- req
				select {
				case <-acknowledge:
				case <-cleanup:
				}
				close(req.uninstalled)
			}()
			defer func() {
				close(cleanup)
				<-loopDone
			}()

			var wg sync.WaitGroup
			for i := 0; i < 3; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					sub.Unsubscribe()
				}()
			}
			unsubscribed := make(chan struct{})
			go func() {
				wg.Wait()
				close(unsubscribed)
			}()

			select {
			case req := <-accepted:
				if req.c != status {
					t.Fatal("uninstall request refers to a different subscription")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("unsubscribe deadlocked with a pending status broadcast")
			}
			select {
			case <-unsubscribed:
				t.Fatal("unsubscribe returned before removal was acknowledged")
			default:
			}
			close(acknowledge)
			select {
			case <-unsubscribed:
			case <-time.After(5 * time.Second):
				t.Fatal("unsubscribe did not finish after removal was acknowledged")
			}
			close(status)
			sub.Unsubscribe()
		})
	}
}
