// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package pebble

import "github.com/cockroachdb/pebble"

// SYSCOIN: a nonempty WAL record with Sync waits for all preceding writes.
// An empty batch is not a storage barrier; ordinary writes remain asynchronous.
func (d *Database) SyncKeyValue() error {
	d.quitLock.RLock()
	defer d.quitLock.RUnlock()
	if d.closed {
		return pebble.ErrClosed
	}
	return d.db.LogData([]byte("syscoin-durable-pair-v1"), pebble.Sync)
}
