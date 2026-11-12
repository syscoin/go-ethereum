// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package ethdb

import "errors"

// SYSCOIN: KeyValueSyncer is an optional durable hot-storage barrier. The
// Database.Sync method belongs to AncientWriter and does not provide this.
type KeyValueSyncer interface {
	SyncKeyValue() error
}

// SyncKeyValue waits until all preceding key-value writes survive a crash.
// Unsupported (including memory-only) stores must never acknowledge durability.
func SyncKeyValue(db KeyValueStore) error {
	if syncer, ok := db.(KeyValueSyncer); ok {
		return syncer.SyncKeyValue()
	}
	return errors.New("key-value durability barrier unsupported")
}
