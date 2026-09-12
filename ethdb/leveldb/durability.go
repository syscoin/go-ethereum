// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package leveldb

import (
	"fmt"

	"github.com/syndtr/goleveldb/leveldb/opt"
)

// SYSCOIN: LevelDB skips empty batches. A reserved, real synchronous write
// forces its WAL barrier, including all preceding asynchronous metadata writes.
func (db *Database) SyncKeyValue() error {
	if db.noSync {
		return fmt.Errorf("key-value durability disabled by LevelDB NoSync")
	}
	return db.db.Put([]byte("SyscoinDurabilityFence"), []byte{1}, &opt.WriteOptions{Sync: true})
}
