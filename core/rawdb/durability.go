// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package rawdb

import "github.com/ethereum/go-ethereum/ethdb"

// SYSCOIN: preserve the optional hot-storage barrier across database wrappers.
func (db *nofreezedb) SyncKeyValue() error {
	return ethdb.SyncKeyValue(db.KeyValueStore)
}

func (db *freezerdb) SyncKeyValue() error {
	// Referenced ancient data must be stable before syncing hot head markers.
	if err := db.chainFreezer.Sync(); err != nil {
		return err
	}
	return ethdb.SyncKeyValue(db.KeyValueStore)
}

func (t *table) SyncKeyValue() error {
	return ethdb.SyncKeyValue(t.db)
}

// WriteTrieJournalChecked propagates a recovery checkpoint's write failure.
func WriteTrieJournalChecked(db ethdb.KeyValueWriter, journal []byte) error {
	return db.Put(trieJournalKey, journal)
}
