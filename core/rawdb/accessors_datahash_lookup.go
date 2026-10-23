// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package rawdb

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
)

// ReadDataHashLookupJournal reads candidates without the consensus accessor's
// error-to-empty conversion. It neither repairs nor modifies the legacy index.
func ReadDataHashLookupJournal(db ethdb.KeyValueReader, number uint64) ([]*common.Hash, error) {
	key := dataHashesKey(number)
	exists, err := db.Has(key)
	if err != nil || !exists {
		return nil, err
	}
	data, err := db.Get(key)
	if err != nil {
		return nil, err
	}
	if len(data) > 32*33+16 {
		return nil, fmt.Errorf("oversized data hash journal at %d", number)
	}
	var hashes []*common.Hash
	if err := rlp.DecodeBytes(data, &hashes); err != nil {
		return nil, err
	}
	return hashes, nil
}

// ReadDataHashLookupSYSHash bypasses mutable caches for the read-only locator.
func ReadDataHashLookupSYSHash(db ethdb.KeyValueReader, number uint64) ([]byte, error) {
	return db.Get(blockNumToSysKey(number))
}
