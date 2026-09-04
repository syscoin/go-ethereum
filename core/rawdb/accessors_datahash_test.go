// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package rawdb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
)

func testDataHash(tag byte) *common.Hash {
	hash := new(common.Hash)
	hash[31] = tag
	return hash
}

func testDataHashCount(t *testing.T, db ethdb.KeyValueReader, hash common.Hash) uint64 {
	t.Helper()
	count, err := readDataHashRefCount(db, hash)
	if err != nil {
		t.Fatal(err)
	}
	return count
}

func TestDataHashIndexMigratesLegacyPresenceToRefcounts(t *testing.T) {
	db := NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	shared, stale := testDataHash(0x11), testDataHash(0x12)
	if err := writeDataHashesRecord(db, 1, []*common.Hash{shared}); err != nil {
		t.Fatal(err)
	}
	if err := writeDataHashesRecord(db, 2, []*common.Hash{shared}); err != nil {
		t.Fatal(err)
	}
	if err := db.Put(dataHashKey(*shared), []byte{0}); err != nil {
		t.Fatal(err)
	}
	if err := db.Put(dataHashKey(*stale), []byte{0}); err != nil {
		t.Fatal(err)
	}

	if err := EnsureDataHashIndex(db, 2); err != nil {
		t.Fatal(err)
	}
	if got := testDataHashCount(t, db, *shared); got != 2 {
		t.Fatalf("shared refcount = %d, want 2", got)
	}
	if got := ReadDataHash(db, *stale); len(got) != 0 {
		t.Fatalf("stale legacy membership survived rebuild: %x", got)
	}
	state, initialized, err := readDataHashIndexState(db)
	if err != nil || !initialized || state.head != 2 || state.historyFloor != 0 {
		t.Fatalf("unexpected migrated state: %+v initialized=%v err=%v", state, initialized, err)
	}
}

func TestDataHashIndexDuplicateExpiryRollbackAndRestart(t *testing.T) {
	db := NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	shared, tip, replacement := testDataHash(0x21), testDataHash(0x22), testDataHash(0x23)
	if err := writeDataHashesRecord(db, 1, []*common.Hash{shared}); err != nil {
		t.Fatal(err)
	}
	if err := writeDataHashesRecord(db, 2, []*common.Hash{shared}); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDataHashIndex(db, DataBlockLimit); err != nil {
		t.Fatal(err)
	}

	WriteDataHashes(db, db, DataBlockLimit+1, []*common.Hash{tip})
	if got := testDataHashCount(t, db, *shared); got != 1 {
		t.Fatalf("newer duplicate was lost when block 1 expired: count=%d", got)
	}
	if got := ReadRawDataHashes(db, 1); len(got) != 1 || *got[0] != *shared {
		t.Fatalf("expired block journal was not retained: %v", got)
	}

	// SYSCOIN: retries are no-ops, not permission to replace canonical data.
	WriteDataHashes(db, db, DataBlockLimit+1, []*common.Hash{tip})
	if err := writeDataHashes(db, db, DataBlockLimit+1, []*common.Hash{replacement}); err == nil {
		t.Fatal("same-height replacement was accepted without a disconnect")
	}
	if got := testDataHashCount(t, db, *tip); got != 1 || len(ReadDataHash(db, *replacement)) != 0 {
		t.Fatalf("retry changed canonical membership: tip count=%d", got)
	}

	DeleteDataHashes(db, db, DataBlockLimit+1)
	if got := ReadDataHash(db, *tip); len(got) != 0 {
		t.Fatalf("disconnected tip membership survived: %x", got)
	}
	if got := testDataHashCount(t, db, *shared); got != 2 {
		t.Fatalf("rollback did not restore expired publication: count=%d", got)
	}

	WriteDataHashes(db, db, DataBlockLimit+1, nil)
	WriteDataHashes(db, db, DataBlockLimit+2, nil)
	if got := ReadDataHash(db, *shared); len(got) != 0 {
		t.Fatalf("hash survived expiry of its final publication: %x", got)
	}
	if err := EnsureDataHashIndex(db, DataBlockLimit+2); err != nil {
		t.Fatal(err)
	}
	if got := ReadDataHash(db, *shared); len(got) != 0 {
		t.Fatalf("restart rebuild changed expired membership: %x", got)
	}
}

func TestDataHashIndexBoundedHistoryFailsClosed(t *testing.T) {
	db := NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	old := testDataHash(0x31)
	if err := writeDataHashesRecord(db, 1, []*common.Hash{old}); err != nil {
		t.Fatal(err)
	}
	if err := writeDataHashIndexState(db, dataHashIndexState{head: 2 * DataBlockLimit}); err != nil {
		t.Fatal(err)
	}
	WriteDataHashes(db, db, 2*DataBlockLimit+1, nil)
	if got := ReadRawDataHashes(db, 1); len(got) != 0 {
		t.Fatalf("journal beyond bounded history was retained: %v", got)
	}
	state, _, err := readDataHashIndexState(db)
	if err != nil || state.historyFloor != 2 {
		t.Fatalf("history floor = %d, want 2 (err=%v)", state.historyFloor, err)
	}
	batch := db.NewBatch()
	if err := RebuildDataHashIndex(batch, db, DataBlockLimit); err == nil {
		t.Fatal("deep rewind rebuilt from unavailable history")
	}
}

type failingDataHashReader struct {
	ethdb.Database
	key []byte
	err error
}

func (db failingDataHashReader) Get(key []byte) ([]byte, error) {
	if bytes.Equal(key, db.key) {
		return nil, db.err
	}
	return db.Database.Get(key)
}

func TestDataHashIndexRebuildPropagatesJournalReadError(t *testing.T) {
	db := NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	hash := testDataHash(0x41)
	if err := writeDataHashesRecord(db, 1, []*common.Hash{hash}); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("journal read failed")
	reader := failingDataHashReader{Database: db, key: dataHashesKey(1), err: wantErr}
	if err := RebuildDataHashIndex(db.NewBatch(), reader, 1); !errors.Is(err, wantErr) {
		t.Fatalf("rebuild error = %v, want %v", err, wantErr)
	}
}

func TestDataHashIndexRebuildRejectsCanonicalHeadAdvance(t *testing.T) {
	db := NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	if err := EnsureDataHashIndex(db, 0); err != nil {
		t.Fatal(err)
	}
	if err := RebuildDataHashIndex(db.NewBatch(), db, 1); err == nil {
		t.Fatal("rebuild treated a missing canonical journal as an empty block")
	}
}

func TestDataHashIndexRejectsLegacyValueAfterMigration(t *testing.T) {
	db := NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	hash := testDataHash(0x51)
	if err := db.Put(dataHashKey(*hash), []byte{0}); err != nil {
		t.Fatal(err)
	}
	if _, err := readDataHashRefCount(db, *hash); err == nil {
		t.Fatal("legacy presence sentinel was accepted as a refcount")
	}
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], 1)
	if err := db.Put(dataHashKey(*hash), count[:]); err != nil {
		t.Fatal(err)
	}
	if got := testDataHashCount(t, db, *hash); got != 1 {
		t.Fatalf("refcount = %d, want 1", got)
	}
}
