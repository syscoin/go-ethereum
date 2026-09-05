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

// SYSCOIN: commit expiry after a lookup captured its result. With Has+Get,
// deletion falls between the two reads; a single Get retains its valid snapshot.
type expiringDataHashReader struct {
	ethdb.Database
	expire             func()
	hasCalls, getCalls int
}

func (db *expiringDataHashReader) Has(key []byte) (bool, error) {
	db.hasCalls++
	exists, err := db.Database.Has(key)
	db.expire()
	return exists, err
}

func (db *expiringDataHashReader) Get(key []byte) ([]byte, error) {
	db.getCalls++
	value, err := db.Database.Get(key)
	db.expire()
	return value, err
}

func TestDataHashReadConcurrentExpiry(t *testing.T) {
	db := NewMemoryDatabase()
	defer db.Close()
	hash := *testDataHash(0x71)
	if err := db.Put(dataHashKey(hash), binary.BigEndian.AppendUint64(nil, 1)); err != nil {
		t.Fatal(err)
	}
	reader := &expiringDataHashReader{Database: db, expire: func() {
		batch := db.NewBatch()
		if err := batch.Delete(dataHashKey(hash)); err != nil {
			t.Fatal(err)
		}
		if err := batch.Write(); err != nil {
			t.Fatal(err)
		}
	}}
	count, err := readDataHashRefCount(reader, hash)
	if err != nil || count != 1 {
		t.Fatalf("expiry invalidated captured refcount: count=%d err=%v", count, err)
	}
	if reader.hasCalls != 0 || reader.getCalls != 1 {
		t.Fatalf("non-atomic lookup: Has=%d Get=%d", reader.hasCalls, reader.getCalls)
	}
	if got := ReadDataHash(db, hash); len(got) != 0 {
		t.Fatalf("expired hash still present: %x", got)
	}
}

func TestDataHashReadPreservesDatabaseAndEncodingErrors(t *testing.T) {
	db := NewMemoryDatabase()
	defer db.Close()
	hash := *testDataHash(0x72)
	wantErr := errors.New("data-hash I/O failure")
	reader := failingDataHashReader{Database: db, key: dataHashKey(hash), err: wantErr}
	if _, err := readDataHashRefCount(reader, hash); !errors.Is(err, wantErr) {
		t.Fatalf("missing key hid database error: %v", err)
	}
	for _, value := range [][]byte{nil, {0}, make([]byte, 8)} {
		if err := db.Put(dataHashKey(hash), value); err != nil {
			t.Fatal(err)
		}
		if _, err := readDataHashRefCount(db, hash); err == nil {
			t.Fatalf("invalid refcount accepted: %x", value)
		}
	}
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

// SYSCOIN: The legacy index retained only the current 50,001-block window.
// Its first disconnect needs one older journal, so migration must refuse that
// rollback without staging any partial index mutation.
func TestMigratedDataHashIndexUnavailableRollbackIsNonMutating(t *testing.T) {
	db := NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	head := uint64(DataBlockLimit + 1)
	tip := testDataHash(0x61)
	if err := writeDataHashesRecord(db, head, []*common.Hash{tip}); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDataHashIndex(db, head); err != nil {
		t.Fatal(err)
	}

	batch := db.NewBatch()
	if _, err := TryDeleteDataHashes(batch, db, head); err == nil {
		t.Fatal("migrated index accepted rollback below its retained-history floor")
	}
	// Even committing the rejected staging batch must be a no-op.
	if err := batch.Write(); err != nil {
		t.Fatal(err)
	}
	state, initialized, err := readDataHashIndexState(db)
	if err != nil || !initialized || state.head != head || state.historyFloor != 2 {
		t.Fatalf("index changed after rejected rollback: state=%+v initialized=%v err=%v", state, initialized, err)
	}
	if got := testDataHashCount(t, db, *tip); got != 1 {
		t.Fatalf("tip membership changed after rejected rollback: count=%d", got)
	}
	if got := ReadRawDataHashes(db, head); len(got) != 1 || *got[0] != *tip {
		t.Fatalf("tip journal changed after rejected rollback: %v", got)
	}
	// A restart at the unchanged canonical head remains valid.
	if err := EnsureDataHashIndex(db, head); err != nil {
		t.Fatalf("restart repair at unchanged head failed: %v", err)
	}

	// Advancing once moves the rollback target onto the retained migration-head
	// journal. The earlier rejected batch must not poison later progress.
	if err := writeDataHashes(db, db, head+1, nil); err != nil {
		t.Fatalf("append after rejected rollback: %v", err)
	}
	rollback := db.NewBatch()
	if _, err := TryDeleteDataHashes(rollback, db, head+1); err != nil {
		t.Fatalf("rollback after retained history advanced: %v", err)
	}
	if err := rollback.Write(); err != nil {
		t.Fatal(err)
	}
	state, initialized, err = readDataHashIndexState(db)
	if err != nil || !initialized || state.head != head || state.historyFloor != 2 {
		t.Fatalf("index after valid append/rollback: state=%+v initialized=%v err=%v", state, initialized, err)
	}
	if got := testDataHashCount(t, db, *tip); got != 1 {
		t.Fatalf("tip membership after valid append/rollback: count=%d", got)
	}
	if err := EnsureDataHashIndex(db, head); err != nil {
		t.Fatalf("restart repair after valid append/rollback failed: %v", err)
	}
}
