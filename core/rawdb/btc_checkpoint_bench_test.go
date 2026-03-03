package rawdb

import (
	"encoding/binary"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/ethdb/pebble"
)

func benchBTCCheckpointPopulate(b testing.TB, db ethdb.Database, n uint64) []common.Hash {
	b.Helper()

	hashes := make([]common.Hash, 0, n)
	for i := uint64(1); i <= n; i++ {
		// Deterministic pseudo-hash for stable benchmarks.
		var h common.Hash
		binary.BigEndian.PutUint64(h[24:], i)
		hashes = append(hashes, h)
		WriteBTCCheckpointHashByIndex(db, i, h)
		WriteBTCCheckpointIndexByHash(db, h, i)
	}
	WriteBTCCheckpointLastIndex(db, n)
	return hashes
}

func BenchmarkBTCCheckpointReadHashByIndex_WarmPebble(b *testing.B) {
	dir := b.TempDir()
	kv, err := pebble.New(dir, 64, 64, "", false, false)
	if err != nil {
		b.Fatal(err)
	}
	db := NewDatabase(kv)
	defer db.Close()

	const (
		nTotal = uint64(1000)
		nRead  = uint64(100)
	)
	benchBTCCheckpointPopulate(b, db, nTotal)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for idx := uint64(1); idx <= nRead; idx++ {
			_ = ReadBTCCheckpointHashByIndex(db, idx)
		}
	}
}

func BenchmarkBTCCheckpointReadIndexByHash_WarmPebble(b *testing.B) {
	dir := b.TempDir()
	kv, err := pebble.New(dir, 64, 64, "", false, false)
	if err != nil {
		b.Fatal(err)
	}
	db := NewDatabase(kv)
	defer db.Close()

	const (
		nTotal = uint64(1000)
		nRead  = uint64(100)
	)
	hashes := benchBTCCheckpointPopulate(b, db, nTotal)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := uint64(0); j < nRead; j++ {
			_ = ReadBTCCheckpointIndexByHash(db, hashes[j])
		}
	}
}

func BenchmarkBTCCheckpointReadHashByIndex_ReopenPebble(b *testing.B) {
	dir := b.TempDir()

	// Populate once.
	{
		kv, err := pebble.New(dir, 64, 64, "", false, false)
		if err != nil {
			b.Fatal(err)
		}
		db := NewDatabase(kv)
		benchBTCCheckpointPopulate(b, db, 1000)
		db.Close()
	}

	const nRead = uint64(100)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		kv, err := pebble.New(dir, 64, 64, "", false, false)
		if err != nil {
			b.Fatal(err)
		}
		db := NewDatabase(kv)
		for idx := uint64(1); idx <= nRead; idx++ {
			_ = ReadBTCCheckpointHashByIndex(db, idx)
		}
		db.Close()
	}
}

