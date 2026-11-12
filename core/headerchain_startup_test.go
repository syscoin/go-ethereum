// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math"
	"math/big"
	"math/bits"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/triedb"
)

// Capture keys through exported writers rather than duplicating rawdb's schema.
type btcStartupKeyCapture struct{ key []byte }

func (c *btcStartupKeyCapture) Put(key, _ []byte) error {
	c.key = bytes.Clone(key)
	return nil
}

func (c *btcStartupKeyCapture) Delete([]byte) error {
	return errors.New("unexpected delete while capturing a checkpoint key")
}

func btcStartupLastKey() []byte {
	capture := new(btcStartupKeyCapture)
	rawdb.WriteBTCCheckpointLastIndex(capture, 0)
	return capture.key
}

func btcStartupHashKey(index uint64) []byte {
	capture := new(btcStartupKeyCapture)
	rawdb.WriteBTCCheckpointHashByIndex(capture, index, common.Hash{})
	return capture.key
}

type btcStartupTestDB struct {
	ethdb.Database
	faultKey   []byte
	faultErr   error
	faultValue []byte
	override   bool
	faultHits  int
	reads      int
	readLimit  int
	writes     []string
}

func (db *btcStartupTestDB) Get(key []byte) ([]byte, error) {
	db.reads++
	if db.readLimit > 0 && db.reads > db.readLimit {
		return nil, errors.New("checkpoint startup exceeded bounded read budget")
	}
	if bytes.Equal(key, db.faultKey) && (db.faultErr != nil || db.override) {
		db.faultHits++
		if db.faultErr != nil {
			return nil, db.faultErr
		}
		return bytes.Clone(db.faultValue), nil
	}
	return db.Database.Get(key)
}

func (db *btcStartupTestDB) Put(key, value []byte) error {
	db.writes = append(db.writes, "put:"+string(key))
	return db.Database.Put(key, value)
}

func (db *btcStartupTestDB) Delete(key []byte) error {
	db.writes = append(db.writes, "delete:"+string(key))
	return db.Database.Delete(key)
}

func (db *btcStartupTestDB) observeBatch(batch ethdb.Batch) ethdb.Batch {
	return &ethdb.HookedBatch{
		Batch:    batch,
		OnPut:    func(key, _ []byte) { db.writes = append(db.writes, "put:"+string(key)) },
		OnDelete: func(key []byte) { db.writes = append(db.writes, "delete:"+string(key)) },
	}
}

func (db *btcStartupTestDB) NewBatch() ethdb.Batch {
	return db.observeBatch(db.Database.NewBatch())
}

func (db *btcStartupTestDB) NewBatchWithSize(size int) ethdb.Batch {
	return db.observeBatch(db.Database.NewBatchWithSize(size))
}

func (db *btcStartupTestDB) resetObservations() {
	db.reads, db.faultHits = 0, 0
	db.writes = nil
}

func btcStartupContents(t *testing.T, db ethdb.Database) map[string]string {
	t.Helper()
	contents := make(map[string]string)
	iterator := db.NewIterator(nil, nil)
	defer iterator.Release()
	for iterator.Next() {
		contents[string(iterator.Key())] = string(iterator.Value())
	}
	if err := iterator.Error(); err != nil {
		t.Fatal(err)
	}
	return contents
}

func newBTCStartupTestDB(t *testing.T, last, present uint64, storeMarker bool) (*btcStartupTestDB, *Genesis) {
	t.Helper()
	db := &btcStartupTestDB{Database: rawdb.NewMemoryDatabase()}
	t.Cleanup(func() { db.Close() })
	genesis := &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: params.AllEthashProtocolChanges}
	trieDB := triedb.NewDatabase(db, nil)
	t.Cleanup(func() { trieDB.Close() })
	if _, err := genesis.Commit(db, trieDB); err != nil {
		t.Fatal(err)
	}
	for index := uint64(1); index <= present; index++ {
		hash := testBTCCheckpointHash(byte(index))
		rawdb.WriteBTCCheckpointHashByIndex(db, index, hash)
		rawdb.WriteBTCCheckpointIndexByHash(db, hash, index)
		rawdb.WriteBTCCheckpointIndexByBlockNumber(db, index+100, index)
	}
	if storeMarker {
		rawdb.WriteBTCCheckpointLastIndex(db, last)
	}
	db.resetObservations()
	return db, genesis
}

func checkBTCStartupIndex(t *testing.T, hc *HeaderChain, db ethdb.Database, want uint64) {
	t.Helper()
	if hc == nil || hc.ReadBTCCheckpointLastIndex() != want {
		t.Fatalf("constructor did not publish checkpoint index %d", want)
	}
	if got, err := rawdb.ReadBTCCheckpointLastIndexWithError(db); err != nil || got != want {
		t.Fatalf("persisted checkpoint index = %d, %v; want %d", got, err, want)
	}
}

func TestHeaderChainBTCCheckpointStartupReadFailures(t *testing.T) {
	// With a prefix through 10 and marker 16, exponential probing reaches 8,
	// then binary refinement reads 10. The intact-top case needs no repair.
	phases := []struct {
		name    string
		key     []byte
		present uint64
		size    int
	}{
		{"marker", btcStartupLastKey(), 10, 8},
		{"missing-top", btcStartupHashKey(16), 10, common.HashLength},
		{"exponential", btcStartupHashKey(8), 10, common.HashLength},
		{"binary", btcStartupHashKey(10), 10, common.HashLength},
		{"intact-top", btcStartupHashKey(16), 16, common.HashLength},
	}
	for _, phase := range phases {
		for _, mode := range []string{"io", "empty", "short", "long"} {
			t.Run(phase.name+"/"+mode, func(t *testing.T) {
				db, genesis := newBTCStartupTestDB(t, 16, phase.present, true)
				before := btcStartupContents(t, db)
				db.faultKey = phase.key
				readErr := errors.New("checkpoint source temporarily unavailable")
				if mode == "io" {
					db.faultErr = readErr
				} else {
					db.override = true
					size := 0
					if mode == "short" {
						size = phase.size - 1
					} else if mode == "long" {
						size = phase.size + 1
					}
					db.faultValue = make([]byte, size)
				}
				hc, err := NewHeaderChain(db, genesis.Config, ethash.NewFaker(), func() bool { return false })
				if hc != nil || err == nil {
					t.Fatalf("failed checkpoint read returned chain %p, error %v", hc, err)
				}
				if mode == "io" && !errors.Is(err, readErr) {
					t.Fatalf("constructor lost the source error: %v", err)
				}
				if mode != "io" && !strings.Contains(err.Error(), "invalid execution metadata length") {
					t.Fatalf("constructor lost the malformed-length error: %v", err)
				}
				if db.faultHits != 1 {
					t.Fatalf("targeted constructor read count = %d, want 1", db.faultHits)
				}
				if len(db.writes) != 0 || !maps.Equal(before, btcStartupContents(t, db)) {
					t.Fatal("failed constructor attempted a write or changed the database")
				}

				// The same persisted source remains usable after a healthy read.
				db.faultErr, db.override = nil, false
				db.resetObservations()
				hc, err = NewHeaderChain(db, genesis.Config, ethash.NewFaker(), func() bool { return false })
				if err != nil {
					t.Fatalf("healthy retry failed: %v", err)
				}
				checkBTCStartupIndex(t, hc, db, phase.present)
				var encoded [8]byte
				binary.BigEndian.PutUint64(encoded[:], phase.present)
				before[string(btcStartupLastKey())] = string(encoded[:])
				if !maps.Equal(before, btcStartupContents(t, db)) {
					t.Fatal("healthy retry changed state beyond the checkpoint marker")
				}
			})
		}
	}
}

func TestHeaderChainBTCCheckpointStartupTailRecovery(t *testing.T) {
	for _, test := range []struct {
		name        string
		last        uint64
		present     uint64
		storeMarker bool
		zeroHash    bool
	}{
		{"missing-marker", 0, 0, false, false},
		{"zero-marker", 0, 0, true, false},
		{"intact-tail", 16, 16, true, false},
		{"zero-valued-hash-is-present", 1, 1, true, true},
		{"missing-suffix", 16, 10, true, false},
		{"all-tail-missing", 16, 0, true, false},
		{"huge-index-with-prefix", math.MaxUint64, 10, true, false},
		{"huge-index-without-prefix", math.MaxUint64, 0, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, genesis := newBTCStartupTestDB(t, test.last, test.present, test.storeMarker)
			if test.zeroHash {
				rawdb.WriteBTCCheckpointHashByIndex(db, test.last, common.Hash{})
			}
			before := btcStartupContents(t, db)
			db.resetObservations()
			// Two logarithmic searches plus the fixed genesis/header reads.
			db.readLimit = 2*bits.Len64(test.last) + 16
			hc, err := NewHeaderChain(db, genesis.Config, ethash.NewFaker(), func() bool { return false })
			if err != nil {
				t.Fatal(err)
			}
			if db.reads > db.readLimit {
				t.Fatalf("startup used %d reads, limit %d", db.reads, db.readLimit)
			}
			checkBTCStartupIndex(t, hc, db.Database, test.present)
			if test.last != test.present {
				var encoded [8]byte
				binary.BigEndian.PutUint64(encoded[:], test.present)
				before[string(btcStartupLastKey())] = string(encoded[:])
				if len(db.writes) != 1 || db.writes[0] != "put:"+string(btcStartupLastKey()) {
					t.Fatalf("repair writes = %q, want only the last-index marker", db.writes)
				}
			} else if len(db.writes) != 0 {
				t.Fatalf("unchanged checkpoint state caused writes: %q", db.writes)
			}
			if !maps.Equal(before, btcStartupContents(t, db)) {
				t.Fatal("startup changed state beyond the expected checkpoint marker")
			}
		})
	}
}

func TestBlockChainBTCCheckpointStartupErrorPropagation(t *testing.T) {
	db, genesis := newBTCStartupTestDB(t, 16, 16, true)
	before := btcStartupContents(t, db)
	readErr := errors.New("checkpoint startup read failed")
	db.faultKey, db.faultErr = btcStartupHashKey(16), fmt.Errorf("backend lookup: %w", readErr)
	cache := DefaultCacheConfigWithScheme(rawdb.HashScheme)
	cache.SnapshotLimit = 0
	chain, err := NewBlockChain(db, cache, genesis, nil, ethash.NewFaker(), vm.Config{}, nil)
	if chain != nil {
		chain.Stop()
		t.Fatal("blockchain constructor returned a chain after checkpoint read failure")
	}
	if !errors.Is(err, readErr) || db.faultHits != 1 {
		t.Fatalf("blockchain constructor did not preserve checkpoint failure: %v, hits %d", err, db.faultHits)
	}
	if len(db.writes) != 0 || !maps.Equal(before, btcStartupContents(t, db)) {
		t.Fatal("failed blockchain startup changed the persisted source")
	}
	db.faultErr = nil
	chain, err = NewBlockChain(db, cache, genesis, nil, ethash.NewFaker(), vm.Config{}, nil)
	if err != nil {
		t.Fatalf("healthy blockchain startup failed: %v", err)
	}
	defer chain.Stop()
	checkBTCStartupIndex(t, chain.hc, db, 16)
}

func TestBlockChainBTCCheckpointStartupPathRetryReleasesHistory(t *testing.T) {
	db := &btcStartupTestDB{Database: openSyscoinRecoveryPathDB(t, t.TempDir())}
	genesis := &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: params.AllEthashProtocolChanges}
	cache := DefaultCacheConfigWithScheme(rawdb.PathScheme)
	cache.SnapshotLimit = 0
	seedTrie := triedb.NewDatabase(db, cache.triedbConfig(false))
	if _, err := genesis.Commit(db, seedTrie); err != nil {
		seedTrie.Close()
		t.Fatal(err)
	}
	// Seeding must not retain the state-history freezer that startup will open.
	if err := seedTrie.Close(); err != nil {
		t.Fatal(err)
	}
	hash := testBTCCheckpointHash(1)
	rawdb.WriteBTCCheckpointHashByIndex(db, 1, hash)
	rawdb.WriteBTCCheckpointIndexByHash(db, hash, 1)
	rawdb.WriteBTCCheckpointIndexByBlockNumber(db, 101, 1)
	rawdb.WriteBTCCheckpointLastIndex(db, 1)
	before := btcStartupContents(t, db)
	db.resetObservations()
	readErr := errors.New("path startup checkpoint read unavailable")
	db.faultKey, db.faultErr = btcStartupHashKey(1), readErr
	chain, err := NewBlockChain(db, cache, genesis, nil, ethash.NewFaker(), vm.Config{}, nil)
	if chain != nil {
		chain.Stop()
		t.Fatal("path blockchain constructor returned a chain after checkpoint read failure")
	}
	if !errors.Is(err, readErr) || db.faultHits != 1 {
		t.Fatalf("path blockchain constructor lost checkpoint failure: %v, hits %d", err, db.faultHits)
	}
	if len(db.writes) != 0 || !maps.Equal(before, btcStartupContents(t, db)) {
		t.Fatal("failed path blockchain startup changed the persisted source")
	}

	ancient, err := db.AncientDatadir()
	if err != nil || ancient == "" {
		t.Fatalf("disk-backed state-history directory unavailable: %q, %v", ancient, err)
	}
	// Check release through the error-returning freezer API before the retry:
	// a retained lock must fail this assertion without reaching pathdb's Crit.
	freezer, err := rawdb.NewStateFreezer(ancient, false, false)
	if err != nil {
		t.Fatalf("failed startup retained the state-history freezer lock: %v", err)
	}
	if err := freezer.Close(); err != nil {
		t.Fatal(err)
	}
	db.faultErr = nil
	chain, err = NewBlockChain(db, cache, genesis, nil, ethash.NewFaker(), vm.Config{}, nil)
	if err != nil {
		t.Fatalf("healthy path startup retry failed: %v", err)
	}
	defer chain.Stop()
	checkBTCStartupIndex(t, chain.hc, db, 1)
}
