// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package core

import (
	"bytes"
	"errors"
	"maps"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/syscoin/syscoinwire/syscoin/wire"
)

type checkpointRollbackDB struct {
	ethdb.Database
	mu          sync.RWMutex
	faultKey    []byte
	faultValue  []byte
	faultErr    error
	faultActive bool
	hits        atomic.Int32
	writes      atomic.Int32
	stagedKey   []byte
	staged      atomic.Int32
}

func (db *checkpointRollbackDB) Get(key []byte) ([]byte, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	if db.faultActive && bytes.Equal(key, db.faultKey) {
		db.hits.Add(1)
		return bytes.Clone(db.faultValue), db.faultErr
	}
	return db.Database.Get(key)
}

func (db *checkpointRollbackDB) fault(key, value []byte, err error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.faultKey, db.faultValue, db.faultErr = key, value, err
	db.faultActive = key != nil
	db.hits.Store(0)
}

type checkpointRollbackBatch struct {
	ethdb.Batch
	db *checkpointRollbackDB
}

func (db *checkpointRollbackDB) NewBatch() ethdb.Batch {
	return &checkpointRollbackBatch{Batch: db.Database.NewBatch(), db: db}
}

func (db *checkpointRollbackDB) NewBatchWithSize(size int) ethdb.Batch {
	return &checkpointRollbackBatch{Batch: db.Database.NewBatchWithSize(size), db: db}
}

func (b *checkpointRollbackBatch) Write() error {
	b.db.writes.Add(1)
	return b.Batch.Write()
}

func (b *checkpointRollbackBatch) Delete(key []byte) error {
	if bytes.Equal(key, b.db.stagedKey) {
		b.db.staged.Add(1)
	}
	return b.Batch.Delete(key)
}

func checkpointCarrierKey(number uint64) []byte {
	capture := new(btcStartupKeyCapture)
	rawdb.WriteBTCCheckpointIndexByBlockNumber(capture, number, 1)
	return capture.key
}

func checkpointRollbackRows(t *testing.T, db ethdb.Database) map[string][]byte {
	t.Helper()
	rows := make(map[string][]byte)
	it := db.NewIterator(nil, nil)
	defer it.Release()
	for it.Next() {
		rows[string(it.Key())] = bytes.Clone(it.Value())
	}
	if err := it.Error(); err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestSyscoinCheckpointRollbackReadFailure(t *testing.T) {
	readErr := errors.New("injected checkpoint read failure")
	for _, test := range []struct {
		name  string
		hash  bool
		value []byte
		err   error
	}{
		{"carrier-io", false, nil, readErr},
		{"carrier-short", false, make([]byte, 7), nil},
		{"carrier-long", false, make([]byte, 9), nil},
		{"carrier-zero", false, make([]byte, 8), nil},
		{"hash-io", true, nil, readErr},
		{"hash-short", true, make([]byte, 31), nil},
		{"hash-long", true, make([]byte, 33), nil},
		{"hash-zero", true, make([]byte, 32), nil},
		{"hash-missing", true, nil, ethdb.ErrKeyNotFound},
	} {
		for _, mode := range []string{"disconnect-hash", "disconnect-path", "rewind-lower-carrier"} {
			t.Run(mode+"/"+test.name, func(t *testing.T) {
				scheme := rawdb.HashScheme
				if mode == "disconnect-path" {
					scheme = rawdb.PathScheme
				}
				db := &checkpointRollbackDB{Database: rawdb.NewMemoryDatabase(), stagedKey: checkpointCarrierKey(3)}
				t.Cleanup(func() { db.Close() })
				f := newSyscoinRecoveryFixture(t, scheme, false, db)
				f.check(t, f.chain, db, 3) // Warm all metadata and transaction caches.
				checkCheckpointCache := func() {
					t.Helper()
					for i, hash := range f.btc {
						if index, ok := f.chain.hc.BTCCheckpointIndexCache.Get(hash); !ok || index != uint64(i+1) {
							t.Fatalf("checkpoint cache changed: hash=%s index=%d present=%t", hash, index, ok)
						}
					}
				}
				checkCheckpointCache()
				sys := []byte(f.blocks[2].NevmBlockConnect.Sysblockhash)
				if err := f.chain.SetSyscoinFinality(3, sys); err != nil {
					t.Fatal(err)
				}
				// Exact inverse of the fixture's block-three address changes.
				disconnect := &types.NEVMBlockDisconnect{Sysblockhash: string(sys), Diff: &wire.NEVMAddressDiff{
					RemovedMNNEVM: []wire.NEVMRemoveEntry{{Address: f.addr[0].Bytes()}},
					UpdatedMNNEVM: []wire.NEVMAddressUpdateEntry{{OldAddress: f.addr[1].Bytes(), NewAddress: f.addr[1].Bytes(), CollateralHeight: 20}},
				}}
				rollback := func() error { return f.chain.DisconnectSyscoinBlock(disconnect) }
				number, index := uint64(3), uint64(2)
				if mode == "rewind-lower-carrier" {
					// Height three's checkpoint and height two's non-carrier are
					// staged first; fail on the lower checkpoint before any commit.
					number, index = 1, 1
					rollback = func() error { return f.chain.SetHead(0) }
				}
				key := checkpointCarrierKey(number)
				if test.hash {
					key = btcStartupHashKey(index)
				}
				headEvents := make(chan ChainHeadEvent, 4)
				chainEvents := make(chan ChainEvent, 4)
				removed := make(chan RemovedLogsEvent, 4)
				added := make(chan []*types.Log, 4)
				for _, sub := range []interface{ Unsubscribe() }{
					f.chain.SubscribeChainHeadEvent(headEvents), f.chain.SubscribeChainEvent(chainEvents),
					f.chain.SubscribeRemovedLogsEvent(removed), f.chain.SubscribeLogsEvent(added),
				} {
					t.Cleanup(sub.Unsubscribe)
				}
				before := checkpointRollbackRows(t, db)
				writes, staged := db.writes.Load(), db.staged.Load()
				checkGeneration := f.chain.BeginSyscoinMetadataRead()
				db.fault(key, test.value, test.err)
				err := rollback()
				hits := db.hits.Load()
				db.fault(nil, nil, nil)
				if hits == 0 {
					t.Fatalf("rollback did not reach the intended checkpoint read: %v", err)
				}
				if err == nil {
					t.Error("checkpoint read fault was accepted as a successful rollback")
				} else {
					assertInvalidBlockClass(t, err, false)
					if test.err == readErr && !errors.Is(err, readErr) {
						t.Errorf("local read failure was not preserved: %v", err)
					}
				}
				if db.writes.Load() != writes || !maps.EqualFunc(before, checkpointRollbackRows(t, db), bytes.Equal) {
					t.Error("checkpoint read failure committed a partial rollback")
				}
				if len(headEvents) != 0 || len(chainEvents) != 0 || len(removed) != 0 || len(added) != 0 {
					t.Error("checkpoint read failure published rollback events")
				}
				if err := checkGeneration(); err != nil {
					t.Errorf("checkpoint preflight failure published a metadata generation: %v", err)
				}
				if mode == "rewind-lower-carrier" && db.staged.Load() == staged {
					t.Error("multi-height fixture did not stage the higher carrier before failing")
				}
				if err == nil {
					// The baseline already changed canonical state. Do not pretend
					// a retry from that different parent tests failure recovery.
					return
				}
				checkCheckpointCache() // Check membership separately from cache-backed reads.
				f.check(t, f.chain, db, 3)
				if f.chain.CurrentFinalBlock() == nil || f.chain.CurrentFinalBlock().Hash() != f.blocks[2].Hash() || !f.chain.HasState(f.blocks[2].Root()) {
					t.Fatal("rejected rollback changed finality or execution state")
				}
				if err := rollback(); err != nil {
					t.Fatalf("readable retry: %v", err)
				}
				if f.chain.CurrentFinalBlock() != nil {
					t.Error("successful rollback retained removed finality")
				}
				wantHead, wantLast := f.blocks[1], uint64(1)
				if mode == "rewind-lower-carrier" {
					wantHead, wantLast = f.genesis.ToBlock(), 0
				}
				if f.chain.CurrentBlock().Hash() != wantHead.Hash() || rawdb.ReadHeadBlockHash(db) != wantHead.Hash() || !f.chain.HasState(wantHead.Root()) {
					t.Fatal("successful retry did not publish the expected execution head")
				}
				if rawdb.ReadBTCCheckpointLastIndex(db) != wantLast || f.chain.ReadBTCCheckpointLastIndex() != wantLast {
					t.Fatal("retry left an incorrect checkpoint tail")
				}
				for i, hash := range f.btc {
					want := uint64(0)
					if i == 0 && wantLast != 0 {
						want = 1
					}
					if rawdb.ReadBTCCheckpointIndexByHash(db, hash) != want || f.chain.BTCCheckpointIndex(hash) != want ||
						(rawdb.ReadBTCCheckpointIndexByBlockNumber(db, uint64(2*i+1)) != 0) != (want != 0) ||
						(len(rawdb.ReadBTCCheckpointHashByIndex(db, uint64(i+1))) != 0) != (want != 0) {
						t.Error("retry left stale checkpoint rows or cache entries")
					}
				}
				if len(headEvents) != 1 || len(added) != 0 {
					t.Error("successful retry did not publish one head event without added logs")
				}
				if mode != "rewind-lower-carrier" {
					if len(chainEvents) != 1 || len(removed) != 1 {
						t.Error("successful disconnect did not publish its chain/removal events")
					}
					// Height two repeats checkpoint one but owns no carrier row.
					// It must disconnect without reading/deleting that retained hash.
					db.fault(btcStartupHashKey(1), nil, readErr)
					err := f.chain.DisconnectSyscoinBlock(&types.NEVMBlockDisconnect{
						Sysblockhash: f.blocks[1].NevmBlockConnect.Sysblockhash,
						Diff: &wire.NEVMAddressDiff{
							AddedMNNEVM:   []wire.NEVMAddressEntry{{Address: f.addr[2].Bytes(), CollateralHeight: 10}},
							UpdatedMNNEVM: []wire.NEVMAddressUpdateEntry{{OldAddress: f.addr[1].Bytes(), NewAddress: f.addr[0].Bytes(), CollateralHeight: 0}},
						},
					})
					hits := db.hits.Load()
					db.fault(nil, nil, nil)
					if err != nil || hits != 0 {
						t.Fatalf("no-carrier disconnect read the retained checkpoint: hits=%d err=%v", hits, err)
					}
					f.check(t, f.chain, db, 1)
				}
			})
		}
	}
}
