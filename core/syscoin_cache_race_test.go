package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
)

// SYSCOIN: delay a cold read after its DB snapshot, not before it. This models
// an RPC reader resuming after the block writer has committed newer metadata.
type delayedSyscoinReadDB struct {
	ethdb.Database
	armed    atomic.Bool
	captured chan struct{}
	release  chan struct{}
}

func TestSyscoinFailedDisconnectBatchPreservesCachesAndRetries(t *testing.T) {
	hc := newBTCCheckpointTestHeaderChain(t)
	t.Cleanup(func() { hc.chainDb.Close() })
	addr := common.HexToAddress("0x1234")
	btcHash := common.HexToHash("0x5678")
	hc.StoreNEVMAddress(hc.chainDb, addr, 10)
	hc.WriteSYSHash(hc.chainDb, "sys", 1)
	hc.WriteBTCCheckpoint(hc.chainDb, 1, btcHash)
	hc.WriteDataHashes(hc.chainDb, 1, []*common.Hash{&btcHash})
	check := func(present bool) {
		t.Helper()
		if (len(hc.GetNEVMAddress(addr)) > 0) != present ||
			(len(hc.ReadSYSHash(1)) > 0) != present ||
			(hc.BTCCheckpointIndex(btcHash) == 1) != present ||
			(hc.ReadBTCCheckpointLastIndex() == 1) != present ||
			(len(hc.ReadBTCCheckpointHashByIndex(1)) > 0) != present ||
			(len(hc.ReadDataHash(btcHash)) > 0) != present {
			t.Fatal("metadata cache visibility does not match successful commit")
		}
		if (len(rawdb.GetNEVMAddress(hc.chainDb, addr)) > 0) != present ||
			(len(rawdb.ReadSYSHash(hc.chainDb, 1)) > 0) != present ||
			(rawdb.ReadBTCCheckpointIndexByHash(hc.chainDb, btcHash) == 1) != present ||
			(rawdb.ReadBTCCheckpointLastIndex(hc.chainDb) == 1) != present {
			t.Fatal("persisted metadata does not match successful commit")
		}
	}
	disconnect := func(batch ethdb.Batch) {
		hc.RemoveNEVMAddress(batch, addr)
		hc.DeleteSYSHash(batch, 1)
		hc.DeleteBTCCheckpoint(batch, 1)
		hc.DeleteDataHashes(batch, 1)
	}
	failErr := errors.New("disconnect write failure")
	failed := hc.newSyscoinCacheBatch(&failingBTCCheckpointBatch{Batch: hc.chainDb.NewBatch(), err: failErr})
	disconnect(failed)
	check(true)
	if err := failed.Write(); !errors.Is(err, failErr) {
		t.Fatalf("expected failed disconnect, got %v", err)
	}
	check(true)
	// Exercise the exported constructor used by Ethereum.DeleteBlock as well.
	bc := &BlockChain{db: hc.chainDb, hc: hc}
	retry := bc.NewSyscoinCacheBatch()
	disconnect(retry)
	check(true)
	if err := retry.Write(); err != nil {
		t.Fatal(err)
	}
	check(false)
}

func (db *delayedSyscoinReadDB) Get(key []byte) ([]byte, error) {
	value, err := db.Database.Get(key)
	if db.armed.CompareAndSwap(true, false) {
		close(db.captured)
		<-db.release
	}
	return value, err
}

func TestSyscoinColdReadCannotOverwriteCommittedCache(t *testing.T) {
	addr := common.HexToAddress("0x1234")
	btcHash := common.HexToHash("0x5678")
	encodeIndex := func(idx uint64) []byte {
		return binary.BigEndian.AppendUint64(nil, idx)
	}
	for _, test := range []struct {
		name   string
		seed   func(*HeaderChain)
		read   func(*HeaderChain) []byte
		mutate func(*HeaderChain, ethdb.KeyValueWriter)
		want   []byte
	}{
		{
			name: "NEVM address replacement",
			seed: func(hc *HeaderChain) { hc.StoreNEVMAddress(hc.chainDb, addr, 10) },
			read: func(hc *HeaderChain) []byte { return hc.GetNEVMAddress(addr) },
			mutate: func(hc *HeaderChain, db ethdb.KeyValueWriter) {
				hc.StoreNEVMAddress(db, addr, 20)
			},
			want: []byte{0, 0, 0, 20},
		},
		{
			name: "NEVM address removal",
			seed: func(hc *HeaderChain) { hc.StoreNEVMAddress(hc.chainDb, addr, 10) },
			read: func(hc *HeaderChain) []byte { return hc.GetNEVMAddress(addr) },
			mutate: func(hc *HeaderChain, db ethdb.KeyValueWriter) {
				hc.RemoveNEVMAddress(db, addr)
			},
		},
		{
			name: "SYS hash replacement",
			seed: func(hc *HeaderChain) { hc.WriteSYSHash(hc.chainDb, "old", 10) },
			read: func(hc *HeaderChain) []byte { return hc.ReadSYSHash(10) },
			mutate: func(hc *HeaderChain, db ethdb.KeyValueWriter) {
				hc.WriteSYSHash(db, "new", 10)
			},
			want: []byte("new"),
		},
		{
			name: "SYS hash removal",
			seed: func(hc *HeaderChain) { hc.WriteSYSHash(hc.chainDb, "old", 10) },
			read: func(hc *HeaderChain) []byte { return hc.ReadSYSHash(10) },
			mutate: func(hc *HeaderChain, db ethdb.KeyValueWriter) {
				hc.DeleteSYSHash(db, 10)
			},
		},
		{
			name: "BTC checkpoint removal",
			seed: func(hc *HeaderChain) { hc.WriteBTCCheckpoint(hc.chainDb, 10, btcHash) },
			read: func(hc *HeaderChain) []byte { return encodeIndex(hc.BTCCheckpointIndex(btcHash)) },
			mutate: func(hc *HeaderChain, db ethdb.KeyValueWriter) {
				hc.DeleteBTCCheckpoint(db, 10)
			},
			want: encodeIndex(0),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			hc := newBTCCheckpointTestHeaderChain(t)
			t.Cleanup(func() { hc.chainDb.Close() })
			test.seed(hc)
			hc.NEVMAddressCache.Purge()
			hc.SYSHashCache.Purge()
			hc.BTCCheckpointIndexCache.Purge()
			db := &delayedSyscoinReadDB{
				Database: hc.chainDb,
				captured: make(chan struct{}),
				release:  make(chan struct{}),
			}
			hc.chainDb = db
			db.armed.Store(true)
			readDone := make(chan []byte, 1)
			go func() { readDone <- test.read(hc) }()
			select {
			case <-db.captured:
			case <-time.After(5 * time.Second):
				close(db.release)
				t.Fatal("cold read did not capture its old database value")
			}
			batch := hc.newSyscoinCacheBatch(db.NewBatch())
			test.mutate(hc, batch)
			err := batch.Write()
			// The old reader may return its pre-commit snapshot; what must not
			// happen is poisoning subsequent reads after the commit completed.
			close(db.release)
			<-readDone
			if err != nil {
				t.Fatal(err)
			}
			if got := test.read(hc); !bytes.Equal(got, test.want) {
				t.Fatalf("delayed old read poisoned committed cache: got %x, want %x", got, test.want)
			}
		})
	}
}
