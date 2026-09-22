// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package core

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
)

// A repeated Core checkpoint must not allocate a new index if its duplicate
// lookup fails after EVM execution. The LOG0 transaction in this fixture does
// not read BTC metadata, so this exercises the canonical commit boundary.
func TestSyscoinCheckpointConnectReadFailure(t *testing.T) {
	readErr := errors.New("injected checkpoint duplicate lookup failure")
	for _, scheme := range []string{rawdb.HashScheme, rawdb.PathScheme} {
		for _, fault := range []struct {
			name  string
			value []byte
			err   error
		}{
			{"io", nil, readErr},
			{"short", make([]byte, 7), nil},
			{"long", make([]byte, 9), nil},
			{"zero", make([]byte, 8), nil},
		} {
			t.Run(scheme+"/"+fault.name, func(t *testing.T) {
				db := &checkpointRollbackDB{Database: &syscoinDurabilityDB{Database: rawdb.NewMemoryDatabase()}}
				t.Cleanup(func() { db.Close() })
				f := newSyscoinRecoveryFixture(t, scheme, false, db)
				if err := f.chain.SetHead(1); err != nil {
					t.Fatal(err)
				}
				f.check(t, f.chain, db, 1)
				if index, ok := f.chain.hc.BTCCheckpointIndexCache.Get(f.btc[0]); !ok || index != 1 {
					t.Fatalf("fixture checkpoint cache = %d/%t, want 1/true", index, ok)
				}
				capture := new(btcStartupKeyCapture)
				rawdb.WriteBTCCheckpointIndexByHash(capture, f.btc[0], 1)
				headEvents := make(chan ChainHeadEvent, 4)
				chainEvents := make(chan ChainEvent, 4)
				logs := make(chan []*types.Log, 4)
				for _, sub := range []interface{ Unsubscribe() }{
					f.chain.SubscribeChainHeadEvent(headEvents), f.chain.SubscribeChainEvent(chainEvents),
					f.chain.SubscribeLogsEvent(logs),
				} {
					t.Cleanup(sub.Unsubscribe)
				}
				checkGeneration := f.chain.BeginSyscoinMetadataRead()
				db.fault(capture.key, fault.value, fault.err)
				_, err := f.chain.InsertChain(f.blocks[1:2])
				hits := db.hits.Load()
				db.fault(nil, nil, nil)
				if hits == 0 {
					t.Fatalf("connect did not reach duplicate checkpoint lookup: %v", err)
				}
				if err == nil {
					t.Errorf("checkpoint read failure accepted: head=%d lastIndex=%d duplicateIndex=%d carrierIndex=%d",
						f.chain.CurrentBlock().Number.Uint64(), f.chain.ReadBTCCheckpointLastIndex(),
						rawdb.ReadBTCCheckpointIndexByHash(db, f.btc[0]), rawdb.ReadBTCCheckpointIndexByBlockNumber(db, 2))
				} else {
					assertInvalidBlockClass(t, err, false)
					if fault.err == readErr && !errors.Is(err, readErr) {
						t.Errorf("local read error was not preserved: %v", err)
					}
				}
				if len(headEvents) != 0 || len(chainEvents) != 0 || len(logs) != 0 {
					t.Error("checkpoint read failure published canonical events")
				}
				if err := checkGeneration(); err != nil {
					t.Errorf("checkpoint read failure published metadata: %v", err)
				}
				if err == nil {
					return // The baseline changed the parent; this is not a valid retry state.
				}
				if index, ok := f.chain.hc.BTCCheckpointIndexCache.Get(f.btc[0]); !ok || index != 1 {
					t.Errorf("failed connect changed warm checkpoint cache: %d/%t", index, ok)
				}
				f.check(t, f.chain, db, 1)
				if _, err := f.chain.InsertChain(f.blocks[1:2]); err != nil {
					t.Fatalf("readable duplicate retry: %v", err)
				}
				if f.chain.CurrentBlock().Hash() != f.blocks[1].Hash() || rawdb.ReadBTCCheckpointLastIndex(db) != 1 ||
					f.chain.ReadBTCCheckpointLastIndex() != 1 || f.chain.BTCCheckpointIndex(f.btc[0]) != 1 ||
					rawdb.ReadBTCCheckpointIndexByHash(db, f.btc[0]) != 1 || rawdb.ReadBTCCheckpointIndexByBlockNumber(db, 2) != 0 {
					t.Fatal("duplicate retry changed the checkpoint index")
				}
				if len(headEvents) != 1 || len(chainEvents) != 1 || len(logs) != 1 {
					t.Fatal("readable retry did not publish exactly one block and its log")
				}
				if _, err := f.chain.InsertChain(f.blocks[2:]); err != nil {
					t.Fatalf("new checkpoint after duplicate retry: %v", err)
				}
				f.check(t, f.chain, db, 3)
			})
		}
	}
}
