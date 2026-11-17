// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package core

import (
	"bytes"
	"errors"
	"maps"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
)

type syscoinStartupReadDB struct {
	*btcStartupTestDB
	skipFaultReads int
	faultOnce      bool
}

func (db *syscoinStartupReadDB) Get(key []byte) ([]byte, error) {
	if bytes.Equal(key, db.faultKey) && db.skipFaultReads > 0 {
		db.skipFaultReads--
		return db.Database.Get(key)
	}
	data, err := db.btcStartupTestDB.Get(key)
	if bytes.Equal(key, db.faultKey) && db.faultOnce {
		db.faultErr, db.override = nil, false
	}
	return data, err
}

func (db *syscoinStartupReadDB) SyncKeyValue() error {
	return ethdb.SyncKeyValue(db.Database)
}

func TestSyscoinStartupRequiresExecutedHead(t *testing.T) {
	source := &syscoinDurabilityDB{Database: rawdb.NewMemoryDatabase()}
	t.Cleanup(func() { source.Close() })
	f := newSyscoinRecoveryFixture(t, rawdb.HashScheme, false, source)
	f.chain.Stop()
	tip := f.blocks[len(f.blocks)-1]
	keyFor := func(write func(ethdb.KeyValueWriter)) []byte {
		capture := new(btcStartupKeyCapture)
		write(capture)
		return capture.key
	}
	headKey := keyFor(func(db ethdb.KeyValueWriter) { rawdb.WriteHeadBlockHash(db, tip.Hash()) })
	genesisKey := keyFor(func(db ethdb.KeyValueWriter) { rawdb.WriteCanonicalHash(db, f.genesis.ToBlock().Hash(), 0) })
	configKey := keyFor(func(db ethdb.KeyValueWriter) {
		rawdb.WriteChainConfig(db, f.genesis.ToBlock().Hash(), f.genesis.Config)
	})
	for _, test := range []struct {
		name     string
		key      []byte
		skip     int
		once     bool
		missing  bool
		override bool
		value    []byte
	}{
		// Genesis setup must not overwrite an existing chain when its
		// initialization records cannot be loaded.
		{name: "genesis-mapping", key: genesisKey},
		{name: "genesis-config", key: configKey},
		{name: "missing-genesis-mapping", key: genesisKey, missing: true},
		{name: "missing-genesis-config", key: configKey, missing: true},
		{name: "short-genesis-mapping", key: genesisKey, override: true, value: []byte{1}},
		{name: "malformed-genesis-config", key: configKey, override: true, value: []byte("{")},
		{name: "executed-marker", key: headKey},
		{name: "header-number", key: keyFor(func(db ethdb.KeyValueWriter) { rawdb.WriteHeaderNumber(db, tip.Hash(), tip.NumberU64()) }), skip: 1},
		{name: "header", key: keyFor(func(db ethdb.KeyValueWriter) { rawdb.WriteHeader(db, tip.Header()) }), skip: 1},
		{name: "body", key: keyFor(func(db ethdb.KeyValueWriter) { rawdb.WriteBody(db, tip.Hash(), tip.NumberU64(), tip.Body()) })},
		{name: "canonical", key: keyFor(func(db ethdb.KeyValueWriter) { rawdb.WriteCanonicalHash(db, tip.Hash(), tip.NumberU64()) })},
		{name: "missing-executed-marker", key: headKey, override: true},
		{name: "short-executed-marker", key: headKey, override: true, value: tip.Hash().Bytes()[1:]},
		{name: "long-executed-marker", key: headKey, override: true, value: append([]byte{1}, tip.Hash().Bytes()...)},
		{name: "header-marker-mismatch", key: keyFor(func(db ethdb.KeyValueWriter) { rawdb.WriteHeadHeaderHash(db, tip.Hash()) }), override: true, value: f.genesis.ToBlock().Hash().Bytes()},
		{name: "missing-snap-marker", key: keyFor(func(db ethdb.KeyValueWriter) { rawdb.WriteHeadFastBlockHash(db, tip.Hash()) }), override: true},
		// The header constructor may fall back after one unavailable read, but
		// only the later successful executed-head load may choose the DA head.
		{name: "transient-header-constructor-read", key: headKey, once: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := &syscoinStartupReadDB{
				btcStartupTestDB: &btcStartupTestDB{
					Database: copySyscoinRecoveryDB(t, source), faultKey: test.key,
					override: test.override, faultValue: test.value,
				},
				skipFaultReads: test.skip, faultOnce: test.once,
			}
			if test.missing {
				if err := db.Database.Delete(test.key); err != nil {
					t.Fatal(err)
				}
			} else if !test.override {
				db.faultErr = errors.New("executed head temporarily unavailable")
			}
			before := btcStartupContents(t, db)
			chain, err := NewBlockChain(db, f.cache, f.genesis, nil, ethash.NewFaker(), vm.Config{}, nil)
			if !test.missing && db.faultHits == 0 {
				t.Fatal("startup did not read the unavailable record")
			}
			if test.once {
				if err != nil {
					t.Fatalf("startup after a successful head reread: %v", err)
				}
				defer chain.Stop()
				f.check(t, chain, db, tip.NumberU64())
				return
			}
			if chain != nil {
				chain.Stop()
				t.Fatal("startup accepted an unavailable or inconsistent executed head")
			}
			if err == nil {
				t.Fatal("startup did not report the head failure")
			}
			if len(db.writes) != 0 || !maps.Equal(before, btcStartupContents(t, db)) {
				t.Fatal("failed startup wrote metadata or changed the persisted DA index")
			}
			db.faultErr, db.override = nil, false
			if test.missing {
				original, err := source.Get(test.key)
				if err != nil {
					t.Fatal(err)
				}
				if err := db.Put(test.key, original); err != nil {
					t.Fatal(err)
				}
			}
			chain, err = NewBlockChain(db, f.cache, f.genesis, nil, ethash.NewFaker(), vm.Config{}, nil)
			if err != nil {
				t.Fatalf("healthy startup retry: %v", err)
			}
			defer chain.Stop()
			f.check(t, chain, db, tip.NumberU64())
		})
	}
}

func TestSyscoinGenesisStartupDAIndex(t *testing.T) {
	db := &syscoinDurabilityDB{Database: rawdb.NewMemoryDatabase()}
	defer db.Close()
	config := *params.AllEthashProtocolChanges
	config.SyscoinBlock = big.NewInt(0)
	genesis := &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: &config}
	cache := DefaultCacheConfigWithScheme(rawdb.HashScheme)
	cache.SnapshotLimit = 0
	for _, prunedBody := range []bool{false, true} {
		if prunedBody {
			rawdb.DeleteBody(db, genesis.ToBlock().Hash(), 0)
		}
		chain, err := NewBlockChain(db, cache, genesis, nil, ethash.NewFaker(), vm.Config{}, nil)
		if err != nil {
			t.Fatalf("genesis startup (pruned body %t): %v", prunedBody, err)
		}
		if chain.CurrentBlock().Hash() != genesis.ToBlock().Hash() {
			chain.Stop()
			t.Fatal("startup did not retain genesis as executed head")
		}
		// The versioned index must record a genesis head and retention floor.
		want := make([]byte, 17)
		want[0] = 1
		if got, err := db.Get([]byte("datahash-index-state")); err != nil || !bytes.Equal(got, want) {
			chain.Stop()
			t.Fatalf("genesis DA index = %x, %v; want %x", got, err, want)
		}
		chain.Stop()
	}
}

func TestGenesisStartupFromFreezer(t *testing.T) {
	for _, syscoin := range []bool{false, true} {
		name := "ethereum"
		if syscoin {
			name = "syscoin"
		}
		t.Run(name, func(t *testing.T) {
			db, err := rawdb.NewDatabaseWithFreezer(&syscoinDurabilityDB{Database: rawdb.NewMemoryDatabase()}, t.TempDir(), "", false)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			config := *params.AllEthashProtocolChanges
			if syscoin {
				config.SyscoinBlock = big.NewInt(0)
			}
			genesis := &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: &config}
			if _, err := rawdb.WriteAncientHeaderChain(db, []*types.Header{genesis.ToBlock().Header()}); err != nil {
				t.Fatal(err)
			}
			cache := DefaultCacheConfigWithScheme(rawdb.HashScheme)
			cache.SnapshotLimit = 0
			chain, err := NewBlockChain(db, cache, genesis, nil, ethash.NewFaker(), vm.Config{}, nil)
			if err != nil {
				t.Fatalf("startup with frozen genesis and empty key-value store: %v", err)
			}
			defer chain.Stop()
			if chain.CurrentBlock().Hash() != genesis.ToBlock().Hash() {
				t.Fatal("startup did not restore the frozen genesis")
			}
		})
	}
}
