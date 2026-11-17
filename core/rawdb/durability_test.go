// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package rawdb

import (
	"errors"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
)

type durableKVProbe struct {
	ethdb.KeyValueStore
	events *[]string
	err    error
}

func (p *durableKVProbe) SyncKeyValue() error {
	*p.events = append(*p.events, "kv")
	return p.err
}

type durableAncientProbe struct {
	ethdb.AncientStore
	events *[]string
	err    error
}

func (p *durableAncientProbe) Sync() error {
	*p.events = append(*p.events, "ancient")
	return p.err
}

// SYSCOIN: freezer Sync alone is never the hot-database fence, and an ancient
// error must prevent acknowledgement even if the hot backend could sync.
func TestDurabilityWrapperOrdering(t *testing.T) {
	failure := errors.New("injected storage failure")
	for _, failAncient := range []bool{false, true} {
		var events []string
		kv := &durableKVProbe{KeyValueStore: memorydb.New(), events: &events}
		defer kv.Close()
		ancient := &durableAncientProbe{events: &events}
		if failAncient {
			ancient.err = failure
		}
		db := &freezerdb{KeyValueStore: kv, chainFreezer: &chainFreezer{AncientStore: ancient}}
		if err := ethdb.SyncKeyValue(NewTable(db, "test")); errors.Is(err, failure) != failAncient {
			t.Fatalf("freezer fence error %v, failAncient=%v", err, failAncient)
		}
		want := []string{"ancient", "kv"}
		if failAncient {
			want = want[:1]
		}
		if !reflect.DeepEqual(events, want) {
			t.Fatalf("barrier events %v, want %v", events, want)
		}
	}
	var events []string
	kv := &durableKVProbe{KeyValueStore: memorydb.New(), events: &events, err: failure}
	defer kv.Close()
	if err := ethdb.SyncKeyValue(NewTable(NewDatabase(kv), "test")); !errors.Is(err, failure) {
		t.Fatalf("hot storage failure lost across wrappers: %v", err)
	}
	if !reflect.DeepEqual(events, []string{"kv"}) {
		t.Fatalf("non-freezer fence events %v", events)
	}
	unsupported := NewMemoryDatabase()
	defer unsupported.Close()
	if err := ethdb.SyncKeyValue(NewTable(unsupported, "test")); err == nil {
		t.Fatal("memory database acknowledged crash durability")
	}
}
