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
	"github.com/ethereum/go-ethereum/rlp"
)

func TestNEVMAddressUndoRoundTrip(t *testing.T) {
	db := NewMemoryDatabase()
	defer db.Close()
	nevm, sys := common.HexToHash("0x11"), common.HexToHash("0x22")
	absent, zero, present := common.HexToAddress("0x1"), common.HexToAddress("0x2"), common.HexToAddress("0x3")
	StoreNEVMAddress(db, zero, make([]byte, 4))
	StoreNEVMAddress(db, present, binary.BigEndian.AppendUint32(nil, 42))
	batch := db.NewBatch()
	if err := WriteNEVMAddressUndo(batch, db, 1, nevm, sys, []common.Address{absent, zero, present, present, absent}); err != nil {
		t.Fatal(err)
	}
	// SYSCOIN: before-images and new values become durable together, and repeated
	// touches in a block must not replace an address's pre-block value.
	for _, address := range []common.Address{absent, zero, present} {
		StoreNEVMAddress(batch, address, binary.BigEndian.AppendUint32(nil, 100))
	}
	if _, err := ReadNEVMAddressUndo(db, 1, nevm, sys); !errors.Is(err, ethdb.ErrKeyNotFound) {
		t.Fatalf("uncommitted record visible: %v", err)
	}
	if err := batch.Write(); err != nil {
		t.Fatal(err)
	}
	entries, err := ReadNEVMAddressUndo(db, 1, nevm, sys)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[0].Address != absent || len(entries[0].Previous) != 0 ||
		entries[1].Address != zero || !bytes.Equal(entries[1].Previous, make([]byte, 4)) ||
		entries[2].Address != present || !bytes.Equal(entries[2].Previous, binary.BigEndian.AppendUint32(nil, 42)) {
		t.Fatalf("wrong before-images: %+v", entries)
	}
	if err := WriteNEVMAddressUndo(db.NewBatch(), db, 1, nevm, sys, nil); err == nil {
		t.Fatal("existing before-images overwritten")
	}
	for _, pair := range [][2]common.Hash{{sys, sys}, {nevm, nevm}} {
		if _, err := ReadNEVMAddressUndo(db, 1, pair[0], pair[1]); err == nil {
			t.Fatal("wrong block pair accepted")
		}
	}
	if err := DeleteNEVMAddressUndo(db, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadNEVMAddressUndo(db, 1, nevm, sys); !errors.Is(err, ethdb.ErrKeyNotFound) {
		t.Fatalf("deleted record accepted: %v", err)
	}
	if err := WriteNEVMAddressUndo(db, db, 1, nevm, sys, nil); err != nil {
		t.Fatal(err)
	}
	if entries, err := ReadNEVMAddressUndo(db, 1, nevm, sys); err != nil || len(entries) != 0 {
		t.Fatalf("explicit empty record missing: %+v, %v", entries, err)
	}
}

func TestNEVMAddressUndoRejectsMalformedRecords(t *testing.T) {
	db := NewMemoryDatabase()
	defer db.Close()
	nevm, sys := common.HexToHash("0x11"), common.HexToHash("0x22")
	address := common.HexToAddress("0x1")
	valid := nevmAddressUndoRecord{Version: nevmAddressUndoVersion, NEVMHash: nevm, SYSHash: sys}
	encode := func(record nevmAddressUndoRecord) []byte {
		t.Helper()
		value, err := rlp.EncodeToBytes(record)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	badVersion, badValue, duplicate := valid, valid, valid
	badVersion.Version++
	badValue.Entries = []NEVMAddressUndoEntry{{Address: address, Previous: []byte{1}}}
	duplicate.Entries = []NEVMAddressUndoEntry{{Address: address}, {Address: address}}
	for name, data := range map[string][]byte{
		"empty": nil, "not-list": {0x80}, "truncated": encode(valid)[:5],
		"trailing": append(encode(valid), 0), "version": encode(badVersion),
		"value": encode(badValue), "duplicate": encode(duplicate),
	} {
		t.Run(name, func(t *testing.T) {
			if err := db.Put(nevmAddressUndoKey(1), data); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadNEVMAddressUndo(db, 1, nevm, sys); err == nil || errors.Is(err, ethdb.ErrKeyNotFound) {
				t.Fatalf("malformed record misclassified: %v", err)
			}
			if err := WriteNEVMAddressUndo(db.NewBatch(), db, 1, nevm, sys, nil); err == nil {
				t.Fatal("malformed existing record overwritten")
			}
		})
	}
}

type nevmUndoFailReader struct {
	ethdb.KeyValueReader
	key []byte
	err error
}

func (db nevmUndoFailReader) Get(key []byte) ([]byte, error) {
	if bytes.Equal(key, db.key) {
		return nil, db.err
	}
	return db.KeyValueReader.Get(key)
}

type nevmUndoFailBatch struct {
	ethdb.Batch
	op  string
	err error
}

func (b nevmUndoFailBatch) Put(key, value []byte) error {
	if b.op == "put" {
		return b.err
	}
	return b.Batch.Put(key, value)
}

func (b nevmUndoFailBatch) Delete(key []byte) error {
	if b.op == "delete" {
		return b.err
	}
	return b.Batch.Delete(key)
}

func (b nevmUndoFailBatch) Write() error {
	if b.op == "write" {
		return b.err
	}
	return b.Batch.Write()
}

func TestNEVMAddressUndoStorageFailures(t *testing.T) {
	db := NewMemoryDatabase()
	defer db.Close()
	nevm, sys := common.HexToHash("0x11"), common.HexToHash("0x22")
	address := common.HexToAddress("0x1")
	wantErr := errors.New("undo I/O failure")
	for _, key := range [][]byte{nevmAddressUndoKey(1), nevmAddressKey(address)} {
		batch := db.NewBatch()
		reader := nevmUndoFailReader{KeyValueReader: db, key: key, err: wantErr}
		if err := WriteNEVMAddressUndo(batch, reader, 1, nevm, sys, []common.Address{address}); !errors.Is(err, wantErr) {
			t.Fatalf("write hid read error: %v", err)
		}
		if batch.ValueSize() != 0 {
			t.Fatal("read failure staged partial writes")
		}
	}
	reader := nevmUndoFailReader{KeyValueReader: db, key: nevmAddressUndoKey(1), err: wantErr}
	if _, err := ReadNEVMAddressUndo(reader, 1, nevm, sys); !errors.Is(err, wantErr) {
		t.Fatalf("read hid I/O error: %v", err)
	}
	for _, data := range [][]byte{nil, {1}, make([]byte, 5)} {
		if err := db.Put(nevmAddressKey(address), data); err != nil {
			t.Fatal(err)
		}
		batch := db.NewBatch()
		if err := WriteNEVMAddressUndo(batch, db, 1, nevm, sys, []common.Address{address}); err == nil {
			t.Fatalf("invalid present address value accepted: %x", data)
		}
		if batch.ValueSize() != 0 {
			t.Fatal("malformed address staged partial writes")
		}
	}
	StoreNEVMAddress(db, address, make([]byte, 4))
	if err := WriteNEVMAddressUndo(db, db, 1, nevm, sys, nil); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"put", "delete", "write"} {
		t.Run(op, func(t *testing.T) {
			batch := nevmUndoFailBatch{Batch: db.NewBatch(), op: op, err: wantErr}
			err := WriteNEVMAddressUndo(batch, db, DataBlockLimit+1, nevm, sys, []common.Address{address})
			if op == "write" {
				if err != nil {
					t.Fatal(err)
				}
				StoreNEVMAddress(batch, address, binary.BigEndian.AppendUint32(nil, 100))
				err = batch.Write()
			}
			if !errors.Is(err, wantErr) {
				t.Fatalf("write failure lost: %v", err)
			}
			// Discard errored batches, just as the canonical writer must.
			if _, err := ReadNEVMAddressUndo(db, DataBlockLimit+1, nevm, sys); !errors.Is(err, ethdb.ErrKeyNotFound) {
				t.Fatalf("failed batch persisted record: %v", err)
			}
			if _, err := ReadNEVMAddressUndo(db, 1, nevm, sys); err != nil {
				t.Fatalf("failed batch pruned old record: %v", err)
			}
			if got := GetNEVMAddress(db, address); !bytes.Equal(got, make([]byte, 4)) {
				t.Fatalf("failed batch changed address: %x", got)
			}
		})
	}
}

func TestNEVMAddressUndoPruning(t *testing.T) {
	db := NewMemoryDatabase()
	defer db.Close()
	nevm, sys := common.HexToHash("0x11"), common.HexToHash("0x22")
	for _, height := range []uint64{1, 2, DataBlockLimit} {
		if err := WriteNEVMAddressUndo(db, db, height, nevm, sys, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ReadNEVMAddressUndo(db, 1, nevm, sys); err != nil {
		t.Fatalf("oldest in-window record pruned early: %v", err)
	}
	batch := db.NewBatch()
	if err := WriteNEVMAddressUndo(batch, db, DataBlockLimit+1, nevm, sys, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadNEVMAddressUndo(db, 1, nevm, sys); err != nil {
		t.Fatalf("record pruned before commit: %v", err)
	}
	if err := batch.Write(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadNEVMAddressUndo(db, 1, nevm, sys); !errors.Is(err, ethdb.ErrKeyNotFound) {
		t.Fatalf("expired record retained: %v", err)
	}
	for _, height := range []uint64{2, DataBlockLimit, DataBlockLimit + 1} {
		if _, err := ReadNEVMAddressUndo(db, height, nevm, sys); err != nil {
			t.Fatalf("in-window record missing at %d: %v", height, err)
		}
	}
}
