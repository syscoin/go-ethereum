// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package rawdb

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
)

// SYSCOIN: retain address before-images for the same bounded recovery interval as
// DA. These are local recovery records, not consensus inputs or a second state DB.
const nevmAddressUndoVersion = 1

// NEVMAddressUndoEntry holds an address's value before a canonical block. An
// empty Previous means absent; four bytes preserve even a present zero height.
type NEVMAddressUndoEntry struct {
	Address  common.Address
	Previous []byte
}

type nevmAddressUndoRecord struct {
	Version  uint8
	NEVMHash common.Hash
	SYSHash  common.Hash
	Entries  []NEVMAddressUndoEntry
}

// WriteNEVMAddressUndo stages a block's before-images before its address changes.
// The caller must use the same atomic batch for this record, pruning, address
// changes and canonical markers, and discard that batch on any error.
func WriteNEVMAddressUndo(dbw ethdb.KeyValueWriter, dbr ethdb.KeyValueReader, number uint64, nevmHash, sysHash common.Hash, addresses []common.Address) error {
	key := nevmAddressUndoKey(number)
	if _, err := dbr.Get(key); err == nil {
		return fmt.Errorf("NEVM address undo already exists at block %d", number)
	} else if !errors.Is(err, ethdb.ErrKeyNotFound) {
		return fmt.Errorf("read NEVM address undo at block %d: %w", number, err)
	}
	record := nevmAddressUndoRecord{Version: nevmAddressUndoVersion, NEVMHash: nevmHash, SYSHash: sysHash}
	seen := make(map[common.Address]struct{}, len(addresses))
	for _, address := range addresses {
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		previous, err := dbr.Get(nevmAddressKey(address))
		if errors.Is(err, ethdb.ErrKeyNotFound) {
			previous = nil
		} else if err != nil {
			return fmt.Errorf("read NEVM address %s before block %d: %w", address, number, err)
		} else if len(previous) != 4 {
			return fmt.Errorf("invalid NEVM address %s value size %d before block %d", address, len(previous), number)
		}
		record.Entries = append(record.Entries, NEVMAddressUndoEntry{Address: address, Previous: previous})
	}
	encoded, err := rlp.EncodeToBytes(record)
	if err != nil {
		return err
	}
	if err := dbw.Put(key, encoded); err != nil {
		return err
	}
	if number >= DataBlockLimit {
		return DeleteNEVMAddressUndo(dbw, number-DataBlockLimit)
	}
	return nil
}

// ReadNEVMAddressUndo requires an exact committed block pair. Missing history is
// an error (wrapping ethdb.ErrKeyNotFound), distinct from an explicit empty record.
func ReadNEVMAddressUndo(db ethdb.KeyValueReader, number uint64, nevmHash, sysHash common.Hash) ([]NEVMAddressUndoEntry, error) {
	encoded, err := db.Get(nevmAddressUndoKey(number))
	if err != nil {
		return nil, fmt.Errorf("read NEVM address undo at block %d: %w", number, err)
	}
	var record nevmAddressUndoRecord
	if err := rlp.DecodeBytes(encoded, &record); err != nil {
		return nil, fmt.Errorf("invalid NEVM address undo at block %d: %w", number, err)
	}
	if record.Version != nevmAddressUndoVersion {
		return nil, fmt.Errorf("unsupported NEVM address undo version %d at block %d", record.Version, number)
	}
	if record.NEVMHash != nevmHash || record.SYSHash != sysHash {
		return nil, fmt.Errorf("NEVM address undo block pair mismatch at block %d", number)
	}
	seen := make(map[common.Address]struct{}, len(record.Entries))
	for _, entry := range record.Entries {
		if len(entry.Previous) != 0 && len(entry.Previous) != 4 {
			return nil, fmt.Errorf("invalid NEVM address undo value size %d at block %d", len(entry.Previous), number)
		}
		if _, exists := seen[entry.Address]; exists {
			return nil, fmt.Errorf("duplicate NEVM address undo entry at block %d", number)
		}
		seen[entry.Address] = struct{}{}
	}
	return record.Entries, nil
}

// DeleteNEVMAddressUndo removes a record in the block's atomic disconnect batch.
func DeleteNEVMAddressUndo(db ethdb.KeyValueWriter, number uint64) error {
	return db.Delete(nevmAddressUndoKey(number))
}
