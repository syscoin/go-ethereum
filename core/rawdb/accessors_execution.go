// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package rawdb

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
)

// readExecutionValue distinguishes legitimate absence from failed or malformed
// reads. Execution must not turn a local database failure into a different EVM
// result and then attribute the resulting state mismatch to the block.
func readExecutionValue(db ethdb.KeyValueReader, key []byte, size int) ([]byte, error) {
	data, err := db.Get(key)
	if errors.Is(err, ethdb.ErrKeyNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) != size {
		return nil, fmt.Errorf("invalid execution metadata length %d, want %d", len(data), size)
	}
	return data, nil
}

func ReadSYSHashWithError(db ethdb.KeyValueReader, n uint64) ([]byte, error) {
	return readExecutionValue(db, blockNumToSysKey(n), common.HashLength)
}

func GetNEVMAddressWithError(db ethdb.KeyValueReader, addr common.Address) ([]byte, error) {
	return readExecutionValue(db, nevmAddressKey(addr), 4)
}

func ReadBTCCheckpointIndexWithError(db ethdb.KeyValueReader, hash common.Hash) (uint64, error) {
	data, err := readExecutionValue(db, btcCheckpointH2IKey(hash), 8)
	if err != nil || data == nil {
		return 0, err
	}
	index := binary.BigEndian.Uint64(data)
	if index == 0 {
		return 0, errors.New("zero BTC checkpoint index")
	}
	return index, nil
}

func ReadBTCCheckpointHashWithError(db ethdb.KeyValueReader, index uint64) ([]byte, error) {
	return readExecutionValue(db, btcCheckpointI2HKey(index), common.HashLength)
}

func ReadBTCCheckpointLastIndexWithError(db ethdb.KeyValueReader) (uint64, error) {
	data, err := readExecutionValue(db, btcCheckpointLastKey, 8)
	if err != nil || data == nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(data), nil
}

func ReadDataHashWithError(db ethdb.KeyValueReader, hash common.Hash) ([]byte, error) {
	count, err := readDataHashRefCount(db, hash)
	if err != nil || count == 0 {
		return nil, err
	}
	return hash.Bytes(), nil
}
