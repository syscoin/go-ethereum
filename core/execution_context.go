// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package core

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
)

// executionChainContext records the first failed execution read outside the
// StateDB. It belongs to one Process call, including system calls and rewards;
// it must never be shared with prefetchers or other block executions.
type executionChainContext struct {
	*HeaderChain
	err error
}

func (c *executionChainContext) fail(err error) {
	if c.err == nil && err != nil {
		c.err = fmt.Errorf("execution chain read: %w", err)
	}
}

func (c *executionChainContext) GetHeader(hash common.Hash, number uint64) *types.Header {
	header := c.HeaderChain.GetHeader(hash, number)
	if header == nil || header.Hash() != hash || header.Number.Uint64() != number {
		c.fail(fmt.Errorf("missing or inconsistent execution header %d (%s)", number, hash))
		return nil
	}
	return header
}

func (c *executionChainContext) ReadSYSHash(number uint64) []byte {
	data, ok := c.SYSHashCache.Get(number)
	if !ok {
		var err error
		data, err = rawdb.ReadSYSHashWithError(c.chainDb, number)
		c.fail(err)
	}
	// Genesis and pre-activation heights legitimately have no external pair.
	if number != 0 && c.Config().IsSyscoin(new(big.Int).SetUint64(number)) && len(data) != common.HashLength {
		c.fail(fmt.Errorf("missing Syscoin pair at height %d", number))
	}
	return data
}

func (c *executionChainContext) GetNEVMAddress(addr common.Address) []byte {
	if data, ok := c.NEVMAddressCache.Get(addr); ok {
		return data
	}
	data, err := rawdb.GetNEVMAddressWithError(c.chainDb, addr)
	c.fail(err)
	return data
}

func (c *executionChainContext) BTCCheckpointIndex(hash common.Hash) uint64 {
	if hash == (common.Hash{}) {
		return 0
	}
	if index, ok := c.BTCCheckpointIndexCache.Get(hash); ok {
		return index
	}
	index, err := rawdb.ReadBTCCheckpointIndexWithError(c.chainDb, hash)
	c.fail(err)
	if index > c.ReadBTCCheckpointLastIndex() {
		c.fail(fmt.Errorf("BTC checkpoint index %d exceeds current last index", index))
	}
	return index
}

func (c *executionChainContext) ReadBTCCheckpointHashByIndex(index uint64) []byte {
	if index == 0 || index > c.ReadBTCCheckpointLastIndex() {
		return nil
	}
	data, err := rawdb.ReadBTCCheckpointHashWithError(c.chainDb, index)
	c.fail(err)
	if len(data) != common.HashLength {
		c.fail(fmt.Errorf("missing BTC checkpoint hash at index %d", index))
	}
	return data
}

func (c *executionChainContext) ReadBTCCheckpointLastIndex() uint64 {
	index, err := rawdb.ReadBTCCheckpointLastIndexWithError(c.chainDb)
	c.fail(err)
	if index != c.BTCCheckpointLastIndex.Load() {
		c.fail(fmt.Errorf("inconsistent BTC checkpoint last index %d", index))
	}
	return index
}

func (c *executionChainContext) ReadDataHash(hash common.Hash) []byte {
	data, err := rawdb.ReadDataHashWithError(c.chainDb, hash)
	c.fail(err)
	return data
}
