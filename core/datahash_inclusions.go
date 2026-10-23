// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
)

const (
	MaxDataHashLookupHashes     = 64
	MaxDataHashLookupBlocks     = 1024
	DefaultDataHashLookupBlocks = 256
)

// DataHashInclusionCandidate is an untrusted locator for a Core block. Legacy
// journals can outlive a rewind or failed import, so callers must independently
// verify the Core block's contents and canonical finality before using it.
type DataHashInclusionCandidate struct {
	DataHash         common.Hash    `json:"dataHash"`
	NEVMBlockNumber  hexutil.Uint64 `json:"nevmBlockNumber"`
	NEVMBlockHash    common.Hash    `json:"nevmBlockHash"`
	SyscoinBlockHash common.Hash    `json:"syscoinBlockHash"`
}

type DataHashInclusionPage struct {
	ChainID      *hexutil.Big                 `json:"chainId"`
	HeadNumber   hexutil.Uint64               `json:"headNumber"`
	HeadHash     common.Hash                  `json:"headHash"`
	SearchedFrom *hexutil.Uint64              `json:"searchedFrom,omitempty"`
	SearchedTo   *hexutil.Uint64              `json:"searchedTo,omitempty"`
	Inclusions   []DataHashInclusionCandidate `json:"inclusions"`
	NextBefore   *hexutil.Uint64              `json:"nextBefore,omitempty"`
	Exhausted    bool                         `json:"exhausted"`
}

type dataHashInclusionReader interface {
	head() *types.Header
	chainID() *big.Int
	journal(uint64) ([]*common.Hash, error)
	canonicalHeader(uint64) *types.Header
	syscoinHash(uint64) ([]byte, error)
}

type dataHashInclusionChainReader struct{ chain *BlockChain }

func (r dataHashInclusionChainReader) head() *types.Header { return r.chain.CurrentBlock() }
func (r dataHashInclusionChainReader) chainID() *big.Int   { return r.chain.Config().ChainID }
func (r dataHashInclusionChainReader) journal(n uint64) ([]*common.Hash, error) {
	return rawdb.ReadDataHashLookupJournal(r.chain.db, n)
}
func (r dataHashInclusionChainReader) canonicalHeader(n uint64) *types.Header {
	return r.chain.GetHeaderByNumber(n)
}
func (r dataHashInclusionChainReader) syscoinHash(n uint64) ([]byte, error) {
	return rawdb.ReadDataHashLookupSYSHash(r.chain.db, n)
}

func validateDataHashLookup(hashes []common.Hash, maxBlocks uint64) error {
	if len(hashes) == 0 || len(hashes) > MaxDataHashLookupHashes {
		return fmt.Errorf("data hash lookup requires 1..%d hashes", MaxDataHashLookupHashes)
	}
	if maxBlocks == 0 || maxBlocks > MaxDataHashLookupBlocks {
		return fmt.Errorf("data hash lookup requires 1..%d blocks", MaxDataHashLookupBlocks)
	}
	seen := make(map[common.Hash]bool, len(hashes))
	for _, hash := range hashes {
		if hash == (common.Hash{}) || seen[hash] {
			return errors.New("data hash lookup requires nonzero unique hashes")
		}
		seen[hash] = true
	}
	return nil
}

// GetDataHashInclusions reads only the existing legacy journal. It never reads
// the positive LRU or changes consensus metadata, and does not assert inclusion.
func (bc *BlockChain) GetDataHashInclusions(ctx context.Context, hashes []common.Hash, before *uint64, maxBlocks uint64) (*DataHashInclusionPage, error) {
	if err := validateDataHashLookup(hashes, maxBlocks); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	locked, err := bc.chainmu.TryLockContext(ctx)
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, errChainStopped
	}
	defer bc.chainmu.Unlock()
	return readDataHashInclusions(ctx, dataHashInclusionChainReader{bc}, hashes, before, maxBlocks)
}

func readDataHashInclusions(ctx context.Context, reader dataHashInclusionReader, hashes []common.Hash, before *uint64, maxBlocks uint64) (*DataHashInclusionPage, error) {
	if err := validateDataHashLookup(hashes, maxBlocks); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	head := reader.head()
	if head == nil || head.Number == nil || !head.Number.IsUint64() {
		return nil, errors.New("data hash lookup has no valid canonical head")
	}
	chainID := reader.chainID()
	if chainID == nil || chainID.Sign() <= 0 {
		return nil, errors.New("data hash lookup has no valid chain ID")
	}
	page := &DataHashInclusionPage{
		ChainID:    (*hexutil.Big)(new(big.Int).Set(chainID)),
		HeadNumber: hexutil.Uint64(head.Number.Uint64()), HeadHash: head.Hash(),
		Inclusions: make([]DataHashInclusionCandidate, 0), Exhausted: true,
	}
	upper := head.Number.Uint64()
	if before != nil {
		if *before > upper {
			return nil, errors.New("data hash lookup cursor exceeds canonical head")
		}
		upper = *before
	}
	floor := uint64(1) // Genesis cannot contain a Core publication.
	if head.Number.Uint64() >= rawdb.DataBlockLimit {
		floor = head.Number.Uint64() - rawdb.DataBlockLimit + 1
	}
	if upper < floor {
		return page, nil
	}
	lower := floor
	if upper-floor >= maxBlocks {
		lower = upper - maxBlocks + 1
	}
	lo, hi := hexutil.Uint64(lower), hexutil.Uint64(upper)
	page.SearchedFrom, page.SearchedTo = &lo, &hi
	if lower > floor {
		next := hexutil.Uint64(lower - 1)
		page.NextBefore, page.Exhausted = &next, false
	}
	wanted := make(map[common.Hash]bool, len(hashes))
	for _, hash := range hashes {
		wanted[hash] = true
	}
	found := make(map[common.Hash]bool, len(hashes))
	for n := upper; ; n-- {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		journal, err := reader.journal(n)
		if err != nil {
			return nil, fmt.Errorf("read data hash journal %d: %w", n, err)
		}
		if len(journal) > 32 {
			return nil, fmt.Errorf("data hash journal %d exceeds Core block bound", n)
		}
		var matches []common.Hash
		for _, hash := range journal {
			if hash == nil {
				return nil, fmt.Errorf("nil data hash in journal %d", n)
			}
			if wanted[*hash] && !found[*hash] {
				matches = append(matches, *hash)
				found[*hash] = true
			}
		}
		if len(matches) != 0 {
			header := reader.canonicalHeader(n)
			if header == nil || header.Number == nil || !header.Number.IsUint64() || header.Number.Uint64() != n {
				return nil, fmt.Errorf("missing or inconsistent canonical header %d", n)
			}
			sysHash, err := reader.syscoinHash(n)
			if err != nil {
				return nil, fmt.Errorf("read Core block pairing %d: %w", n, err)
			}
			if len(sysHash) != common.HashLength || common.BytesToHash(sysHash) == (common.Hash{}) {
				return nil, fmt.Errorf("invalid Core block pairing %d", n)
			}
			// Core serializes uint256 least-significant byte first; its JSON RPC
			// displays the bytes in the opposite order.
			var displayHash common.Hash
			for i := range sysHash {
				displayHash[i] = sysHash[len(sysHash)-1-i]
			}
			for _, hash := range matches {
				page.Inclusions = append(page.Inclusions, DataHashInclusionCandidate{hash, hexutil.Uint64(n), header.Hash(), displayHash})
			}
		}
		if n == lower {
			break
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	current := reader.head()
	if current == nil || current.Hash() != page.HeadHash {
		return nil, errors.New("canonical head changed during data hash lookup")
	}
	return page, nil
}
