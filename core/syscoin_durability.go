// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package core

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
)

// SYSCOIN: SyncSyscoinPair durably fences one exact published endpoint before
// Core forgets its crash-recovery request. Ordinary imports and disconnects do
// not pay this cost. sysHash uses the serialized uint256 byte order.
func (bc *BlockChain) SyncSyscoinPair(number uint64, sysHash []byte) error {
	if bc.chainConfig.SyscoinBlock == nil {
		return errors.New("Syscoin durability fence on non-Syscoin chain")
	}
	if !bc.chainmu.TryLock() {
		return errChainStopped
	}
	defer bc.chainmu.Unlock()

	head := bc.CurrentBlock()
	if head == nil || head.Number.Uint64() != number || len(sysHash) != common.HashLength {
		return errors.New("Syscoin durability fence count mismatch")
	}
	if number == 0 {
		if common.BytesToHash(sysHash) != (common.Hash{}) {
			return errors.New("Syscoin durability fence genesis hash mismatch")
		}
	} else if common.BytesToHash(sysHash) == (common.Hash{}) ||
		!bytes.Equal(rawdb.ReadSYSHash(bc.db, number), sysHash) ||
		!bytes.Equal(bc.hc.ReadSYSHash(number), sysHash) {
		return errors.New("Syscoin durability fence paired hash mismatch")
	}
	// Authenticate both published and stored markers under the operation lock.
	if bc.CurrentHeader() == nil || bc.CurrentSnapBlock() == nil ||
		bc.CurrentHeader().Hash() != head.Hash() || bc.CurrentSnapBlock().Hash() != head.Hash() ||
		rawdb.ReadHeadHeaderHash(bc.db) != head.Hash() || rawdb.ReadHeadBlockHash(bc.db) != head.Hash() ||
		rawdb.ReadHeadFastBlockHash(bc.db) != head.Hash() || rawdb.ReadCanonicalHash(bc.db, number) != head.Hash() {
		return errors.New("Syscoin durability fence inconsistent head markers")
	}
	if !bc.HasState(head.Root) {
		return errors.New("Syscoin durability fence state unavailable")
	}
	// Header/pair durability alone is insufficient: startup otherwise rewinds
	// to an older trie and loses the endpoint whose recovery record was erased.
	if err := bc.triedb.Checkpoint(head.Root); err != nil {
		return fmt.Errorf("checkpoint Syscoin endpoint state: %w", err)
	}
	if err := ethdb.SyncKeyValue(bc.db); err != nil {
		return fmt.Errorf("sync Syscoin endpoint storage: %w", err)
	}
	return nil
}
