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

// SYSCOIN: keep a restartable state well inside the retained metadata undo window,
// even when repeated writes to the same trie paths never fill the state buffer.
const syscoinCheckpointInterval = rawdb.DataBlockLimit / 2

// SYSCOIN: SyncSyscoinPair durably fences one exact published endpoint before
// Core forgets its crash-recovery request. sysHash uses serialized uint256 order.
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
	return bc.checkpointSyscoinHead()
}

// SYSCOIN: callers hold chainmu. Establish the baseline lazily before the first
// import after startup/rewind, then refresh it before metadata undo can expire.
// Checking each canonical block also covers large batches and known-block replay.
func (bc *BlockChain) maybeCheckpointSyscoinHead() error {
	if bc.chainConfig.SyscoinBlock == nil {
		return nil
	}
	head := bc.CurrentBlock()
	previous := bc.syscoinCheckpoint
	if previous != nil && head.Number.Uint64() >= previous.Number.Uint64() &&
		head.Number.Uint64()-previous.Number.Uint64() < syscoinCheckpointInterval {
		return nil
	}
	return bc.checkpointSyscoinHead()
}

// SYSCOIN: checkpoint the currently published head under chainmu. This internal
// operation also works before Syscoin activation, when no Core pairing exists;
// SyncSyscoinPair retains the stricter remote request validation above.
func (bc *BlockChain) checkpointSyscoinHead() error {
	head := bc.CurrentBlock()
	if head == nil {
		return errors.New("Syscoin durability fence missing head")
	}
	number := head.Number.Uint64()
	if number > 0 && bc.chainConfig.IsSyscoin(head.Number) {
		sysHash := rawdb.ReadSYSHash(bc.db, number)
		if len(sysHash) != common.HashLength || common.BytesToHash(sysHash) == (common.Hash{}) ||
			!bytes.Equal(bc.hc.ReadSYSHash(number), sysHash) {
			return errors.New("Syscoin durability fence paired hash mismatch")
		}
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
	bc.syscoinCheckpoint = head
	return nil
}
