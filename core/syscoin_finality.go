// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package core

import (
	"bytes"
	"errors"

	"github.com/ethereum/go-ethereum/common"
)

// SetSyscoinFinality projects Core's accepted ChainLock onto an executed pair.
// Core verifies and persists the certificate. This runtime projection is replayed
// after restart and is independent of generic engine finality markers.
func (bc *BlockChain) SetSyscoinFinality(number uint64, sysHash []byte) error {
	if bc.chainConfig.SyscoinBlock == nil || number == 0 || len(sysHash) != common.HashLength || common.BytesToHash(sysHash) == (common.Hash{}) {
		return errors.New("invalid Syscoin finality pair")
	}
	if !bc.chainmu.TryLock() {
		return errChainStopped
	}
	defer bc.chainmu.Unlock()
	head := bc.currentBlock.Load()
	if head == nil || number > head.Number.Uint64() {
		return errors.New("Syscoin finality pair is not executed")
	}
	header := bc.GetHeaderByNumber(number)
	if header == nil || !bytes.Equal(bc.ReadSYSHash(number), sysHash) {
		return errors.New("Syscoin finality pair is not canonical")
	}
	if previous := bc.currentSyscoinFinalBlock.Load(); previous != nil {
		if number < previous.Number.Uint64() || (number == previous.Number.Uint64() && header.Hash() != previous.Hash()) {
			return errors.New("Syscoin finality update is stale or conflicting")
		}
		if header.Hash() == previous.Hash() {
			return nil
		}
	}
	bc.currentSyscoinFinalBlock.Store(header)
	return nil
}
