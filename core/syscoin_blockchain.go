// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
)

// SYSCOIN: DisconnectSyscoinBlock atomically rewinds one canonical Core/NEVM
// pair and its consensus-visible metadata. Events and in-memory head markers
// are published only after the database batch is durable.
func (bc *BlockChain) DisconnectSyscoinBlock(disconnect *types.NEVMBlockDisconnect) error {
	if disconnect == nil {
		return errors.New("nil Syscoin block disconnect")
	}
	if bc.chainConfig.SyscoinBlock == nil {
		return errors.New("Syscoin block disconnect on non-Syscoin chain")
	}
	if !bc.chainmu.TryLock() {
		return errChainStopped
	}
	defer bc.chainmu.Unlock()

	currentHeader := bc.CurrentBlock()
	if currentHeader == nil {
		return errors.New("current block is nil")
	}
	currentNumber := currentHeader.Number.Uint64()
	if currentNumber == 0 {
		return nil
	}
	disconnectHash := common.BytesToHash([]byte(disconnect.Sysblockhash))
	pairedSysHash := common.BytesToHash(bc.ReadSYSHash(currentNumber))
	if pairedSysHash == (common.Hash{}) || disconnectHash == (common.Hash{}) || pairedSysHash != disconnectHash {
		return fmt.Errorf("disconnect does not match current Core/NEVM pairing: tip=%d paired=%x disconnect=%x",
			currentNumber, pairedSysHash.Bytes()[:4], disconnectHash.Bytes()[:4])
	}
	current := bc.GetBlock(currentHeader.Hash(), currentNumber)
	if current == nil {
		return errors.New("current block body not found")
	}
	parent := bc.GetBlock(currentHeader.ParentHash, currentNumber-1)
	if parent == nil {
		return errors.New("parent block not found")
	}
	if bc.GetCanonicalHash(parent.NumberU64()) != parent.Hash() {
		return errors.New("parent block is not canonical")
	}
	batch := bc.hc.newSyscoinCacheBatch(bc.db.NewBatch())
	if err := bc.hc.TryDeleteDataHashes(batch, currentNumber); err != nil {
		return fmt.Errorf("cannot disconnect Syscoin DA membership at block %d: %w", currentNumber, err)
	}
	// SYSCOIN: replay cannot recover Core pairing metadata from block RLP. Fail
	// closed instead of invoking generic ancestor recovery outside this batch.
	if !bc.HasState(parent.Root()) {
		return errors.New("parent state unavailable for Syscoin disconnect")
	}

	removedLogs := bc.collectLogs(current, true)
	parentLogs := bc.collectLogs(parent, false)
	if disconnect.Diff != nil && disconnect.HasDiff() {
		for _, entry := range disconnect.Diff.AddedMNNEVM {
			bc.StoreNEVMAddress(batch, common.BytesToAddress(entry.Address), entry.CollateralHeight)
		}
		for _, entry := range disconnect.Diff.UpdatedMNNEVM {
			bc.RemoveNEVMAddress(batch, common.BytesToAddress(entry.OldAddress))
			bc.StoreNEVMAddress(batch, common.BytesToAddress(entry.NewAddress), entry.CollateralHeight)
		}
		for _, entry := range disconnect.Diff.RemovedMNNEVM {
			bc.RemoveNEVMAddress(batch, common.BytesToAddress(entry.Address))
		}
	}
	bc.DeleteSYSHash(batch, currentNumber)
	bc.DeleteBTCCheckpoint(batch, currentNumber)
	for _, tx := range current.Transactions() {
		rawdb.DeleteTxLookupEntry(batch, tx.Hash())
	}
	rawdb.DeleteCanonicalHash(batch, currentNumber)
	bc.writeHeadBlockMarkers(batch, parent)

	// Keep transaction lookups stable across the atomic database transition.
	bc.txLookupLock.Lock()
	if err := batch.Write(); err != nil {
		bc.txLookupLock.Unlock()
		return fmt.Errorf("write Syscoin disconnect batch: %w", err)
	}
	bc.publishHeadBlock(parent)
	bc.txLookupCache.Purge()
	bc.txLookupLock.Unlock()

	if len(removedLogs) > 0 {
		bc.rmLogsFeed.Send(RemovedLogsEvent{Logs: removedLogs})
	}
	bc.chainFeed.Send(ChainEvent{Header: parent.Header()})
	if len(parentLogs) > 0 {
		bc.logsFeed.Send(parentLogs)
	}
	bc.chainHeadFeed.Send(ChainHeadEvent{Header: parent.Header()})
	return nil
}
