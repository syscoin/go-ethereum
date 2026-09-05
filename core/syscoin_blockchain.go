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
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
)

// SYSCOIN: save only the pre-block values of touched addresses. The raw accessor
// deduplicates them before reading; updates may touch the same key repeatedly.
func (bc *BlockChain) writeNEVMAddressUndo(batch ethdb.KeyValueWriter, block *types.Block) error {
	var addresses []common.Address
	var sysHash common.Hash
	if connect := block.NevmBlockConnect; connect != nil {
		sysHash = common.BytesToHash([]byte(connect.Sysblockhash))
		if connect.HasDiff() {
			for _, entry := range connect.Diff.AddedMNNEVM {
				addresses = append(addresses, common.BytesToAddress(entry.Address))
			}
			for _, entry := range connect.Diff.UpdatedMNNEVM {
				addresses = append(addresses, common.BytesToAddress(entry.OldAddress), common.BytesToAddress(entry.NewAddress))
			}
			for _, entry := range connect.Diff.RemovedMNNEVM {
				addresses = append(addresses, common.BytesToAddress(entry.Address))
			}
		}
	}
	return rawdb.WriteNEVMAddressUndo(batch, bc.db, block.NumberU64(), block.Hash(), sysHash, addresses)
}

// SYSCOIN: rewind metadata and all head markers together before replaying lost
// trie state. Caller holds chainmu. Block bodies/receipts are retained for Core
// to replay; this is local recovery, not an independent Core fork choice.
func (bc *BlockChain) rewindSyscoinHead(head, timestamp uint64, root common.Hash, repair bool) (uint64, error) {
	current := bc.CurrentBlock()
	if current == nil || bc.CurrentHeader().Hash() != current.Hash() || bc.CurrentSnapBlock().Hash() != current.Hash() {
		return 0, errors.New("inconsistent Syscoin head markers; rebuild Geth state explicitly")
	}
	target := current
	for (timestamp > 0 && target.Time > timestamp) || (timestamp == 0 && target.Number.Uint64() > head) {
		if target.Number.Sign() == 0 {
			return 0, errors.New("Syscoin rewind timestamp predates genesis")
		}
		target = bc.GetHeader(target.ParentHash, target.Number.Uint64()-1)
		if target == nil {
			return 0, errors.New("missing Syscoin rewind ancestor")
		}
	}
	var rootNumber uint64
	if bc.triedb.Scheme() == rawdb.PathScheme {
		target, rootNumber = bc.rewindPathHead(target, root, false)
	} else {
		target, rootNumber = bc.rewindHashHead(target, root)
	}
	number := target.Number.Uint64()
	if bc.GetCanonicalHash(number) != target.Hash() {
		return 0, errors.New("Syscoin rewind target is not canonical")
	}
	if number > 0 && bc.Config().IsSyscoin(target.Number) {
		sysHash := rawdb.ReadSYSHash(bc.db, number)
		if len(sysHash) != common.HashLength || common.BytesToHash(sysHash) == (common.Hash{}) {
			return 0, fmt.Errorf("missing Syscoin pairing at rewind target %d", number)
		}
	}
	if current.Number.Uint64()-number > rawdb.DataBlockLimit {
		return 0, errors.New("Syscoin rewind exceeds retained address history; rebuild Geth state explicitly")
	}
	stateAvailable := bc.HasState(target.Root)
	if !stateAvailable && !bc.stateRecoverable(target.Root) {
		return 0, errors.New("Syscoin rewind has no recoverable target state")
	}
	// A live caller must not change path-trie state before a metadata batch that
	// could fail. Startup has no execution consumers and can safely retry using
	// the unchanged journals/markers after a trie recovery or final-write error.
	if !stateAvailable && (!repair || bc.HasState(current.Root)) {
		return 0, errors.New("Syscoin trie recovery requires an offline restart")
	}
	if current.Hash() == target.Hash() {
		if !stateAvailable {
			return rootNumber, bc.triedb.Recover(target.Root)
		}
		return rootNumber, nil
	}
	frozen, err := bc.db.Ancients()
	if err == nil && frozen > number+1 {
		return 0, errors.New("Syscoin rewind crosses immutable ancient history; rebuild Geth state explicitly")
	}
	parent := bc.GetBlock(target.Hash(), number)
	if parent == nil {
		return 0, errors.New("missing Syscoin rewind target body")
	}
	batch := bc.hc.newSyscoinCacheBatch(bc.db.NewBatch())
	// Check and stage the final DA window once. Per-height DA undo cannot read
	// previous writes from an uncommitted batch. This also preflights the P2
	// history-floor failure before any head, trie, or metadata writes.
	if err := rawdb.RebuildDataHashIndex(batch, bc.db, number); err != nil {
		return 0, fmt.Errorf("preflight Syscoin DA rewind: %w", err)
	}
	for block := bc.GetBlock(current.Hash(), current.Number.Uint64()); ; {
		if block == nil {
			return 0, errors.New("missing Syscoin rewind block body")
		}
		if block.NumberU64() == number {
			if block.Hash() != target.Hash() {
				return 0, errors.New("Syscoin rewind target is not an ancestor")
			}
			break
		}
		n := block.NumberU64()
		if bc.GetCanonicalHash(n) != block.Hash() {
			return 0, errors.New("Syscoin rewind block is not canonical")
		}
		sysHash := rawdb.ReadSYSHash(bc.db, n)
		if bc.Config().IsSyscoin(block.Number()) && (len(sysHash) != common.HashLength || common.BytesToHash(sysHash) == (common.Hash{})) {
			return 0, fmt.Errorf("missing Syscoin pairing at block %d", n)
		}
		undo, err := rawdb.ReadNEVMAddressUndo(bc.db, n, block.Hash(), common.BytesToHash(sysHash))
		if err != nil {
			return 0, fmt.Errorf("preflight Syscoin address rewind: %w", err)
		}
		for _, entry := range undo {
			if len(entry.Previous) == 0 {
				bc.RemoveNEVMAddress(batch, entry.Address)
			} else {
				bc.StoreNEVMAddress(batch, entry.Address, binary.BigEndian.Uint32(entry.Previous))
			}
		}
		if err := rawdb.DeleteNEVMAddressUndo(batch, n); err != nil {
			return 0, err
		}
		rawdb.DeleteDataHashesJournal(batch, n)
		bc.DeleteSYSHash(batch, n)
		bc.DeleteBTCCheckpoint(batch, n)
		for _, tx := range block.Transactions() {
			rawdb.DeleteTxLookupEntry(batch, tx.Hash())
		}
		rawdb.DeleteCanonicalHash(batch, n)
		block = bc.GetBlock(block.ParentHash(), n-1)
	}
	bc.writeHeadBlockMarkers(batch, parent)
	finalized := bc.currentFinalBlock.Load()
	if finalized != nil && finalized.Number.Uint64() > number {
		rawdb.WriteFinalizedBlockHash(batch, common.Hash{})
	}
	if !stateAvailable {
		if err := bc.triedb.Recover(target.Root); err != nil {
			return 0, fmt.Errorf("recover Syscoin trie state: %w", err)
		}
	}
	bc.txLookupLock.Lock()
	defer bc.txLookupLock.Unlock()
	if err := batch.Write(); err != nil {
		return 0, fmt.Errorf("write Syscoin rewind batch: %w", err)
	}
	bc.publishHeadBlock(parent)
	bc.txLookupCache.Purge()
	if finalized != nil && finalized.Number.Uint64() > number {
		bc.currentFinalBlock.Store(nil)
		headFinalizedBlockGauge.Update(0)
	}
	if safe := bc.currentSafeBlock.Load(); safe != nil && safe.Number.Uint64() > number {
		bc.currentSafeBlock.Store(nil)
		headSafeBlockGauge.Update(0)
	}
	return rootNumber, nil
}

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
	// SYSCOIN: active-DB batches cannot remove canonical rows in the freezer.
	if frozen, err := bc.db.Ancients(); err == nil && frozen > currentNumber {
		return errors.New("Syscoin disconnect crosses immutable ancient history")
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
	if err := rawdb.DeleteNEVMAddressUndo(batch, currentNumber); err != nil {
		return err
	}
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
