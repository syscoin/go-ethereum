// Copyright 2020 The go-ethereum Authors
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
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/triedb"
)

func verifyUnbrokenCanonchain(hc *HeaderChain) error {
	h := hc.CurrentHeader()
	for {
		canonHash := rawdb.ReadCanonicalHash(hc.chainDb, h.Number.Uint64())
		if exp := h.Hash(); canonHash != exp {
			return fmt.Errorf("Canon hash chain broken, block %d got %x, expected %x",
				h.Number, canonHash[:8], exp[:8])
		}
		if h.Number.Uint64() == 0 {
			break
		}
		h = hc.GetHeader(h.ParentHash, h.Number.Uint64()-1)
	}
	return nil
}

func testInsert(t *testing.T, hc *HeaderChain, chain []*types.Header, wantStatus WriteStatus, wantErr error) {
	t.Helper()

	status, err := hc.InsertHeaderChain(chain, time.Now())
	if status != wantStatus {
		t.Errorf("wrong write status from InsertHeaderChain: got %v, want %v", status, wantStatus)
	}
	// Always verify that the header chain is unbroken
	if err := verifyUnbrokenCanonchain(hc); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("unexpected error from InsertHeaderChain: %v", err)
	}
}

// This test checks status reporting of InsertHeaderChain.
func TestHeaderInsertion(t *testing.T) {
	var (
		db    = rawdb.NewMemoryDatabase()
		gspec = &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: params.AllEthashProtocolChanges}
	)
	gspec.Commit(db, triedb.NewDatabase(db, nil))
	hc, err := NewHeaderChain(db, gspec.Config, ethash.NewFaker(), func() bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	// chain A: G->A1->A2...A128
	genDb, chainA := makeHeaderChainWithGenesis(gspec, 128, ethash.NewFaker(), 10)
	// chain B: G->A1->B1...B128
	chainB := makeHeaderChain(gspec.Config, chainA[0], 128, ethash.NewFaker(), genDb, 10)

	// Inserting 64 headers on an empty chain, expecting
	// 1 callbacks, 1 canon-status, 0 sidestatus,
	testInsert(t, hc, chainA[:64], CanonStatTy, nil)

	// Inserting 64 identical headers, expecting
	// 0 callbacks, 0 canon-status, 0 sidestatus,
	testInsert(t, hc, chainA[:64], NonStatTy, nil)

	// Inserting the same some old, some new headers
	// 1 callbacks, 1 canon, 0 side
	testInsert(t, hc, chainA[32:96], CanonStatTy, nil)

	// Inserting headers from chain B, overtaking the canon chain blindly
	testInsert(t, hc, chainB[0:32], CanonStatTy, nil)

	// Inserting more headers on chain B, but we don't have the parent
	testInsert(t, hc, chainB[34:36], NonStatTy, consensus.ErrUnknownAncestor)

	// Inserting more headers on chain B, extend the canon chain
	testInsert(t, hc, chainB[32:97], CanonStatTy, nil)

	// Inserting more headers on chain A, taking back the canonicality
	testInsert(t, hc, chainA[90:100], CanonStatTy, nil)

	// And B becomes canon again
	testInsert(t, hc, chainB[97:107], CanonStatTy, nil)

	// And B becomes even longer
	testInsert(t, hc, chainB[107:128], CanonStatTy, nil)
}

func newBTCCheckpointTestHeaderChain(t *testing.T) *HeaderChain {
	t.Helper()

	db := rawdb.NewMemoryDatabase()
	gspec := &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: params.AllEthashProtocolChanges}
	gspec.Commit(db, triedb.NewDatabase(db, nil))

	hc, err := NewHeaderChain(db, gspec.Config, ethash.NewFaker(), func() bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	return hc
}

func testBTCCheckpointHash(tag byte) common.Hash {
	var h common.Hash
	h[31] = tag
	return h
}

func TestHeaderChainBTCCheckpointTailRollback(t *testing.T) {
	hc := newBTCCheckpointTestHeaderChain(t)
	db := hc.chainDb

	h1 := testBTCCheckpointHash(1)
	h2 := testBTCCheckpointHash(2)
	h3 := testBTCCheckpointHash(3)

	hc.WriteBTCCheckpoint(db, 100, h1)
	hc.WriteBTCCheckpoint(db, 101, h2)
	hc.WriteBTCCheckpoint(db, 102, h3)

	if got := hc.ReadBTCCheckpointLastIndex(); got != 3 {
		t.Fatalf("unexpected last index after writes: got %d want %d", got, 3)
	}
	if got := rawdb.ReadBTCCheckpointLastIndex(db); got != 3 {
		t.Fatalf("unexpected persisted last index after writes: got %d want %d", got, 3)
	}
	if got := rawdb.ReadBTCCheckpointIndexByBlockNumber(db, 102); got != 3 {
		t.Fatalf("unexpected block->index mapping at tip: got %d want %d", got, 3)
	}

	hc.DeleteBTCCheckpoint(db, 102)
	if got := hc.ReadBTCCheckpointLastIndex(); got != 2 {
		t.Fatalf("unexpected last index after first tail delete: got %d want %d", got, 2)
	}
	if got := rawdb.ReadBTCCheckpointLastIndex(db); got != 2 {
		t.Fatalf("unexpected persisted last index after first tail delete: got %d want %d", got, 2)
	}
	if got := rawdb.ReadBTCCheckpointIndexByBlockNumber(db, 102); got != 0 {
		t.Fatalf("unexpected removed block->index mapping: got %d want %d", got, 0)
	}
	if got := common.BytesToHash(rawdb.ReadBTCCheckpointHashByIndex(db, 3)); got != (common.Hash{}) {
		t.Fatalf("unexpected hash left at removed index 3: got %x", got)
	}
	if got := rawdb.ReadBTCCheckpointIndexByHash(db, h3); got != 0 {
		t.Fatalf("unexpected hash->index mapping left for removed hash: got %d want %d", got, 0)
	}
	if got := common.BytesToHash(rawdb.ReadBTCCheckpointHashByIndex(db, 2)); got != h2 {
		t.Fatalf("unexpected hash at index 2 after tail delete: got %x want %x", got, h2)
	}

	hc.DeleteBTCCheckpoint(db, 101)
	if got := hc.ReadBTCCheckpointLastIndex(); got != 1 {
		t.Fatalf("unexpected last index after second tail delete: got %d want %d", got, 1)
	}
	if got := common.BytesToHash(rawdb.ReadBTCCheckpointHashByIndex(db, 1)); got != h1 {
		t.Fatalf("unexpected hash at surviving index 1: got %x want %x", got, h1)
	}

	hc.DeleteBTCCheckpoint(db, 100)
	if got := hc.ReadBTCCheckpointLastIndex(); got != 0 {
		t.Fatalf("unexpected last index after deleting boundary index 1: got %d want %d", got, 0)
	}
	if got := rawdb.ReadBTCCheckpointLastIndex(db); got != 0 {
		t.Fatalf("unexpected persisted last index after deleting boundary index 1: got %d want %d", got, 0)
	}
	// Non-existent block deletion should remain a no-op.
	hc.DeleteBTCCheckpoint(db, 999)
	if got := hc.ReadBTCCheckpointLastIndex(); got != 0 {
		t.Fatalf("unexpected last index after no-op delete: got %d want %d", got, 0)
	}
}

func TestHeaderChainBTCCheckpointDuplicateHashNoop(t *testing.T) {
	hc := newBTCCheckpointTestHeaderChain(t)
	db := hc.chainDb

	h1 := testBTCCheckpointHash(0x11)
	hc.WriteBTCCheckpoint(db, 200, h1)

	if got := hc.ReadBTCCheckpointLastIndex(); got != 1 {
		t.Fatalf("unexpected last index after first write: got %d want %d", got, 1)
	}
	if got := rawdb.ReadBTCCheckpointIndexByBlockNumber(db, 200); got != 1 {
		t.Fatalf("unexpected block->index mapping for first write: got %d want %d", got, 1)
	}

	// Duplicate hash on a later block should be ignored.
	hc.WriteBTCCheckpoint(db, 201, h1)
	if got := hc.ReadBTCCheckpointLastIndex(); got != 1 {
		t.Fatalf("duplicate hash changed last index: got %d want %d", got, 1)
	}
	if got := rawdb.ReadBTCCheckpointIndexByBlockNumber(db, 201); got != 0 {
		t.Fatalf("duplicate hash created unexpected block->index mapping: got %d want %d", got, 0)
	}

	// Same behavior should hold within one batch before writes are flushed to chainDb.
	h2 := testBTCCheckpointHash(0x22)
	batch := db.NewBatch()
	hc.WriteBTCCheckpoint(batch, 300, h2)
	hc.WriteBTCCheckpoint(batch, 301, h2)
	if err := batch.Write(); err != nil {
		t.Fatalf("failed to flush batch: %v", err)
	}
	if got := hc.ReadBTCCheckpointLastIndex(); got != 2 {
		t.Fatalf("duplicate hash in batch changed last index: got %d want %d", got, 2)
	}
	if got := rawdb.ReadBTCCheckpointIndexByBlockNumber(db, 300); got != 2 {
		t.Fatalf("unexpected block->index mapping for batch write: got %d want %d", got, 2)
	}
	if got := rawdb.ReadBTCCheckpointIndexByBlockNumber(db, 301); got != 0 {
		t.Fatalf("duplicate hash in batch created unexpected block->index mapping: got %d want %d", got, 0)
	}

	// Zero hash should remain a no-op.
	hc.WriteBTCCheckpoint(db, 400, common.Hash{})
	if got := hc.ReadBTCCheckpointLastIndex(); got != 2 {
		t.Fatalf("zero hash write changed last index: got %d want %d", got, 2)
	}
	if got := rawdb.ReadBTCCheckpointIndexByBlockNumber(db, 400); got != 0 {
		t.Fatalf("zero hash write created unexpected block->index mapping: got %d want %d", got, 0)
	}
}

func TestHeaderChainBTCCheckpointReorgSwitch(t *testing.T) {
	hc := newBTCCheckpointTestHeaderChain(t)
	db := hc.chainDb

	old1 := testBTCCheckpointHash(0x31)
	old2 := testBTCCheckpointHash(0x32)
	hc.WriteBTCCheckpoint(db, 500, old1)
	hc.WriteBTCCheckpoint(db, 501, old2)
	if got := hc.ReadBTCCheckpointLastIndex(); got != 2 {
		t.Fatalf("unexpected last index after old branch writes: got %d want %d", got, 2)
	}

	// Reorg disconnect of old tail branch.
	hc.DeleteBTCCheckpoint(db, 501)
	hc.DeleteBTCCheckpoint(db, 500)
	if got := hc.ReadBTCCheckpointLastIndex(); got != 0 {
		t.Fatalf("unexpected last index after old branch tail delete: got %d want %d", got, 0)
	}
	if got := rawdb.ReadBTCCheckpointIndexByHash(db, old1); got != 0 {
		t.Fatalf("old branch hash old1 still indexed: got %d want %d", got, 0)
	}
	if got := rawdb.ReadBTCCheckpointIndexByHash(db, old2); got != 0 {
		t.Fatalf("old branch hash old2 still indexed: got %d want %d", got, 0)
	}

	// Reorg connect of new branch over same block numbers.
	new1 := testBTCCheckpointHash(0x41)
	new2 := testBTCCheckpointHash(0x42)
	hc.WriteBTCCheckpoint(db, 500, new1)
	hc.WriteBTCCheckpoint(db, 501, new2)

	if got := hc.ReadBTCCheckpointLastIndex(); got != 2 {
		t.Fatalf("unexpected last index after new branch writes: got %d want %d", got, 2)
	}
	if got := rawdb.ReadBTCCheckpointIndexByBlockNumber(db, 500); got != 1 {
		t.Fatalf("unexpected block->index mapping for new branch block 500: got %d want %d", got, 1)
	}
	if got := rawdb.ReadBTCCheckpointIndexByBlockNumber(db, 501); got != 2 {
		t.Fatalf("unexpected block->index mapping for new branch block 501: got %d want %d", got, 2)
	}
	if got := common.BytesToHash(rawdb.ReadBTCCheckpointHashByIndex(db, 1)); got != new1 {
		t.Fatalf("unexpected hash at index 1 after reorg: got %x want %x", got, new1)
	}
	if got := common.BytesToHash(rawdb.ReadBTCCheckpointHashByIndex(db, 2)); got != new2 {
		t.Fatalf("unexpected hash at index 2 after reorg: got %x want %x", got, new2)
	}
}

func reverseHashBytes(h common.Hash) common.Hash {
	var out common.Hash
	for i := 0; i < len(h); i++ {
		out[i] = h[len(h)-1-i]
	}
	return out
}

func TestHeaderChainBTCCheckpointHashRepresentationStable(t *testing.T) {
	hc := newBTCCheckpointTestHeaderChain(t)
	db := hc.chainDb

	// Use a non-symmetric pattern so accidental byte-order reversal is detectable.
	raw := make([]byte, 32)
	for i := 0; i < len(raw); i++ {
		raw[i] = byte(i)
	}
	hash := common.BytesToHash(raw)
	reversed := reverseHashBytes(hash)

	if hash == reversed {
		t.Fatalf("test setup produced symmetric hash pattern, cannot validate byte-order behavior")
	}

	hc.WriteBTCCheckpoint(db, 600, hash)
	if got := hc.ReadBTCCheckpointLastIndex(); got != 1 {
		t.Fatalf("unexpected last index after write: got %d want %d", got, 1)
	}

	if got := common.BytesToHash(rawdb.ReadBTCCheckpointHashByIndex(db, 1)); got != hash {
		t.Fatalf("stored checkpoint hash bytes changed representation: got %x want %x", got, hash)
	}
	if got := rawdb.ReadBTCCheckpointIndexByHash(db, hash); got != 1 {
		t.Fatalf("expected exact hash lookup to resolve index 1, got %d", got)
	}
	if got := rawdb.ReadBTCCheckpointIndexByHash(db, reversed); got != 0 {
		t.Fatalf("unexpected index for byte-reversed hash representation: got %d want %d", got, 0)
	}

	hc.DeleteBTCCheckpoint(db, 600)
	if got := rawdb.ReadBTCCheckpointIndexByHash(db, hash); got != 0 {
		t.Fatalf("expected hash lookup to clear after delete, got %d", got)
	}
	if got := common.BytesToHash(rawdb.ReadBTCCheckpointHashByIndex(db, 1)); got != (common.Hash{}) {
		t.Fatalf("expected index slot to clear after delete, got %x", got)
	}
}
