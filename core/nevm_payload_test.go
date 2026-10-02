// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
)

func TestNEVMPayloadCommitmentClassification(t *testing.T) {
	header := &types.Header{
		Number: big.NewInt(1), UncleHash: types.EmptyUncleHash,
		TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash,
	}
	if err := ValidateNEVMPayload(types.NewBlockWithHeader(header)); err != nil {
		t.Fatalf("valid empty body: %v", err)
	}
	// Exercise only the pure commitment check with a local header fixture.
	header.TxHash[0] ^= 1
	err := ValidateNEVMPayload(types.NewBlockWithHeader(header))
	var payload *types.NEVMPayloadError
	var invalid *consensus.InvalidBlockError
	if !errors.As(err, &payload) || errors.As(err, &invalid) {
		t.Fatalf("body commitment classification: %v", err)
	}
	if err := ValidateNEVMPayload(nil); err == nil || errors.As(err, &payload) {
		t.Fatalf("missing block should remain unclassified: %v", err)
	}
}
