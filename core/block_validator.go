// Copyright 2015 The go-ethereum Authors
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

	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
)

// BlockValidator is responsible for validating block headers, uncles and
// processed state.
//
// BlockValidator implements Validator.
type BlockValidator struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
}

// NewBlockValidator returns a new block validator which is safe for re-use
func NewBlockValidator(config *params.ChainConfig, blockchain *BlockChain) *BlockValidator {
	validator := &BlockValidator{
		config: config,
		bc:     blockchain,
	}
	return validator
}

// ValidateBody validates the given block's uncles and verifies the block
// header's transaction and uncle roots. The headers are assumed to be already
// validated at this point.
func (v *BlockValidator) ValidateBody(block *types.Block) error {
	// Check whether the block is already imported.
	if v.bc.HasBlockAndState(block.Hash(), block.NumberU64()) {
		// SYSCOIN: Core pairs a SYSBLOCKHASH with each NEVM block via NevmBlockConnect.
		// After a matched disconnect, the same NEVM bytes may be reconnected under a
		// different Core hash. Skipping execution would keep the old SYS-dependent
		// state while writeNEVMData rewrites the mapping (history-dependent consensus).
		// Force re-execution whenever an external Core pair is supplied.
		if block.NevmBlockConnect == nil {
			return ErrKnownBlock
		}
	}

	if err := ValidateNEVMPayload(block); err != nil {
		return err
	}
	if err := validateBodySemantics(block); err != nil {
		return err
	}
	if err := v.bc.engine.VerifyUncles(v.bc, block); err != nil {
		return err
	}

	// Ancestor block must be known.
	if !v.bc.HasBlockAndState(block.ParentHash(), block.NumberU64()-1) {
		if !v.bc.HasBlock(block.ParentHash(), block.NumberU64()-1) {
			return consensus.ErrUnknownAncestor
		}
		return consensus.ErrPrunedAncestor
	}
	return nil
}

// ValidateNEVMPayload checks only body representation commitments. It does not
// consult chain state, verify ancestry or execute transactions. Import uses this
// same check once; recovery may invoke it separately for a replacement payload.
func ValidateNEVMPayload(block *types.Block) error {
	if block == nil {
		return errors.New("empty block")
	}
	return types.MarkNEVMPayloadError(validateBodyCommitments(block), block)
}

// validateBodyCommitments checks the supplied body against its immutable header.
// A failure describes mutable payload data, not permanent header invalidity.
func validateBodyCommitments(block *types.Block) error {
	// Header validity is known at this point. Here we verify that uncles, transactions
	// and withdrawals given in the block body match the header.
	header := block.Header()
	if hash := types.CalcUncleHash(block.Uncles()); hash != header.UncleHash {
		return fmt.Errorf("uncle root hash mismatch (header value %x, calculated %x)", header.UncleHash, hash)
	}
	if hash := types.DeriveSha(block.Transactions(), trie.NewStackTrie(nil)); hash != header.TxHash {
		return fmt.Errorf("transaction root hash mismatch (header value %x, calculated %x)", header.TxHash, hash)
	}

	// Withdrawals are present after the Shanghai fork.
	if header.WithdrawalsHash != nil {
		// Withdrawals list must be present in body after Shanghai.
		if block.Withdrawals() == nil {
			return errors.New("missing withdrawals in block body")
		}
		if hash := types.DeriveSha(block.Withdrawals(), trie.NewStackTrie(nil)); hash != *header.WithdrawalsHash {
			return fmt.Errorf("withdrawals root hash mismatch (header value %x, calculated %x)", *header.WithdrawalsHash, hash)
		}
	} else if block.Withdrawals() != nil {
		// Withdrawals are not allowed prior to Shanghai fork
		return errors.New("withdrawals present in block body")
	}

	// Blob transactions may be present after the Cancun fork.
	for i, tx := range block.Transactions() {
		// If the tx is a blob tx, it must NOT have a sidecar attached to be valid in a block.
		if tx.BlobTxSidecar() != nil {
			return fmt.Errorf("unexpected blob sidecar in transaction at index %d", i)
		}

		// The individual checks for blob validity (version-check + not empty)
		// happens in state transition.
	}

	return nil
}

// validateBodySemantics runs only after the body's commitments and absence of
// mutable sidecars are proven. Blob counts are then fixed by the committed txs.
func validateBodySemantics(block *types.Block) error {
	header := block.Header()
	var blobs int
	for _, tx := range block.Transactions() {
		blobs += len(tx.BlobHashes())
	}
	// Check blob gas usage.
	if header.BlobGasUsed != nil {
		if want := *header.BlobGasUsed / params.BlobTxBlobGasPerBlob; uint64(blobs) != want { // div because the header is surely good vs the body might be bloated
			return consensus.MarkInvalidBlock(fmt.Errorf("blob gas used mismatch (header %v, calculated %v)", *header.BlobGasUsed, blobs*params.BlobTxBlobGasPerBlob))
		}
	} else {
		if blobs > 0 {
			return consensus.MarkInvalidBlock(errors.New("data blobs present in block body"))
		}
	}

	return nil
}

// invalidBlockExecutionError is used only at deterministic execution/validation
// origins. A different body can share the same header hash, so prove its
// commitments before allowing an external caller to permanently reject it.
func invalidBlockExecutionError(block *types.Block, err error) error {
	if validateBodyCommitments(block) != nil {
		return err
	}
	return consensus.MarkInvalidBlock(err)
}

// ValidateState validates the various changes that happen after a state transition,
// such as amount of used gas, the receipt roots and the state root itself.
func (v *BlockValidator) ValidateState(block *types.Block, statedb *state.StateDB, res *ProcessResult, stateless bool) error {
	if err := statedb.Error(); err != nil {
		return err
	}
	if res == nil {
		return errors.New("nil ProcessResult value")
	}
	header := block.Header()
	if block.GasUsed() != res.GasUsed {
		return invalidBlockExecutionError(block, fmt.Errorf("invalid gas used (remote: %d local: %d)", block.GasUsed(), res.GasUsed))
	}
	// Validate the received block's bloom with the one derived from the generated receipts.
	// For valid blocks this should always validate to true.
	//
	// Receipts must go through MakeReceipt to calculate the receipt's bloom
	// already. Merge the receipt's bloom together instead of recalculating
	// everything.
	rbloom := types.MergeBloom(res.Receipts)
	if rbloom != header.Bloom {
		return invalidBlockExecutionError(block, fmt.Errorf("invalid bloom (remote: %x  local: %x)", header.Bloom, rbloom))
	}
	// In stateless mode, return early because the receipt and state root are not
	// provided through the witness, rather the cross validator needs to return it.
	if stateless {
		return nil
	}
	// The receipt Trie's root (R = (Tr [[H1, R1], ... [Hn, Rn]]))
	receiptSha := types.DeriveSha(res.Receipts, trie.NewStackTrie(nil))
	if receiptSha != header.ReceiptHash {
		return invalidBlockExecutionError(block, fmt.Errorf("invalid receipt root hash (remote: %x local: %x)", header.ReceiptHash, receiptSha))
	}
	// Validate the parsed requests match the expected header value.
	if header.RequestsHash != nil {
		reqhash := types.CalcRequestsHash(res.Requests)
		if reqhash != *header.RequestsHash {
			return invalidBlockExecutionError(block, fmt.Errorf("invalid requests hash (remote: %x local: %x)", *header.RequestsHash, reqhash))
		}
	} else if res.Requests != nil {
		return invalidBlockExecutionError(block, errors.New("block has requests before prague fork"))
	}
	// Validate the state root against the received state root and throw
	// an error if they don't match.
	root := statedb.IntermediateRoot(v.config.IsEIP158(header.Number))
	if err := statedb.Error(); err != nil {
		return err
	}
	if header.Root != root {
		return invalidBlockExecutionError(block, fmt.Errorf("invalid merkle root (remote: %x local: %x)", header.Root, root))
	}
	return nil
}

// CalcGasLimit computes the gas limit of the next block after parent. It aims
// to keep the baseline gas close to the provided target, and increase it towards
// the target if the baseline gas is lower.
func CalcGasLimit(parentGasLimit, desiredLimit uint64) uint64 {
	delta := parentGasLimit/params.GasLimitBoundDivisor - 1
	limit := parentGasLimit
	if desiredLimit < params.MinGasLimit {
		desiredLimit = params.MinGasLimit
	}
	// If we're outside our allowed gas range, we try to hone towards them
	if limit < desiredLimit {
		limit = parentGasLimit + delta
		if limit > desiredLimit {
			limit = desiredLimit
		}
		return limit
	}
	if limit > desiredLimit {
		limit = parentGasLimit - delta
		if limit < desiredLimit {
			limit = desiredLimit
		}
	}
	return limit
}
