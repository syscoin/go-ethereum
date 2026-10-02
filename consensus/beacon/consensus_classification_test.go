// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package beacon

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

type classificationHeaderChain struct {
	consensus.ChainHeaderReader
	config *params.ChainConfig
}

func (c classificationHeaderChain) Config() *params.ChainConfig { return c.config }

func TestSyscoinHeaderErrorClassification(t *testing.T) {
	config := &params.ChainConfig{SyscoinBlock: big.NewInt(0), LondonBlock: big.NewInt(0)}
	chain := classificationHeaderChain{config: config}
	engine := New(ethash.NewFaker())
	parent := &types.Header{Number: big.NewInt(0), Time: 1, GasLimit: 10000000, GasUsed: 5000000, Difficulty: big.NewInt(1), BaseFee: big.NewInt(params.InitialBaseFee)}
	for _, name := range []string{"valid", "nonce", "timestamp", "difficulty", "gas", "number", "future"} {
		t.Run(name, func(t *testing.T) {
			header := &types.Header{Number: big.NewInt(1), Time: 2, GasLimit: parent.GasLimit,
				Difficulty: big.NewInt(1), UncleHash: types.EmptyUncleHash, BaseFee: big.NewInt(params.InitialBaseFee)}
			switch name {
			case "nonce":
				header.Nonce = types.EncodeNonce(1)
			case "timestamp":
				header.Time = parent.Time
			case "difficulty":
				header.Difficulty = common.Big2
			case "gas":
				header.GasUsed = header.GasLimit + 1
			case "number":
				header.Number = big.NewInt(2)
			case "future":
				header.Time = 10000
			}
			err := engine.verifyHeader(chain, header, parent, 2)
			var invalid *consensus.InvalidBlockError
			if name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if name == "future" {
				if !errors.Is(err, consensus.ErrFutureBlock) || errors.As(err, &invalid) {
					t.Fatalf("future block must remain retryable: %v", err)
				}
			} else if !errors.As(err, &invalid) {
				t.Fatalf("missing deterministic header marker: %v", err)
			}
			if name == "number" && !errors.Is(err, consensus.ErrInvalidNumber) {
				t.Fatalf("underlying consensus error lost: %v", err)
			}
		})
	}
}
