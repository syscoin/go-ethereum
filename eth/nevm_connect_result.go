// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package eth

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

// nevmInvalidBlockError retains the pair that actually failed validation, which
// may precede the request that triggered a buffered import.
type nevmInvalidBlockError struct {
	err      error
	nevmHash common.Hash
	sysHash  common.Hash
}

func (e *nevmInvalidBlockError) Error() string { return e.err.Error() }
func (e *nevmInvalidBlockError) Unwrap() error { return e.err }

func nevmConnectError(err error, pair *types.NEVMBlockConnect) error {
	var invalid *consensus.InvalidBlockError
	if !errors.As(err, &invalid) || pair == nil || pair.Block == nil {
		return err
	}
	// An empty SYS hash is the existing header-only candidate check. Do not
	// reinterpret a malformed, nonempty hash as an identifiable pair.
	if len(pair.Sysblockhash) != 0 && len(pair.Sysblockhash) != common.HashLength {
		return err
	}
	return &nevmInvalidBlockError{
		err:      err,
		nevmHash: pair.Block.Hash(),
		sysHash:  common.BytesToHash([]byte(pair.Sysblockhash)),
	}
}

func nevmInsertError(err error, index int, pairs []*types.NEVMBlockConnect) error {
	// An absent/out-of-range failing index cannot identify an immutable pair.
	if index < 0 || index >= len(pairs) {
		return err
	}
	return nevmConnectError(err, pairs[index])
}

func nevmConnectResult(err error) string {
	if err == nil {
		return "connected"
	}
	var invalid *nevmInvalidBlockError
	if errors.As(err, &invalid) {
		return "invalid:" + encodeSyscoinDisplayHash(invalid.nevmHash[:]) + ":" + encodeSyscoinDisplayHash(invalid.sysHash[:])
	}
	return "error:" + err.Error()
}

func (zmq *ZMQRep) handleNEVMConnect(payload []byte) string {
	var pair types.NEVMBlockConnect
	if err := pair.Deserialize(payload); err != nil {
		// Transport/body-input errors do not establish immutable block invalidity.
		log.Error("addBlockSub Deserialize", "err", err)
		return "error:" + err.Error()
	}
	err := zmq.eth.AddBlock(&pair)
	if err != nil {
		log.Error("addBlockSub AddBlock", "err", err)
	}
	return nevmConnectResult(err)
}
