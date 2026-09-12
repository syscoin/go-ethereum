// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package eth

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

const nevmDurablePairPrefix = "durable-pair-v1:"

// SYSCOIN: accept only the canonical, short Bitcoin-serialized command. Reply
// with command text, following connect-v1/payload-v1, only after the fence.
func parseNEVMDurablePair(command string) (string, uint64, []byte, error) {
	if len(command) < 2 || len(command)-1 >= 253 || int(command[0]) != len(command)-1 {
		return "", 0, nil, errors.New("invalid durable-pair serialization")
	}
	text := command[1:]
	fields := strings.Split(text, ":")
	if len(fields) != 3 || fields[0] != "durable-pair-v1" {
		return "", 0, nil, errors.New("invalid durable-pair command")
	}
	number, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil || strconv.FormatUint(number, 10) != fields[1] {
		return "", 0, nil, errors.New("invalid durable-pair count")
	}
	hash, err := hex.DecodeString(fields[2])
	if err != nil || len(hash) != 32 || hex.EncodeToString(hash) != fields[2] {
		return "", 0, nil, errors.New("invalid durable-pair hash")
	}
	for i := 0; i < len(hash)/2; i++ {
		hash[i], hash[len(hash)-1-i] = hash[len(hash)-1-i], hash[i]
	}
	return text, number, hash, nil
}

func (eth *Ethereum) syncNEVMPair(number uint64, hash []byte) error {
	// SYSCOIN: the caller first flushes and observes the exact published pair.
	// Do not silently import additional buffered work while acknowledging it.
	eth.bufferLock.Lock()
	defer eth.bufferLock.Unlock()
	if len(eth.blockConnectBuffer) != 0 {
		return errors.New("durable-pair has buffered blocks")
	}
	return eth.blockchain.SyncSyscoinPair(number, hash)
}
