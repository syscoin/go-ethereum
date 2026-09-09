// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package eth

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
)

// Exercise only result serialization with synthetic error and pair identities.
func TestNEVMResultSerialization(t *testing.T) {
	const nevmDisplay = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
	const sysDisplay = "3f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120"
	const invalidReply = "invalid:" + nevmDisplay + ":" + sysDisplay
	const zeroDisplay = "0000000000000000000000000000000000000000000000000000000000000000"
	var nevmHash, sysHash common.Hash
	for i := range nevmHash {
		nevmHash[i] = byte(i)
		sysHash[i] = byte(i + common.HashLength)
	}
	cause := errors.New("synthetic validation result")
	identified := &nevmInvalidBlockError{err: cause, nevmHash: nevmHash, sysHash: sysHash}
	wrapped := fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", identified))
	var recovered *nevmInvalidBlockError
	if !errors.Is(wrapped, cause) || !errors.As(wrapped, &recovered) || recovered != identified {
		t.Fatal("wrapped result lost its typed pair identity or cause")
	}
	for _, command := range []struct {
		name        string
		format      func(error) string
		success     string
		errorPrefix string
	}{
		{"connect", nevmConnectResult, "connected", "error:"},
		{"flush", nevmFlushResult, "flushed", "flush-failed: "},
	} {
		t.Run(command.name, func(t *testing.T) {
			for _, test := range []struct {
				name string
				err  error
				want string
			}{
				{"success", nil, command.success},
				{"identified", identified, invalidReply},
				{"wrapped-identity", wrapped, invalidReply},
				{"candidate-only", &nevmInvalidBlockError{err: cause, nevmHash: nevmHash}, "invalid:" + nevmDisplay + ":" + zeroDisplay},
				{"operational", errors.New("storage unavailable"), command.errorPrefix + "storage unavailable"},
				{"untyped-token", errors.New(invalidReply), command.errorPrefix + invalidReply},
				{"unpaired-marker", consensus.MarkInvalidBlock(cause), command.errorPrefix + cause.Error()},
			} {
				t.Run(test.name, func(t *testing.T) {
					if got := command.format(test.err); got != test.want {
						t.Fatalf("serialized result = %q, want %q", got, test.want)
					}
				})
			}
		})
	}
}
