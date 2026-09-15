// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package miner

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

func TestPendingCacheValidity(t *testing.T) {
	parent := common.HexToHash("0x1234")
	for _, test := range []struct {
		name  string
		check func() error
	}{
		{"nil", nil},
		{"noop", func() error { return nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache, result := new(pending), new(newPayloadResult)
			cache.update(parent, result, test.check)
			if got := cache.resolve(parent); got != result {
				t.Fatal("stable pending result was not reused")
			}
			if got := cache.resolve(common.HexToHash("0x5678")); got != nil {
				t.Fatal("pending result survived a different parent")
			}
			cache.created = time.Now().Add(-pendingTTL - time.Second)
			if got := cache.resolve(parent); got != nil {
				t.Fatal("expired pending result was reused")
			}
		})
	}
}
