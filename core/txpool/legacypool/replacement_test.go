// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package legacypool

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// Replacement rejection must happen before a full pool evicts another sender.
// Accepted replacements only need space for their net slot growth.
func TestReplacementAtCapacity(t *testing.T) {
	for _, stage := range []string{"pending", "queued"} {
		for _, dynamic := range []bool{false, true} {
			kind := "legacy"
			if dynamic {
				kind = "dynamic"
			}
			for _, test := range []struct {
				name        string
				price       int64
				dataSize    uint64
				wantErr     error
				wantEvict   bool
				oldPrice    int64
				oldDataSize uint64
			}{
				{name: "rejected", oldPrice: 100, price: 101, wantErr: txpool.ErrReplaceUnderpriced},
				{name: "rejected-growth", oldPrice: 100, price: 101, dataSize: txSlotSize, wantErr: txpool.ErrReplaceUnderpriced},
				{name: "same-size", oldPrice: 100, price: 110},
				{name: "shrink", oldPrice: 100, oldDataSize: txSlotSize, price: 110},
				{name: "growth", oldPrice: 100, price: 110, dataSize: txSlotSize, wantEvict: true},
				{name: "growth-cheapest-predecessor", oldPrice: 1, price: 2, dataSize: txSlotSize, wantEvict: true},
			} {
				t.Run(stage+"/"+kind+"/"+test.name, func(t *testing.T) {
					pool, key := setupPool()
					defer pool.Close()
					pool.config.GlobalSlots = 2
					pool.config.GlobalQueue = 2
					testAddBalance(pool, crypto.PubkeyToAddress(key.PublicKey), big.NewInt(1000000000000))
					nonce := uint64(0)
					if stage == "queued" {
						nonce = 2
					}
					makeTx := func(price int64, dataSize uint64) *types.Transaction {
						if !dynamic {
							return pricedDataTransaction(nonce, 2000000, big.NewInt(price), key, dataSize)
						}
						tx, err := types.SignNewTx(key, pool.signer, &types.DynamicFeeTx{
							ChainID: pool.chainconfig.ChainID, Nonce: nonce,
							GasTipCap: big.NewInt(price), GasFeeCap: big.NewInt(price),
							Gas: 2000000, To: &common.Address{}, Data: make([]byte, dataSize),
						})
						if err != nil {
							t.Fatal(err)
						}
						return tx
					}
					old, candidate := makeTx(test.oldPrice, test.oldDataSize), makeTx(test.price, test.dataSize)
					// Keep a cheaper queued transaction available for legitimate
					// growth, including when the replacement itself is queued.
					peers := make(types.Transactions, 4-numSlots(old))
					for i := range peers {
						peerKey, err := crypto.GenerateKey()
						if err != nil {
							t.Fatal(err)
						}
						testAddBalance(pool, crypto.PubkeyToAddress(peerKey.PublicKey), big.NewInt(1000000000000))
						peerNonce := uint64(0)
						if i == 0 {
							peerNonce = 2
						}
						peers[i] = pricedTransaction(peerNonce, 21000, big.NewInt(int64(10+i)), peerKey)
					}
					for _, tx := range append(types.Transactions{old}, peers...) {
						if err := pool.addRemoteSync(tx); err != nil {
							t.Fatal(err)
						}
					}
					if slots := pool.all.Slots(); slots != 4 {
						t.Fatalf("initial slots: have %d, want 4", slots)
					}
					if drops := pool.unaffordableQueueAfter(crypto.PubkeyToAddress(key.PublicKey), candidate); len(drops) != 0 {
						t.Fatalf("test unexpectedly needs self-pruning: %v", drops)
					}
					if err := pool.addRemoteSync(candidate); !errors.Is(err, test.wantErr) {
						t.Fatalf("replacement error: have %v, want %v", err, test.wantErr)
					}
					if (pool.Get(old.Hash()) != nil) != (test.wantErr != nil) || (pool.Get(candidate.Hash()) != nil) != (test.wantErr == nil) {
						t.Fatal("unexpected predecessor or candidate membership")
					}
					for i, tx := range peers {
						if (pool.Get(tx.Hash()) == nil) != (test.wantEvict && i == 0) {
							t.Fatalf("unexpected eviction of peer %d", i)
						}
					}
					wantSlots := 4
					if test.wantErr == nil {
						wantSlots += numSlots(candidate) - numSlots(old)
						if test.wantEvict {
							wantSlots--
						}
					}
					if slots := pool.all.Slots(); slots != wantSlots {
						t.Fatalf("final slots: have %d, want %d", slots, wantSlots)
					}
					checkPricedTransactions(t, pool)
					checkAffordablePool(t, pool)
				})
			}
		}
	}
}

func TestReplacementGrowthRejectionAtCapacity(t *testing.T) {
	for _, test := range []struct {
		name     string
		dataSize uint64
		wantErr  error
	}{
		{name: "overflow", dataSize: 3 * txSlotSize, wantErr: ErrTxPoolOverflow},
		{name: "future-replaces-pending", dataSize: txSlotSize, wantErr: ErrFutureReplacePending},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool, key := setupPool()
			defer pool.Close()
			pool.config.GlobalSlots = 1
			pool.config.GlobalQueue = 2
			testAddBalance(pool, crypto.PubkeyToAddress(key.PublicKey), big.NewInt(1000000000000))
			old := pricedTransaction(2, 21000, big.NewInt(1), key)
			originals := types.Transactions{old}
			for i := 0; i < 2; i++ {
				peer, err := crypto.GenerateKey()
				if err != nil {
					t.Fatal(err)
				}
				testAddBalance(pool, crypto.PubkeyToAddress(peer.PublicKey), big.NewInt(1000000000000))
				originals = append(originals, pricedTransaction(0, 21000, big.NewInt(int64(10+i)), peer))
			}
			for _, tx := range originals {
				if err := pool.addRemoteSync(tx); err != nil {
					t.Fatal(err)
				}
			}
			candidate := pricedDataTransaction(2, 5000000, big.NewInt(2), key, test.dataSize)
			if err := pool.addRemoteSync(candidate); !errors.Is(err, test.wantErr) {
				t.Fatalf("replacement error: have %v, want %v", err, test.wantErr)
			}
			for _, tx := range originals {
				if pool.Get(tx.Hash()) == nil {
					t.Fatal("rejected growth evicted an existing transaction")
				}
			}
			if pool.Get(candidate.Hash()) != nil || pool.all.Slots() != 3 {
				t.Fatal("rejected growth changed pool occupancy")
			}
			checkPricedTransactions(t, pool)
			// A subsequent replacement must still find the restored predecessor.
			if err := pool.addRemoteSync(pricedTransaction(2, 21000, big.NewInt(2), key)); err != nil {
				t.Fatalf("replacement after rejected growth: %v", err)
			}
			checkPricedTransactions(t, pool)
			checkAffordablePool(t, pool)
		})
	}
}

// Check live price points before validatePoolInternals rebuilds both heaps.
func checkPricedTransactions(t *testing.T, pool *LegacyPool) {
	t.Helper()
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	seen := make(map[common.Hash]bool)
	for _, heap := range []priceHeap{pool.priced.urgent, pool.priced.floating} {
		for _, tx := range heap.list {
			if pool.all.Get(tx.Hash()) == nil {
				continue
			}
			if seen[tx.Hash()] {
				t.Fatal("duplicate live transaction in pricing heaps")
			}
			seen[tx.Hash()] = true
		}
	}
	if len(seen) != pool.all.Count() {
		t.Fatalf("live pricing entries: have %d, want %d", len(seen), pool.all.Count())
	}
}
