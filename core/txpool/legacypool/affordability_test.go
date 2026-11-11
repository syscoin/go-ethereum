// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package legacypool

import (
	"crypto/ecdsa"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

func checkAffordablePool(t *testing.T, pool *LegacyPool) {
	t.Helper()
	if err := validatePoolInternals(pool); err != nil {
		t.Fatal(err)
	}
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	for addr, pending := range pool.pending {
		total := new(big.Int)
		for _, tx := range pending.Flatten() {
			total.Add(total, tx.Cost())
		}
		if total.Cmp(pool.currentState.GetBalance(addr).ToBig()) > 0 {
			t.Fatalf("pending expenditure exceeds balance: %v", total)
		}
	}
}

func TestBatchAffordability(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(map[bool]string{false: "ascending", true: "descending"}[reverse], func(t *testing.T) {
			pool, key := setupPool()
			defer pool.Close()
			addr := crypto.PubkeyToAddress(key.PublicKey)
			testAddBalance(pool, addr, big.NewInt(100000))
			low := transaction(0, 50000, key)
			high := transaction(1, 60000, key)
			txs := []*types.Transaction{low, high}
			if reverse {
				txs[0], txs[1] = txs[1], txs[0]
			}
			errs := pool.addRemotesSync(txs)
			for i, tx := range txs {
				if tx.Nonce() == 0 && errs[i] != nil {
					t.Fatalf("lower nonce rejected: %v", errs[i])
				}
				if tx.Nonce() == 1 && !errors.Is(errs[i], core.ErrInsufficientFunds) {
					t.Fatalf("higher nonce: %v", errs[i])
				}
			}
			if pool.Get(low.Hash()) == nil || pool.Get(high.Hash()) != nil {
				t.Fatal("unexpected retained transactions")
			}
			checkAffordablePool(t, pool)
		})
	}
}

func TestBatchAffordabilityReplacements(t *testing.T) {
	for _, existing := range []string{"batch", "pending", "queue"} {
		t.Run(existing, func(t *testing.T) {
			pool, key := setupPool()
			defer pool.Close()
			addr := crypto.PubkeyToAddress(key.PublicKey)
			testAddBalance(pool, addr, big.NewInt(100000))
			nonce := uint64(0)
			if existing == "queue" {
				nonce = 2
			}
			original := transaction(nonce, 30000, key)
			replacement := pricedTransaction(nonce, 30000, big.NewInt(2), key)
			next := transaction(nonce+1, 30000, key)
			excess := transaction(nonce+2, 30000, key)
			txs := []*types.Transaction{replacement, next, excess}
			if existing == "batch" {
				txs = []*types.Transaction{original, next, replacement, excess}
			} else if err := pool.addRemoteSync(original); err != nil {
				t.Fatal(err)
			}
			errs := pool.addRemotesSync(txs)
			for i := range errs {
				if i == len(errs)-1 {
					if !errors.Is(errs[i], core.ErrInsufficientFunds) {
						t.Fatalf("excess transaction: %v", errs[i])
					}
				} else if errs[i] != nil {
					t.Fatalf("valid transaction %d: %v", i, errs[i])
				}
			}
			if pool.Get(original.Hash()) != nil || pool.Get(replacement.Hash()) == nil || pool.Get(next.Hash()) == nil || pool.Get(excess.Hash()) != nil {
				t.Fatal("unexpected replacement result")
			}
			checkAffordablePool(t, pool)
		})
	}
}

func TestBatchAffordabilityIncludesPending(t *testing.T) {
	pool, key := setupPool()
	defer pool.Close()
	addr := crypto.PubkeyToAddress(key.PublicKey)
	testAddBalance(pool, addr, big.NewInt(100000))
	first := transaction(0, 30000, key)
	if err := pool.addRemoteSync(first); err != nil {
		t.Fatal(err)
	}
	errs := pool.addRemotesSync([]*types.Transaction{transaction(1, 40000, key), transaction(2, 40000, key)})
	if errs[0] != nil || !errors.Is(errs[1], core.ErrInsufficientFunds) {
		t.Fatalf("batch errors: %v", errs)
	}
	checkAffordablePool(t, pool)
}

func TestGapFillAffordability(t *testing.T) {
	pool, key := setupPool()
	defer pool.Close()
	addr := crypto.PubkeyToAddress(key.PublicKey)
	testAddBalance(pool, addr, big.NewInt(100000))
	pending := transaction(0, 30000, key)
	expensive := transaction(2, 40000, key)
	future := transaction(3, 21000, key)
	for _, tx := range []*types.Transaction{pending, expensive, future} {
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatal(err)
		}
	}
	fill := transaction(1, 40000, key)
	if err := pool.addRemoteSync(fill); err != nil {
		t.Fatalf("gap fill rejected: %v", err)
	}
	if pool.Get(fill.Hash()) == nil || pool.Get(expensive.Hash()) != nil || pool.Get(future.Hash()) == nil {
		t.Fatal("gap fill did not preserve the affordable prefix and future suffix")
	}
	if p, q := pool.Stats(); p != 2 || q != 1 {
		t.Fatalf("unexpected pool state %d/%d", p, q)
	}
	checkAffordablePool(t, pool)
}

func TestResetAffordability(t *testing.T) {
	pool, key := setupPool()
	defer pool.Close()
	addr := crypto.PubkeyToAddress(key.PublicKey)
	testAddBalance(pool, addr, big.NewInt(100000))
	txs := []*types.Transaction{transaction(0, 30000, key), transaction(1, 30000, key), transaction(2, 30000, key)}
	for _, tx := range txs {
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatal(err)
		}
	}
	pool.mu.Lock()
	pool.currentState.SetBalance(addr, uint256.NewInt(65000), tracing.BalanceChangeUnspecified)
	pool.mu.Unlock()
	<-pool.requestReset(nil, nil)
	if pool.Get(txs[0].Hash()) == nil || pool.Get(txs[1].Hash()) == nil || pool.Get(txs[2].Hash()) != nil {
		t.Fatal("reset did not retain the affordable prefix")
	}
	checkAffordablePool(t, pool)
}

func TestResetAffordabilityAfterInclusion(t *testing.T) {
	pool, key := setupPool()
	defer pool.Close()
	addr := crypto.PubkeyToAddress(key.PublicKey)
	testAddBalance(pool, addr, big.NewInt(100000))
	included := transaction(0, 50000, key)
	future := transaction(1, 50000, key)
	if err := pool.addRemoteSync(included); err != nil {
		t.Fatal(err)
	}
	pool.mu.Lock()
	pool.enqueueTx(future.Hash(), future, true)
	pool.currentState.SetNonce(addr, 1, tracing.NonceChangeUnspecified)
	pool.currentState.SetBalance(addr, uint256.NewInt(60000), tracing.BalanceChangeUnspecified)
	pool.mu.Unlock()
	<-pool.requestReset(nil, nil)
	if pool.Get(included.Hash()) != nil || pool.Get(future.Hash()) == nil {
		t.Fatal("included transaction was charged against the new balance")
	}
	if p, q := pool.Stats(); p != 1 || q != 0 {
		t.Fatalf("unexpected pool state %d/%d", p, q)
	}
	checkAffordablePool(t, pool)
}

func valueTransaction(nonce uint64, value *big.Int, key *ecdsa.PrivateKey) *types.Transaction {
	tx, _ := types.SignTx(types.NewTransaction(nonce, common.Address{}, value, 21000, big.NewInt(1), nil), types.HomesteadSigner{}, key)
	return tx
}

func TestBatchAffordabilityWithLargeQueueCosts(t *testing.T) {
	pool, key := setupPool()
	defer pool.Close()
	addr := crypto.PubkeyToAddress(key.PublicKey)
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	testAddBalance(pool, addr, max)
	value := new(big.Int).Lsh(big.NewInt(1), 255)
	old := valueTransaction(10, value, key)
	if err := pool.addRemoteSync(old); err != nil {
		t.Fatal(err)
	}
	if err := pool.addRemoteSync(valueTransaction(11, value, key)); !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("second future transaction: %v", err)
	}
	errs := pool.addRemotesSync([]*types.Transaction{valueTransaction(0, value, key), valueTransaction(1, value, key)})
	if errs[0] != nil || !errors.Is(errs[1], core.ErrInsufficientFunds) {
		t.Fatalf("batch errors: %v", errs)
	}
	if pool.Get(old.Hash()) != nil {
		t.Fatal("unaffordable higher nonce retained after gap fill")
	}
	checkAffordablePool(t, pool)
}

func TestSeparateFutureAddsCannotEvictOtherAccounts(t *testing.T) {
	pool, attacker := setupPool()
	defer pool.Close()
	pool.config.GlobalSlots = 1
	pool.config.GlobalQueue = 2
	pendingKey, _ := crypto.GenerateKey()
	queuedKey, _ := crypto.GenerateKey()
	for _, key := range []*ecdsa.PrivateKey{pendingKey, queuedKey} {
		testAddBalance(pool, crypto.PubkeyToAddress(key.PublicKey), big.NewInt(1000000))
	}
	testAddBalance(pool, crypto.PubkeyToAddress(attacker.PublicKey), big.NewInt(100000))
	pending := pricedTransaction(0, 21000, big.NewInt(10), pendingKey)
	queued := pricedTransaction(1, 21000, big.NewInt(1), queuedKey)
	first := pricedTransaction(10, 21000, big.NewInt(3), attacker)
	for _, tx := range []*types.Transaction{pending, queued, first} {
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatal(err)
		}
	}
	// This higher-priced future transaction would have evicted the other
	// account's queued transaction if only pending spend were charged.
	second := pricedTransaction(11, 21000, big.NewInt(4), attacker)
	if err := pool.addRemoteSync(second); !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("underfunded separate Add: %v", err)
	}
	if pool.Get(queued.Hash()) == nil || pool.Get(second.Hash()) != nil {
		t.Fatal("underfunded future transaction displaced another account")
	}
	checkAffordablePool(t, pool)
}

func TestSeparateQueuedReplacementPrunesUnaffordableFuture(t *testing.T) {
	pool, key := setupPool()
	defer pool.Close()
	addr := crypto.PubkeyToAddress(key.PublicKey)
	testAddBalance(pool, addr, big.NewInt(100000))
	old := pricedTransaction(2, 30000, big.NewInt(1), key)
	future := pricedTransaction(3, 30000, big.NewInt(1), key)
	for _, tx := range []*types.Transaction{old, future} {
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatal(err)
		}
	}
	replacement := pricedTransaction(2, 30000, big.NewInt(3), key)
	if err := pool.addRemoteSync(replacement); err != nil {
		t.Fatal(err)
	}
	if pool.Get(old.Hash()) != nil || pool.Get(replacement.Hash()) == nil || pool.Get(future.Hash()) != nil {
		t.Fatal("replacement did not retain the affordable queued prefix")
	}
	checkAffordablePool(t, pool)
}

func TestQueuedReplacementCreditsOwnPruningAtCapacity(t *testing.T) {
	pool, attacker := setupPool()
	defer pool.Close()
	pool.config.GlobalSlots = 1
	pool.config.GlobalQueue = 2
	honest, _ := crypto.GenerateKey()
	testAddBalance(pool, crypto.PubkeyToAddress(honest.PublicKey), big.NewInt(1000000))
	testAddBalance(pool, crypto.PubkeyToAddress(attacker.PublicKey), big.NewInt(2000000))
	honestPending := pricedTransaction(0, 21000, big.NewInt(10), honest)
	old := pricedTransaction(2, 21000, big.NewInt(2), attacker)
	future := pricedTransaction(3, 900000, big.NewInt(1), attacker)
	for _, tx := range []*types.Transaction{honestPending, old, future} {
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatal(err)
		}
	}
	failed := pricedDataTransaction(2, 600000, big.NewInt(2), attacker, 32768)
	valid := pricedDataTransaction(2, 600000, big.NewInt(3), attacker, 32768)
	if numSlots(old) != 1 || numSlots(future) != 1 || numSlots(valid) != 2 {
		t.Fatal("test needs a one-slot replacement growing to two slots")
	}
	if err := pool.addRemoteSync(failed); !errors.Is(err, txpool.ErrReplaceUnderpriced) {
		t.Fatalf("failed price bump: %v", err)
	}
	if pool.Get(honestPending.Hash()) == nil || pool.Get(old.Hash()) == nil || pool.Get(future.Hash()) == nil || pool.Get(failed.Hash()) != nil {
		t.Fatal("failed replacement mutated the pool")
	}
	if err := pool.addRemoteSync(valid); err != nil {
		t.Fatalf("replacement with own pruning should fit: %v", err)
	}
	if pool.Get(honestPending.Hash()) == nil || pool.Get(valid.Hash()) == nil || pool.Get(old.Hash()) != nil || pool.Get(future.Hash()) != nil {
		t.Fatal("replacement failed to prune its own unaffordable future")
	}
	if slots := pool.all.Slots(); slots != 3 {
		t.Fatalf("pool occupancy %d, want 3", slots)
	}
	checkAffordablePool(t, pool)
}
