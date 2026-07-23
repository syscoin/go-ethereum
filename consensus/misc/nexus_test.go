// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package misc

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

func TestApplyBlockHardForksVaultMigration(t *testing.T) {
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	old := params.VaultManager
	neu := common.HexToAddress("0x2222222222222222222222222222222222222222")
	statedb.CreateAccount(old)
	statedb.AddBalance(old, uint256.NewInt(500), tracing.BalanceChangeUnspecified)

	cfg := &params.ChainConfig{
		VaultMigrationBlock: big.NewInt(42),
		VaultManagerV2:      neu,
	}
	ApplyBlockHardForks(cfg, big.NewInt(41), statedb)
	if got := statedb.GetBalance(old); got.Cmp(uint256.NewInt(500)) != 0 {
		t.Fatalf("pre-fork mutate: old=%s want 500", got)
	}
	ApplyBlockHardForks(cfg, big.NewInt(42), statedb)
	if got := statedb.GetBalance(neu); got.Cmp(uint256.NewInt(500)) != 0 {
		t.Fatalf("migration block: new=%s want 500", got)
	}
	if got := statedb.GetBalance(old); !got.IsZero() {
		t.Fatalf("migration block: old=%s want 0", got)
	}
}

func TestApplyVaultMigrationHardForkAddsWithoutOverwrite(t *testing.T) {
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	old := params.VaultManager
	neu := params.VaultManagerV2

	statedb.CreateAccount(old)
	statedb.CreateAccount(neu)
	statedb.AddBalance(old, uint256.NewInt(1000), tracing.BalanceChangeUnspecified)
	statedb.AddBalance(neu, uint256.NewInt(50), tracing.BalanceChangeUnspecified)

	ApplyVaultMigrationHardFork(statedb, neu)

	if got := statedb.GetBalance(neu); got.Cmp(uint256.NewInt(1050)) != 0 {
		t.Fatalf("new vault balance=%s want 1050", got)
	}
	if got := statedb.GetBalance(old); !got.IsZero() {
		t.Fatalf("old vault balance=%s want 0", got)
	}
}

func TestMigrateVaultBalanceZeroIsExactNoopForV2(t *testing.T) {
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	from := params.VaultManager
	to := params.VaultManagerV2
	statedb.CreateAccount(from)
	rootBefore := statedb.IntermediateRoot(false)
	migrateVaultBalance(statedb, from, to, true)
	if statedb.Exist(to) {
		t.Fatal("zero-balance V2 migrate created destination account")
	}
	if rootAfter := statedb.IntermediateRoot(false); rootAfter != rootBefore {
		t.Fatalf("zero-balance V2 migrate changed state root: before=%s after=%s", rootBefore, rootAfter)
	}
}

func TestNexusZeroBalanceCreatesDestination(t *testing.T) {
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	from := params.VaultManagerNexusOld
	to := params.VaultManager
	statedb.CreateAccount(from)
	ApplyNexusHardFork(statedb)
	if !statedb.Exist(to) {
		t.Fatal("Nexus zero-balance migrate did not create destination")
	}
	if got := statedb.GetBalance(from); !got.IsZero() {
		t.Fatalf("source balance=%s want 0", got)
	}
}

func TestMigrateVaultBalanceSkipsIdenticalAddresses(t *testing.T) {
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	addr := common.HexToAddress("0xabc0000000000000000000000000000000000001")
	statedb.CreateAccount(addr)
	statedb.AddBalance(addr, uint256.NewInt(7), tracing.BalanceChangeUnspecified)
	migrateVaultBalance(statedb, addr, addr, true)
	if got := statedb.GetBalance(addr); got.Cmp(uint256.NewInt(7)) != 0 {
		t.Fatalf("balance changed on self-migrate: %s", got)
	}
}
