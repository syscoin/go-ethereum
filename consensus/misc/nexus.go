// Copyright 2016 The go-ethereum Authors
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

package misc

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// ApplyBlockHardForks applies one-shot state mutations that occur at specific
// block numbers before transaction execution (DAO, Nexus, VaultMigration).
// Callers that re-execute a block without going through StateProcessor.Process
// (debug/trace paths) must invoke this so pre-tx state matches consensus.
func ApplyBlockHardForks(config *params.ChainConfig, number *big.Int, statedb *state.StateDB) {
	if config.DAOForkSupport && config.DAOForkBlock != nil && config.DAOForkBlock.Cmp(number) == 0 {
		ApplyDAOHardFork(statedb)
	}
	// SYSCOIN
	if config.NexusBlock != nil && config.NexusBlock.Cmp(number) == 0 {
		ApplyNexusHardFork(statedb)
	}
	if config.VaultMigrationBlock != nil && config.VaultMigrationBlock.Cmp(number) == 0 {
		ApplyVaultMigrationHardFork(statedb, config.VaultManagerV2)
	}
}

// ApplyNexusHardFork transfers SYS from the pre-Nexus vault to the Nexus vault.
// Historical Nexus behavior is preserved for zero balances: the destination
// account is created and the source is touched via SetBalance.
func ApplyNexusHardFork(statedb *state.StateDB) {
	migrateVaultBalance(statedb, params.VaultManagerNexusOld, params.VaultManager, false)
}

// ApplyVaultMigrationHardFork transfers SYS from the Nexus-era vault to vaultV2
// at VaultMigrationBlock. vaultV2 should be the per-network ChainConfig address
// (falls back to params.VaultManagerV2 when zero).
//
// Zero source balance is an exact no-op (unlike Nexus) so unused cutovers do
// not create empty destination accounts.
//
// This is intentionally separate from LibertyBlock: Tanenbaum already activated
// Liberty opcodes at 906001, so replaying that historical block with a new
// balance mutation would invalidate existing state roots.
func ApplyVaultMigrationHardFork(statedb *state.StateDB, vaultV2 common.Address) {
	if vaultV2 == (common.Address{}) {
		vaultV2 = params.VaultManagerV2
	}
	migrateVaultBalance(statedb, params.VaultManager, vaultV2, true)
}

// migrateVaultBalance moves SYS from -> to. If exactNoopOnZero is true and the
// source balance is zero, the state is left untouched. Otherwise (Nexus), a
// missing destination is created and the source is zeroed even when empty.
func migrateVaultBalance(statedb *state.StateDB, from, to common.Address, exactNoopOnZero bool) {
	if from == to {
		return
	}
	oldBalance := new(uint256.Int).Set(statedb.GetBalance(from))
	if oldBalance.IsZero() && exactNoopOnZero {
		return
	}
	if !statedb.Exist(to) {
		statedb.CreateAccount(to)
	}
	if !oldBalance.IsZero() {
		statedb.AddBalance(to, oldBalance, tracing.BalanceIncreaseVaultManagerContract)
	}
	statedb.SetBalance(from, new(uint256.Int), tracing.BalanceDecreaseVaultManagerAccount)
}
