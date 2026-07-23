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
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// ApplyNexusHardFork transfers SYS from the pre-Nexus vault to the Nexus vault.
func ApplyNexusHardFork(statedb *state.StateDB) {
	migrateVaultBalance(statedb, params.VaultManagerNexusOld, params.VaultManager)
}

// ApplyLibertyHardFork transfers SYS from the Nexus-era vault to the Liberty
// replacement vault at LibertyBlock (shared mainnet/tanenbaum rule).
//
// Tanenbaum LibertyBlock is already 906001; activating this requires every
// tanenbaum node to replay from that height (no TokenFreeze logs after it).
func ApplyLibertyHardFork(statedb *state.StateDB) {
	migrateVaultBalance(statedb, params.VaultManager, params.VaultManagerV2)
}

func migrateVaultBalance(statedb *state.StateDB, from, to common.Address) {
	if from == to {
		return
	}
	if !statedb.Exist(to) {
		statedb.CreateAccount(to)
	}
	// Copy before mutating `from` so AddBalance cannot observe a zeroed source.
	oldBalance := new(uint256.Int).Set(statedb.GetBalance(from))
	if oldBalance.IsZero() {
		return
	}
	statedb.AddBalance(to, oldBalance, tracing.BalanceIncreaseVaultManagerContract)
	statedb.SetBalance(from, new(uint256.Int), tracing.BalanceDecreaseVaultManagerAccount)
}
