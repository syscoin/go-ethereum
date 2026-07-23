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

package params

import (
	"github.com/ethereum/go-ethereum/common"
)

// Vault manager addresses for Syscoin NEVM bridge cutovers.
//
// Nexus (activated): VaultManagerNexusOld → VaultManager
// Liberty (at LibertyBlock): VaultManager → VaultManagerV2
//
// Replace VaultManagerV2 with the deployed replacement vault before mainnet
// LibertyBlock is set. Tanenbaum keeps LibertyBlock=906001 and must resync.
var (
	VaultManagerNexusOld = common.HexToAddress("0xA738a563F9ecb55e0b2245D1e9E380f0fE455ea1")
	VaultManager         = common.HexToAddress("0x7904299b3D3dC1b03d1DdEb45E9fDF3576aCBd5f")
	// Stub until replacement vault is deployed at this address.
	VaultManagerV2 = common.HexToAddress("0x1111111111111111111111111111111111111111")
)
