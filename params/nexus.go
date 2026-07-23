package params

import (
	"github.com/ethereum/go-ethereum/common"
)

// Vault manager addresses for Syscoin NEVM bridge cutovers.
//
// Nexus (activated): VaultManagerNexusOld → VaultManager
// Bridge V2 (at VaultMigrationBlock): VaultManager → VaultManagerV2
//
// Package-level VaultManagerV2 is the default stub used by tests and as the
// initial ChainConfig.VaultManagerV2 for each network. Replace the per-network
// ChainConfig field with the deployed UUPS vault proxy before setting that
// network's VaultMigrationBlock. Do not couple migration to LibertyBlock on
// networks where Liberty already activated historically (e.g. Tanenbaum 906001).
var (
	VaultManagerNexusOld = common.HexToAddress("0xA738a563F9ecb55e0b2245D1e9E380f0fE455ea1")
	// Deprecated: use VaultManagerNexusOld.
	VaultManagerOld = VaultManagerNexusOld
	VaultManager    = common.HexToAddress("0x7904299b3D3dC1b03d1DdEb45E9fDF3576aCBd5f")
	// Default stub; prefer ChainConfig.VaultManagerV2 for live networks.
	VaultManagerV2 = common.HexToAddress("0x1111111111111111111111111111111111111111")
)
