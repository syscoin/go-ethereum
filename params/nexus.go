package params

import (
	"github.com/ethereum/go-ethereum/common"
)

// Vault manager addresses for Syscoin NEVM bridge cutovers.
//
// Nexus (activated): VaultManagerNexusOld → VaultManager
// Bridge V2 (at VaultMigrationBlock): VaultManager → VaultManagerV2
//
// Package-level VaultManagerV2 is a test/stub address only. Live ChainConfig
// must leave VaultManagerV2 zero until the real UUPS proxy is known, then set
// both VaultManagerV2 and VaultMigrationBlock together. CheckConfigForkOrder
// rejects scheduling migration to this stub. Do not couple migration to
// LibertyBlock on networks where Liberty already activated historically
// (e.g. Tanenbaum 906001).
var (
	VaultManagerNexusOld = common.HexToAddress("0xA738a563F9ecb55e0b2245D1e9E380f0fE455ea1")
	// Deprecated: use VaultManagerNexusOld.
	VaultManagerOld = VaultManagerNexusOld
	VaultManager    = common.HexToAddress("0x7904299b3D3dC1b03d1DdEb45E9fDF3576aCBd5f")
	// Stub for unit tests only — never schedule live VaultMigrationBlock to this.
	VaultManagerV2 = common.HexToAddress("0x1111111111111111111111111111111111111111")
)
