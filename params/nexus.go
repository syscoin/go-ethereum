package params

import (
	"github.com/ethereum/go-ethereum/common"
)

// Vault manager addresses for Syscoin NEVM bridge cutovers.
//
// Nexus (activated): VaultManagerNexusOld → VaultManager
// Bridge V2 (at VaultMigrationBlock): VaultManager → VaultManagerV2
//
// Replace VaultManagerV2 with the deployed replacement vault proxy before
// setting VaultMigrationBlock. Do not couple this to LibertyBlock on networks
// where Liberty already activated historically (e.g. Tanenbaum 906001).
var (
	VaultManagerNexusOld = common.HexToAddress("0xA738a563F9ecb55e0b2245D1e9E380f0fE455ea1")
	VaultManager         = common.HexToAddress("0x7904299b3D3dC1b03d1DdEb45E9fDF3576aCBd5f")
	// Stub until replacement vault proxy is deployed at this address.
	VaultManagerV2 = common.HexToAddress("0x1111111111111111111111111111111111111111")
)
