# Read-only Syscoin DA candidate lookup

`eth_getDataHashInclusions(hashes, beforeHeight?, maxBlocks?)` locates candidate
Core blocks after expiring blob metadata prevents `getnevmblobdata` from finding
the publication. The lookup accepts 1–64 distinct nonzero 32-byte hashes and
scans at most 1,024 heights per request (256 by default). Heights and counts use
Ethereum hexadecimal quantities. `beforeHeight` is inclusive and defaults to
the current full-block head. Scanning never leaves the retained 50,001-height
DA window, and genesis is excluded.

The response reports `chainId`, `headNumber`, `headHash`, `searchedFrom`,
`searchedTo`, `inclusions`, `nextBefore`, and `exhausted`. Empty ranges omit the
searched bounds; exhausted ranges omit `nextBefore`. Each inclusion contains
`dataHash`, `nevmBlockNumber`, `nevmBlockHash`, and `syscoinBlockHash`. The Core
hash uses Core JSON RPC display byte order. Each page returns at most the newest
candidate for each requested hash. A subsequent page can return older candidates.

These are untrusted locators, **not confirmation or finality evidence**. Legacy
journals and pairings can survive a crash, abandoned import, or rewind. The caller
must independently fetch the indicated Core block, verify that a correctly typed
NEVM transaction commits the exact requested digest, and verify that block's
canonical confirmations or ChainLock under its configured policy. A matching
NEVM precompile response is a separate contract-eligibility check. A missing or
exhausted lookup does not establish that the data was never published.

This RPC reads the existing journals under the blockchain mutex. It does not
change the precompile, caches, consensus index, database format, or activation
rules. Corrupt journals, missing candidate headers and invalid Core pairings
return an error. Request cancellation stops the bounded scan.
