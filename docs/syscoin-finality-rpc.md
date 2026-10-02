# Syscoin finality RPC selectors

On Syscoin NEVM, `safe` and `finalized` identify the same executed NEVM block:
the block paired with Core's latest published, durably accepted ChainLock on the
active chain. Further execution alone cannot advance either selector. If
ChainLocks pause, the last accepted boundary remains available.

Core re-advertises `finality-v1:<nevmHeight>:<sysHash>` through the existing
`nevmcomms` channel during its five-second maintenance cycle, after enforcement
and recovery checks. `sysHash` uses Core's usual display order. Geth checks the
canonical executed header and its stored Syscoin pairing before acknowledging
the exact command. Unexecuted, mismatched, or regressing updates are refused;
the update does not flush buffered blocks or write a new durability record.

RPC finality lookup reads a local cached header and makes no Core RPC or IPC
call. Certificate verification and durable storage remain in Core. Geth keeps
this projection only in memory, ignoring generic engine finality markers for
these Syscoin selectors. After restart, Core must replay an accepted boundary.
Removing the projected block during paired rollback or recovery also clears the
projection until Core supplies a valid boundary again.

Before a valid boundary is received, these selectors return the existing
`safe block not found` or `finalized block not found` errors. Clients requiring
finality should wait and retry. `latest` and numeric selectors continue to expose
executed blocks. Ordinary Ethereum networks retain their existing safe/finalized
head behavior.
