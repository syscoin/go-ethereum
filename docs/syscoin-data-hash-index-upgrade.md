# Syscoin data-hash index upgrade

The data-hash precompile is consensus-visible. This upgrade replaces its
one-byte presence entries with reference counts and makes the persisted index,
not an in-memory cache, authoritative. The membership window remains exactly
50,001 blocks.

Deploy all block-producing and validating Syscoin NEVM nodes together while
stopped. Do not run old and new binaries against the same database, perform a
rolling mixed-version deployment, or downgrade after the new binary writes the
database. Old code overwrites reference counts with a one-byte sentinel and
deletes rollback journal entries. No activation height is embedded in this
patch. Before a live L1 release, protocol operators must choose and validate a
coordinated historical-index rebuild or add an explicit consensus activation;
the local regression tests do not authorize an immediate network cutover.

On first startup the node atomically rebuilds membership from the retained
50,001-block per-height journal. Rewind coverage then grows by one block per
new canonical block, up to 50,001 blocks. A rewind crossing the pre-upgrade or
pruned history floor fails closed and requires explicit recovery. The DA index
alone can reset to genesis; a full metadata rewind must also have address undo
coverage and usable trie state.

A paired Core disconnect preflights this history and requires available parent
state before moving the head. It commits head/canonical/transaction indexes and
DA/SYS/BTC/NEVM rollback metadata in one database batch under the chain lock,
then publishes caches, head markers and events. A rejected or failed batch leaves
the head and metadata unchanged. This does not recover missing journals or
unavailable parent state; ensure rollback history is available before activation.

Missing-state startup and local `BlockChain.SetHead` use bounded metadata
recovery. Each new canonical block atomically records the previous values of
only the NEVM addresses it touched, bound to its NEVM/SYS pair. Empty records
distinguish unchanged blocks from missing history. The last 50,001 undo records
are retained; the live address map is not pruned. Existing databases gain
coverage only as new blocks are committed: no historical address values are
invented at upgrade. Normal Core disconnects still use Core's inverse diff and
remove the corresponding local undo record in the same batch.

Recovery selects the actual state/snapshot target and preflights DA and address
history before any recovery writes. It commits the reconstructed DA window,
reverse address changes, SYS/BTC indexes and head markers together. Block
bodies and receipts remain for replay, which still requires Core's pairing
payloads. Direct header-only rewinds are rejected; RPC/configuration rewind
errors are propagated. Missing undo, out-of-window targets, inconsistent old
head markers, and rewinds into immutable ancient storage require explicit
rebuild instead of partial metadata repair.

Path-trie history recovery is allowed only during missing-state startup. Its
separate trie writes precede the final metadata batch; on failure the unchanged
head markers and undo records permit a later restart to retry. A live rewind
that would require those trie mutations is refused. No new Core/ZMQ protocol
or consensus rule is introduced by address undo. Core's existing finality and
startup alignment restrictions still apply; this is not a promise of automatic
recovery through finalized Core history.

Syscoin imports must extend the current canonical head through Core's paired
connect path. Execution-only side imports and direct sidechain promotion are
rejected; `SetCanonical` permits only the current head. Paired disconnects use
the atomic Core rollback path. Same-height DA writes are exact retries only,
not replacements; a different pairing requires disconnect followed by reconnect.
