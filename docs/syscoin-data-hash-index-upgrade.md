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
pruned history floor fails closed and requires resynchronization. Resetting to
genesis remains supported.

A paired Core disconnect preflights this history before moving the head. An
unavailable rollback returns an error without changing the head or membership,
so the existing database remains restartable. It does not recover missing
journals; ensure the required rollback history is available before activation.

This repair covers only DA-hash membership. Generic `SetHead` does not have the
Core payloads needed to undo every Syscoin hash, BTC checkpoint, or NEVM address
mapping. Production rollback must continue through paired Core disconnects;
generic rewind is not a complete Syscoin metadata recovery procedure.

Syscoin imports must extend the current canonical head through Core's paired
connect path. Execution-only side imports and direct sidechain promotion are
rejected; `SetCanonical` permits only the current head or the immediate parent
step used by paired disconnect. Same-height DA writes are exact retries only,
not replacements; a different pairing requires disconnect followed by reconnect.
