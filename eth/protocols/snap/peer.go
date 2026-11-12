// Copyright 2020 The go-ethereum Authors
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

package snap

import (
	"time" // SYSCOIN: Expire response reservations.

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/tracker" // SYSCOIN: Enforce request-specific response limits.
)

// SYSCOIN BEGIN: Allow bounded framing slack for soft range-response byte limits.
// rangeResponseSlack allows one final account or storage slot and its RLP
// framing when the server exceeds a small, soft request byte limit.
const rangeResponseSlack = 1024

// SYSCOIN END: Allow bounded framing slack for soft range-response byte limits.

// Peer is a collection of relevant information we have about a `snap` peer.
type Peer struct {
	id string // Unique ID for the peer, cached

	*p2p.Peer                          // The embedded P2P package peer
	rw        p2p.MsgReadWriter        // Input/output streams for snap
	version   uint                     // Protocol version negotiated
	responses *tracker.ResponseTracker // SYSCOIN: Concrete limits for active requests.

	logger log.Logger // Contextual logger with the peer id injected
}

// NewPeer creates a wrapper for a network connection and negotiated  protocol
// version.
func NewPeer(version uint, p *p2p.Peer, rw p2p.MsgReadWriter) *Peer {
	id := p.ID().String()
	return &Peer{
		id:        id,
		Peer:      p,
		rw:        rw,
		version:   version,
		responses: tracker.NewResponseTracker(time.Minute), // SYSCOIN: Bound response lifetimes.
		logger:    log.New("peer", id[:8]),
	}
}

// NewFakePeer creates a fake snap peer without a backing p2p peer, for testing purposes.
func NewFakePeer(version uint, id string, rw p2p.MsgReadWriter) *Peer {
	return &Peer{
		id:        id,
		rw:        rw,
		version:   version,
		responses: tracker.NewResponseTracker(time.Minute), // SYSCOIN: Bound response lifetimes.
		logger:    log.New("peer", id[:8]),
	}
}

// ID retrieves the peer's unique identifier.
func (p *Peer) ID() string {
	return p.id
}

// Version retrieves the peer's negotiated `snap` protocol version.
func (p *Peer) Version() uint {
	return p.version
}

// Log overrides the P2P logger with the higher level one containing only the id.
func (p *Peer) Log() log.Logger {
	return p.logger
}

// RequestAccountRange fetches a batch of accounts rooted in a specific account
// trie, starting with the origin.
func (p *Peer) RequestAccountRange(id uint64, root common.Hash, origin, limit common.Hash, bytes uint64) error {
	p.logger.Trace("Fetching range of accounts", "reqid", id, "root", root, "origin", origin, "limit", limit, "bytes", common.StorageSize(bytes))

	requestTracker.Track(p.id, p.version, GetAccountRangeMsg, AccountRangeMsg, id)
	// SYSCOIN: Reserve item and byte budgets before sending the request.
	return p.sendRequest(id, GetAccountRangeMsg, AccountRangeMsg, tracker.ResponseLimits{Items: -1, Bytes: 2*min(bytes, uint64(softResponseLimit)) + rangeResponseSlack, ProofItems: 128}, &GetAccountRangePacket{
		ID:     id,
		Root:   root,
		Origin: origin,
		Limit:  limit,
		Bytes:  bytes,
	})
}

// RequestStorageRanges fetches a batch of storage slots belonging to one or more
// accounts. If slots from only one account is requested, an origin marker may also
// be used to retrieve from there.
func (p *Peer) RequestStorageRanges(id uint64, root common.Hash, accounts []common.Hash, origin, limit []byte, bytes uint64) error {
	if len(accounts) == 1 && origin != nil {
		p.logger.Trace("Fetching range of large storage slots", "reqid", id, "root", root, "account", accounts[0], "origin", common.BytesToHash(origin), "limit", common.BytesToHash(limit), "bytes", common.StorageSize(bytes))
	} else if len(accounts) > 0 { // SYSCOIN: Avoid indexing an empty request while logging.
		p.logger.Trace("Fetching ranges of small storage slots", "reqid", id, "root", root, "accounts", len(accounts), "first", accounts[0], "bytes", common.StorageSize(bytes))
	}
	requestTracker.Track(p.id, p.version, GetStorageRangesMsg, StorageRangesMsg, id)
	// SYSCOIN: Reserve item and byte budgets before sending the request.
	return p.sendRequest(id, GetStorageRangesMsg, StorageRangesMsg, tracker.ResponseLimits{Items: len(accounts), Bytes: 2*min(bytes, uint64(softResponseLimit)) + rangeResponseSlack, ProofItems: 128}, &GetStorageRangesPacket{
		ID:       id,
		Root:     root,
		Accounts: accounts,
		Origin:   origin,
		Limit:    limit,
		Bytes:    bytes,
	})
}

// RequestByteCodes fetches a batch of bytecodes by hash.
func (p *Peer) RequestByteCodes(id uint64, hashes []common.Hash, bytes uint64) error {
	p.logger.Trace("Fetching set of byte codes", "reqid", id, "hashes", len(hashes), "bytes", common.StorageSize(bytes))

	requestTracker.Track(p.id, p.version, GetByteCodesMsg, ByteCodesMsg, id)
	// SYSCOIN: Reserve item and byte budgets before sending the request.
	return p.sendRequest(id, GetByteCodesMsg, ByteCodesMsg, tracker.ResponseLimits{Items: len(hashes), Bytes: maxMessageSize}, &GetByteCodesPacket{
		ID:     id,
		Hashes: hashes,
		Bytes:  bytes,
	})
}

// RequestTrieNodes fetches a batch of account or storage trie nodes rooted in
// a specific state trie.
func (p *Peer) RequestTrieNodes(id uint64, root common.Hash, paths []TrieNodePathSet, bytes uint64) error {
	p.logger.Trace("Fetching set of trie nodes", "reqid", id, "root", root, "pathsets", len(paths), "bytes", common.StorageSize(bytes))

	requestTracker.Track(p.id, p.version, GetTrieNodesMsg, TrieNodesMsg, id)
	// SYSCOIN BEGIN: Count the actual trie nodes requested for response validation.
	count := 0
	for _, pathset := range paths {
		if len(pathset) == 1 {
			count++
		} else if len(pathset) > 1 {
			count += len(pathset) - 1
		}
	}
	// SYSCOIN END: Count the actual trie nodes requested for response validation.
	// SYSCOIN: Reserve item and byte budgets before sending the request.
	return p.sendRequest(id, GetTrieNodesMsg, TrieNodesMsg, tracker.ResponseLimits{Items: count, Bytes: maxMessageSize}, &GetTrieNodesPacket{
		ID:    id,
		Root:  root,
		Paths: paths,
		Bytes: bytes,
	})
}

// SYSCOIN BEGIN: Track response limits before sending and release failed reservations.
func (p *Peer) sendRequest(id, code, response uint64, limits tracker.ResponseLimits, packet interface{}) error {
	if err := p.responses.Track(id, response, limits); err != nil {
		return err
	}
	if err := p2p.Send(p.rw, code, packet); err != nil {
		p.responses.Forget(id)
		return err
	}
	return nil
}

// SYSCOIN END: Track response limits before sending and release failed reservations.
