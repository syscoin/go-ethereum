// Copyright 2026 The go-ethereum Authors
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

// SYSCOIN: Security regression coverage.
package snap

import (
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
)

// Zero-read lookups, including cached misses and failed node encodings, must
// consume the trie-node budget even though they don't add response bytes.
func TestTrieNodesZeroReadLookupCap(t *testing.T) {
	address := common.HexToAddress("0x1234")
	slot := common.HexToHash("0x01")
	genesis := &core.Genesis{
		Config: params.TestChainConfig,
		Alloc: types.GenesisAlloc{address: {
			Balance: big.NewInt(1),
			Storage: map[common.Hash]common.Hash{slot: common.HexToHash("0x02")},
		}},
	}
	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, genesis, nil, ethash.NewFaker(), vm.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	root := chain.Genesis().Root()
	accountHash := crypto.Keccak256Hash(address.Bytes())
	storageHash := crypto.Keccak256Hash(slot.Bytes())
	// A one-nibble prefix cannot match either 64-nibble leaf path.
	accountMiss := []byte{0x10 | ((accountHash[0]>>4 + 1) & 0x0f)}
	storageMiss := []byte{0x10 | ((storageHash[0]>>4 + 1) & 0x0f)}
	accountFailure := append([]byte{0x20}, accountHash.Bytes()...)

	// Pin the fixture: misses and the failed encoding each resolve no DB nodes.
	accountTrie, err := trie.NewStateTrie(trie.StateTrieID(root), chain.TrieDB())
	if err != nil {
		t.Fatal(err)
	}
	if blob, reads, err := accountTrie.GetNode(accountMiss); err != nil || reads != 0 || len(blob) != 0 {
		t.Fatalf("account miss fixture: blob %x, reads %d, err %v", blob, reads, err)
	}
	if _, reads, err := accountTrie.GetNode(accountFailure); err == nil || reads != 0 {
		t.Fatalf("account failure fixture: reads %d, err %v", reads, err)
	}
	account, err := accountTrie.GetAccountByHash(accountHash)
	if err != nil {
		t.Fatal(err)
	}
	storageTrie, err := trie.NewStateTrie(trie.StorageTrieID(root, accountHash, account.Root), chain.TrieDB())
	if err != nil {
		t.Fatal(err)
	}
	if blob, reads, err := storageTrie.GetNode(storageMiss); err != nil || reads != 0 || len(blob) != 0 {
		t.Fatalf("storage miss fixture: blob %x, reads %d, err %v", blob, reads, err)
	}
	query := func(paths []TrieNodePathSet) [][]byte {
		t.Helper()
		nodes, err := ServiceGetTrieNodesQuery(chain, &GetTrieNodesPacket{Root: root, Paths: paths, Bytes: softResponseLimit}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return nodes
	}
	t.Run("account misses", func(t *testing.T) {
		paths := make([]TrieNodePathSet, maxTrieNodeLookups+64)
		for i := range paths {
			paths[i] = TrieNodePathSet{accountMiss}
		}
		if nodes := query(paths); len(nodes) != maxTrieNodeLookups+1 {
			t.Fatalf("zero-read account lookups escaped budget: have %d nodes, want %d", len(nodes), maxTrieNodeLookups+1)
		}
	})
	t.Run("account failures", func(t *testing.T) {
		paths := make([]TrieNodePathSet, maxTrieNodeLookups+2)
		for i := range paths {
			paths[i] = TrieNodePathSet{accountFailure}
		}
		paths[len(paths)-1] = TrieNodePathSet{nil}
		if nodes := query(paths); len(nodes) != 0 {
			t.Fatalf("zero-read account failures escaped budget: served %d trailing nodes", len(nodes))
		}
	})
	t.Run("storage misses", func(t *testing.T) {
		paths := make(TrieNodePathSet, maxTrieNodeLookups+65)
		paths[0] = accountHash.Bytes()
		for i := 1; i < len(paths); i++ {
			paths[i] = storageMiss
		}
		if nodes := query([]TrieNodePathSet{paths}); len(nodes) == 0 || len(nodes) > maxTrieNodeLookups+1 {
			t.Fatalf("zero-read storage lookups escaped budget: have %d nodes", len(nodes))
		}
	})
	t.Run("ordinary requests", func(t *testing.T) {
		nodes := query([]TrieNodePathSet{{nil}, {accountHash.Bytes(), nil}})
		if len(nodes) != 2 || len(nodes[0]) == 0 || len(nodes[1]) == 0 {
			t.Fatalf("ordinary account/storage nodes not served: %x", nodes)
		}
	})
}
