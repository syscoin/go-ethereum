// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package pathdb

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/trie/trienode"
)

// SYSCOIN: Measure the extra serialization and batch staging per physical flush
// once a live checkpoint exists. This excludes disk I/O and is not a production
// throughput benchmark. Sizes follow the existing BenchmarkJournal fixture.
func BenchmarkLiveJournalRebase(b *testing.B) {
	for _, count := range []int{100, 3000} {
		b.Run(fmt.Sprintf("%d-nodes-per-layer", count), func(b *testing.B) {
			base := emptyLayer()
			defer base.db.Close()
			defer base.db.diskdb.Close()
			base.db.journaled = true
			var head layer = base
			var first *diffLayer
			for i := 1; i <= maxDiffLayers+1; i++ {
				nodes := make(map[string]*trienode.Node, count)
				for j := 0; j < count; j++ {
					path := make([]byte, 32)
					binary.BigEndian.PutUint64(path, uint64(j))
					blob := make([]byte, 100)
					binary.BigEndian.PutUint64(blob, uint64(i))
					binary.BigEndian.PutUint64(blob[8:], uint64(j))
					nodes[string(path)] = trienode.New(crypto.Keccak256Hash(blob), blob)
				}
				var root common.Hash
				binary.BigEndian.PutUint64(root[:], uint64(i))
				diff := newDiffLayer(head, root, uint64(i), uint64(i),
					newNodeSet(map[common.Hash]map[string]*trienode.Node{{}: nodes}),
					NewStateSetWithOrigin(nil, nil, nil, nil, false))
				if first == nil {
					first = diff
				}
				head = diff
			}
			journal := newLiveJournal(head.(*diffLayer))
			batch := base.db.diskdb.NewBatch()
			if err := journal.write(batch, first.root, first.id); err != nil {
				b.Fatal(err)
			}
			size := batch.ValueSize()
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				batch := base.db.diskdb.NewBatch()
				if err := journal.write(batch, first.root, first.id); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(size), "journal-B/op")
		})
	}
}
