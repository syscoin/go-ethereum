// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// SYSCOIN: Security regression coverage.
package downloader

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

func newRawDeliveryQueue(t *testing.T, receipt bool, reserve bool) (*queue, *types.Block) {
	t.Helper()
	q := newQueue(10, 10)
	q.Prepare(1, SnapSync)
	block := chain.blocks[0]
	q.Schedule([]*types.Header{block.Header()}, []common.Hash{block.Hash()}, 1)
	if reserve {
		var req *fetchRequest
		if receipt {
			req, _, _ = q.ReserveReceipts(dummyPeer("raw-peer"), 1)
		} else {
			req, _, _ = q.ReserveBodies(dummyPeer("raw-peer"), 1)
		}
		if req == nil {
			t.Fatal("fixture did not reserve a request")
		}
	}
	return q, block
}

func TestRawDeliveryAuthenticatesBeforeDecoding(t *testing.T) {
	for _, receipt := range []bool{false, true} {
		for _, requested := range []bool{false, true} {
			q, block := newRawDeliveryQueue(t, receipt, requested)
			decoded := false
			var err error
			if receipt {
				_, err = q.deliverReceipts("raw-peer", 1, []common.Hash{common.MaxHash}, func(int) ([]*types.Receipt, error) {
					decoded = true
					t.Fatal("unrequested or wrong-root receipts reached the decoder")
					return nil, nil
				})
			} else {
				h := block.Header()
				_, err = q.deliverBodies("raw-peer", 1, []common.Hash{common.MaxHash}, []common.Hash{h.UncleHash}, nil,
					func(int) bool { return false }, func(int) (*eth.BlockBody, error) {
						decoded = true
						t.Fatal("unrequested or wrong-root body reached the decoder")
						return nil, nil
					})
			}
			if err == nil || decoded {
				t.Fatalf("unauthenticated response: error %v, decoded %v", err, decoded)
			}
		}
	}
}

func TestRawBodyDelivery(t *testing.T) {
	q, block := newRawDeliveryQueue(t, false, true)
	txs, _ := rlp.EncodeToBytes(block.Transactions())
	uncles, _ := rlp.EncodeToBytes(block.Uncles())
	body := eth.BlockBodyRLP{Transactions: txs, Uncles: uncles}
	h := block.Header()
	accepted, err := q.DeliverBodiesRLP("raw-peer", eth.BlockBodiesRawResponse{body}, [][]common.Hash{{h.TxHash}, {h.UncleHash}, {{}}})
	if err != nil || accepted != 1 {
		t.Fatalf("valid raw body: accepted %d, error %v", accepted, err)
	}
	if _, err := q.DeliverBodiesRLP("raw-peer", eth.BlockBodiesRawResponse{body}, [][]common.Hash{{h.TxHash}, {h.UncleHash}, {{}}}); err == nil {
		t.Fatal("duplicate raw body accepted")
	}
}

func TestRawReceiptDelivery(t *testing.T) {
	receipts := types.Receipts{{Status: 1, CumulativeGasUsed: 21000, Logs: []*types.Log{{Address: common.Address{1}, Topics: []common.Hash{{2}}, Data: []byte{3}}}}}
	encoded, err := rlp.EncodeToBytes(receipts)
	if err != nil {
		t.Fatal(err)
	}
	header := chain.blocks[0].Header()
	header.ReceiptHash = types.DeriveSha(receipts, trie.NewStackTrie(nil))
	q := newQueue(10, 10)
	q.Prepare(1, SnapSync)
	q.Schedule([]*types.Header{header}, []common.Hash{header.Hash()}, 1)
	if req, _, _ := q.ReserveReceipts(dummyPeer("raw-peer"), 1); req == nil {
		t.Fatal("fixture did not reserve receipts")
	}
	accepted, err := q.DeliverReceiptsRLP("raw-peer", eth.ReceiptsRLPResponse{encoded}, []common.Hash{header.ReceiptHash})
	if err != nil || accepted != 1 {
		t.Fatalf("valid raw receipts: accepted %d, error %v", accepted, err)
	}
}
