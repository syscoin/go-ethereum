// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// SYSCOIN: Security regression coverage.
package eth

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/p2p/tracker"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

func encodeRawList(content []byte) []byte {
	w := rlp.NewEncoderBuffer(nil)
	list := w.List()
	w.Write(content)
	w.ListEnd(list)
	encoded := w.ToBytes()
	w.Flush()
	return encoded
}

func TestTransactionBroadcastDecodeLimit(t *testing.T) {
	minimal := types.NewTx(&types.LegacyTx{})
	raw, err := rlp.EncodeToBytes(minimal)
	if err != nil {
		t.Fatal(err)
	}
	for _, count := range []int{maxTransactionAnnouncements, maxTransactionAnnouncements + 1, 1000000} {
		encoded := encodeRawList(bytes.Repeat(raw, count))
		if len(encoded) > maxMessageSize {
			t.Fatal("hostile fixture exceeds wire limit")
		}
		peer := &Peer{knownTxs: newKnownCache(maxKnownTxs)}
		err := handleTransactions(new(testBackend), decoder{encoded}, peer)
		if count <= maxTransactionAnnouncements {
			if err != nil || !peer.knownTxs.Contains(minimal.Hash()) {
				t.Fatalf("valid broadcast: %v", err)
			}
		} else if err == nil || !strings.Contains(err.Error(), tracker.ErrResponseLimit.Error()) {
			t.Fatalf("oversized broadcast of %d transactions: %v", count, err)
		}
		if count == 1000000 {
			allocs := testing.AllocsPerRun(1, func() { handleTransactions(new(testBackend), decoder{encoded}, peer) })
			if allocs > 100 {
				t.Fatalf("oversized broadcast allocated transaction objects: %.0f allocations", allocs)
			}
		}
	}
}

func TestRawResponseShape(t *testing.T) {
	minimalTx, _ := rlp.EncodeToBytes(types.NewTx(&types.LegacyTx{}))
	minimalWithdrawal, _ := rlp.EncodeToBytes(&types.Withdrawal{})
	minimalReceipt, _ := rlp.EncodeToBytes(&types.Receipt{})
	for _, tc := range []struct {
		name  string
		raw   []byte
		min   int
		typed bool
	}{
		{"transaction", minimalTx, minTxEncodedSize, true},
		{"withdrawal", minimalWithdrawal, minWithdrawalEncodedSize, false},
		{"receipt", minimalReceipt, minReceiptEncodedSize, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.raw) != tc.min {
				t.Fatalf("minimal wire encoding has %d bytes, want %d", len(tc.raw), tc.min)
			}
			if _, err := newRawDerivableList(encodeRawList(tc.raw), tc.min, tc.typed); err != nil {
				t.Fatalf("minimal item rejected: %v", err)
			}
			for _, tiny := range [][]byte{{0x80}, {0xc0}, {0xc1, 0x80}} {
				if _, err := newRawDerivableList(encodeRawList(bytes.Repeat(tiny, 100000)), tc.min, tc.typed); err == nil {
					t.Fatal("tiny item amplification accepted")
				}
			}
		})
	}
}

func TestRawResponseRejectsNestedShapeBeforeDispatch(t *testing.T) {
	tiny := rlp.RawValue(encodeRawList(bytes.Repeat([]byte{0xc1, 0x80}, 100000)))
	for _, test := range []struct {
		name    string
		code    uint64
		handler msgHandler
		items   interface{}
	}{
		{"transactions", BlockBodiesMsg, handleBlockBodies, []BlockBodyRLP{{Transactions: tiny, Uncles: rlp.RawValue{0xc0}}}},
		{"withdrawals", BlockBodiesMsg, handleBlockBodies, []BlockBodyRLP{{Transactions: rlp.RawValue{0xc0}, Uncles: rlp.RawValue{0xc0}, Withdrawals: tiny}}},
		{"receipts", ReceiptsMsg, handleReceipts, []rlp.RawValue{tiny}},
	} {
		t.Run(test.name, func(t *testing.T) {
			peer := &Peer{responses: tracker.NewResponseTracker(time.Minute)}
			if err := peer.responses.Track(7, test.code, tracker.ResponseLimits{Items: 1, Bytes: maxMessageSize}); err != nil {
				t.Fatal(err)
			}
			encoded, err := rlp.EncodeToBytes([]interface{}{uint64(7), test.items})
			if err != nil {
				t.Fatal(err)
			}
			// The peer has no dispatcher: reaching dispatch instead of rejecting
			// the nested shape would block this test.
			done := make(chan error, 1)
			go func() { done <- test.handler(new(testBackend), decoder{encoded}, peer) }()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "invalid list item") {
					t.Fatalf("nested shape not rejected: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("invalid nested shape reached dispatch")
			}
		})
	}
}

func TestTransactionAnnouncementDecodeLimit(t *testing.T) {
	for _, field := range []string{"types", "sizes", "hashes", "valid"} {
		t.Run(field, func(t *testing.T) {
			count := maxTransactionAnnouncements
			ann := NewPooledTransactionHashesPacket{Types: make([]byte, count), Sizes: make([]uint32, count), Hashes: make([]common.Hash, count)}
			var packet interface{} = &ann
			switch field {
			case "types":
				ann.Types = make([]byte, count+1)
			case "sizes":
				packet = []interface{}{[]byte{0}, rlp.RawValue(encodeRawList(bytes.Repeat([]byte{0x80}, 1000000))), []common.Hash{{}}}
			case "hashes":
				ann.Hashes = make([]common.Hash, count+1)
			}
			encoded, err := rlp.EncodeToBytes(packet)
			if err != nil {
				t.Fatal(err)
			}
			var decoded NewPooledTransactionHashesPacket
			err = rlp.DecodeBytes(encoded, &transactionAnnouncementsDecoder{&decoded})
			if field == "valid" {
				if err != nil || len(decoded.Hashes) != count {
					t.Fatalf("valid announcement: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tracker.ErrResponseLimit.Error()) || decoded.Sizes != nil || decoded.Hashes != nil {
				t.Fatalf("oversized %s decoded: %v", field, err)
			}
		})
	}
}

func TestRawBodyAndReceiptHashing(t *testing.T) {
	txs := make(types.Transactions, 260)
	for i := range txs {
		switch i % 3 {
		case 0:
			txs[i] = types.NewTx(&types.LegacyTx{Nonce: uint64(i)})
		case 1:
			txs[i] = types.NewTx(&types.AccessListTx{Nonce: uint64(i)})
		case 2:
			txs[i] = types.NewTx(&types.DynamicFeeTx{Nonce: uint64(i)})
		}
	}
	// A consensus body is not subject to the mempool's individual size limit.
	txs[0] = types.NewTx(&types.LegacyTx{Data: make([]byte, 256*1024)})
	wds := types.Withdrawals{{Index: 1, Address: common.Address{1}}}
	uncles := []*types.Header{{Number: common.Big1}}
	for _, withdrawals := range []types.Withdrawals{nil, {}, wds} {
		body := &BlockBody{Transactions: txs, Uncles: uncles, Withdrawals: withdrawals}
		encoded, err := rlp.EncodeToBytes(body)
		if err != nil {
			t.Fatal(err)
		}
		var raw BlockBodyRLP
		if err := rlp.DecodeBytes(encoded, &raw); err != nil {
			t.Fatal(err)
		}
		if err := raw.validate(); err != nil {
			t.Fatal(err)
		}
		hashes, err := (BlockBodiesRawResponse{raw}).hashes()
		if err != nil {
			t.Fatal(err)
		}
		hasher := trie.NewStackTrie(nil)
		if hashes[0][0] != types.DeriveSha(txs, hasher) || hashes[1][0] != types.CalcUncleHash(uncles) {
			t.Fatal("raw body roots differ from decoded roots")
		}
		if withdrawals != nil && hashes[2][0] != types.DeriveSha(withdrawals, hasher) {
			t.Fatal("raw withdrawal root differs")
		}
		decoded, err := raw.Decode()
		if err != nil || len(decoded.Transactions) != len(txs) || (decoded.Withdrawals == nil) != (withdrawals == nil) {
			t.Fatalf("body round trip: %v", err)
		}
	}
	receipts := make(types.Receipts, 260)
	for i := range receipts {
		receipts[i] = &types.Receipt{Type: txs[i].Type(), Status: 1, CumulativeGasUsed: uint64(i + 1), Logs: []*types.Log{{Address: common.Address{byte(i)}, Topics: []common.Hash{{1}}, Data: []byte{1, 2}}}}
	}
	encoded, err := rlp.EncodeToBytes(receipts)
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := (ReceiptsRLPResponse{encoded}).hashes()
	if err != nil {
		t.Fatal(err)
	}
	if got := hashes[0]; got != types.DeriveSha(receipts, trie.NewStackTrie(nil)) {
		t.Fatal("raw receipt root differs from decoded root")
	}
}
