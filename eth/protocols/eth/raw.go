// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// SYSCOIN: Bounded peer-response decoding and validation.
package eth

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/tracker"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

const (
	minTxEncodedSize         = 1 + 9
	minWithdrawalEncodedSize = 1 + 3 + 21
	// ETH/68 receipts include the bloom (unlike the ETH/69 wire encoding).
	minReceiptEncodedSize = 3 + 1 + 1 + 3 + types.BloomByteLength + 1
)

// BlockBodyRLP retains the nested lists until their roots have been checked
// against a requested header. The optional withdrawals list retains the
// distinction between absent and present-but-empty withdrawals.
type BlockBodyRLP struct {
	Transactions rlp.RawValue
	Uncles       rlp.RawValue
	Withdrawals  rlp.RawValue `rlp:"optional"`
}

type BlockBodiesRawResponse []BlockBodyRLP

func (b *BlockBodyRLP) validate() error {
	if _, err := newRawDerivableList(b.Transactions, minTxEncodedSize, true); err != nil {
		return fmt.Errorf("transactions: %w", err)
	}
	if _, rest, err := rlp.SplitList(b.Uncles); err != nil {
		return fmt.Errorf("uncles: %w", err)
	} else if len(rest) != 0 {
		return fmt.Errorf("uncles: trailing list data")
	}
	if b.Withdrawals != nil {
		if _, err := newRawDerivableList(b.Withdrawals, minWithdrawalEncodedSize, false); err != nil {
			return fmt.Errorf("withdrawals: %w", err)
		}
	}
	return nil
}

// Decode must only be called after all body roots have been authenticated.
func (b *BlockBodyRLP) Decode() (*BlockBody, error) {
	body := new(BlockBody)
	if err := rlp.DecodeBytes(b.Transactions, &body.Transactions); err != nil {
		return nil, err
	}
	if err := rlp.DecodeBytes(b.Uncles, &body.Uncles); err != nil {
		return nil, err
	}
	if b.Withdrawals != nil {
		if err := rlp.DecodeBytes(b.Withdrawals, &body.Withdrawals); err != nil {
			return nil, err
		}
	}
	return body, nil
}

func (b BlockBodiesRawResponse) hashes() ([][]common.Hash, error) {
	txs := make([]common.Hash, len(b))
	uncles := make([]common.Hash, len(b))
	withdrawals := make([]common.Hash, len(b))
	hasher := trie.NewStackTrie(nil)
	for i := range b {
		if err := b[i].validate(); err != nil {
			return nil, err
		}
		list, err := newRawDerivableList(b[i].Transactions, minTxEncodedSize, true)
		if err != nil {
			return nil, err
		}
		txs[i] = types.DeriveSha(list, hasher)
		uncles[i] = crypto.Keccak256Hash(b[i].Uncles)
		if b[i].Withdrawals != nil {
			list, err = newRawDerivableList(b[i].Withdrawals, minWithdrawalEncodedSize, false)
			if err != nil {
				return nil, err
			}
			withdrawals[i] = types.DeriveSha(list, hasher)
		}
	}
	return [][]common.Hash{txs, uncles, withdrawals}, nil
}

func (r ReceiptsRLPResponse) hashes() ([]common.Hash, error) {
	hashes := make([]common.Hash, len(r))
	hasher := trie.NewStackTrie(nil)
	for i, raw := range r {
		list, err := newRawDerivableList(raw, minReceiptEncodedSize, true)
		if err != nil {
			return nil, err
		}
		hashes[i] = types.DeriveSha(list, hasher)
	}
	return hashes, nil
}

// transactionAnnouncementsDecoder checks all parallel list lengths before
// allocating integer or hash slices. In particular, a short Types field cannot
// authorize an independently huge Sizes list.
type transactionAnnouncementsDecoder struct {
	packet *NewPooledTransactionHashesPacket
}

func (d *transactionAnnouncementsDecoder) DecodeRLP(s *rlp.Stream) error {
	var raw struct {
		Types  rlp.RawValue
		Sizes  rlp.RawValue
		Hashes rlp.RawValue
	}
	if err := s.Decode(&raw); err != nil {
		return err
	}
	types, _, err := rlp.SplitString(raw.Types)
	if err != nil {
		return err
	}
	if len(types) > maxTransactionAnnouncements {
		return tracker.ErrResponseLimit
	}
	for _, list := range []rlp.RawValue{raw.Sizes, raw.Hashes} {
		content, _, err := rlp.SplitList(list)
		if err != nil {
			return err
		}
		count, err := rlp.CountValues(content)
		if err != nil {
			return err
		}
		if count > maxTransactionAnnouncements {
			return tracker.ErrResponseLimit
		}
		if count != len(types) {
			return fmt.Errorf("invalid transaction announcement field lengths")
		}
	}
	d.packet.Types = types
	if err := rlp.DecodeBytes(raw.Sizes, &d.packet.Sizes); err != nil {
		return err
	}
	return rlp.DecodeBytes(raw.Hashes, &d.packet.Hashes)
}

// rawDerivableList hashes a serialized list without materializing its items or
// an attacker-sized offset table. DeriveSha visits all but index zero in order;
// rewinding for index zero requires at most one extra pass over the first 128
// items. The minimum size and kind checks also reject empty trie values before
// DeriveSha, whose hasher errors are intentionally ignored by that API.
type rawDerivableList struct {
	content   []byte
	remaining []byte
	count     int
	next      int
	typed     bool
}

func newRawDerivableList(raw []byte, minSize int, typed bool) (*rawDerivableList, error) {
	content, rest, err := rlp.SplitList(raw)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing list data")
	}
	list := &rawDerivableList{content: content, remaining: content, typed: typed}
	for rest = content; len(rest) != 0; list.count++ {
		kind, value, tail, err := rlp.Split(rest)
		if err != nil {
			return nil, err
		}
		if len(rest)-len(tail) < minSize || (kind != rlp.List && (!typed || kind != rlp.String || len(value) == 0)) {
			return nil, fmt.Errorf("invalid list item %d", list.count)
		}
		rest = tail
	}
	return list, nil
}

func (l *rawDerivableList) Len() int { return l.count }

func (l *rawDerivableList) EncodeIndex(i int, buf *bytes.Buffer) {
	if i < l.next {
		l.remaining, l.next = l.content, 0
	}
	for l.next < i {
		_, _, l.remaining, _ = rlp.Split(l.remaining)
		l.next++
	}
	kind, value, tail, _ := rlp.Split(l.remaining)
	if l.typed && kind == rlp.String {
		buf.Write(value) // EIP-2718 consensus encoding omits the RLP string wrapper.
	} else {
		buf.Write(l.remaining[:len(l.remaining)-len(tail)])
	}
	l.remaining, l.next = tail, i+1
}
