// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package snap

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/rlp"
)

func encodePathList(content []byte) []byte {
	w := rlp.NewEncoderBuffer(nil)
	list := w.List()
	w.Write(content)
	w.ListEnd(list)
	encoded := w.ToBytes()
	w.Flush()
	return encoded
}

func TestTrieNodePathDecodingDoesNotExpandLists(t *testing.T) {
	for _, content := range [][]byte{
		bytes.Repeat([]byte{0xc0}, 1000000),                 // Empty pathsets.
		bytes.Repeat([]byte{0xc1, 0x80}, 1000000),           // One empty path per set.
		encodePathList(bytes.Repeat([]byte{0x80}, 1000000)), // One large pathset.
	} {
		raw := encodePathList(content)
		if len(raw) > maxMessageSize {
			t.Fatal("fixture exceeds wire limit")
		}
		allocs := testing.AllocsPerRun(1, func() {
			if _, err := newTrieNodePathIterator(raw); err != nil {
				t.Fatal(err)
			}
		})
		if allocs != 0 {
			t.Fatalf("path shape validation expanded lists: %.0f allocations", allocs)
		}
	}
}

func TestTrieNodePathShape(t *testing.T) {
	for _, raw := range [][]byte{{0x80}, {0xc1, 0x80}, {0xc2, 0xc1, 0xc0}, {0xc2, 0xc1, 0xb8}, {0xc0, 0xc0}} {
		if _, err := newTrieNodePathIterator(raw); err == nil {
			t.Fatalf("accepted invalid path encoding %x", raw)
		}
	}
	raw, err := rlp.EncodeToBytes([]TrieNodePathSet{{{1}}, {{2}, {3}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newTrieNodePathIterator(raw); err != nil {
		t.Fatalf("valid paths rejected: %v", err)
	}
}
