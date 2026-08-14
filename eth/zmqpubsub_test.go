// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package eth

import "testing"

// SYSCOIN: Core and NEVM exchange uint256 hashes in display order.
func TestEncodeSyscoinDisplayHash(t *testing.T) {
	serialized := make([]byte, 32)
	serialized[0] = 0x01
	serialized[31] = 0xfe
	const expected = "fe00000000000000000000000000000000000000000000000000000000000001"
	if got := encodeSyscoinDisplayHash(serialized); got != expected {
		t.Fatalf("wrong Syscoin display hash: got %s want %s", got, expected)
	}

	const zero = "0000000000000000000000000000000000000000000000000000000000000000"
	if got := encodeSyscoinDisplayHash(nil); got != zero {
		t.Fatalf("missing pairing must fail closed as zero: got %s", got)
	}
}
