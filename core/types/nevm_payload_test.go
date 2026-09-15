// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package types

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/syscoin/syscoinwire/syscoin/wire"
)

func TestNEVMPayloadDecodedRejection(t *testing.T) {
	n, envelope := nevmPayloadTestConnect(t)
	cause := errors.New("synthetic body commitment result")
	marked := MarkNEVMPayloadError(cause, n.Block)
	for _, err := range []error{marked, fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", marked))} {
		if !errors.Is(err, cause) {
			t.Fatal("marking or wrapping lost the original cause")
		}
		nevmPayloadTestAssertRejection(t, n, err, envelope)
	}
	if got := MarkNEVMPayloadError(nil, n.Block); got != nil {
		t.Fatalf("marked a nil error: %v", got)
	}
	if got := MarkNEVMPayloadError(cause, nil); got != cause {
		t.Fatal("marking without a checked block changed the error")
	}
}

func TestNEVMPayloadProvenanceFailsClosed(t *testing.T) {
	cause := errors.New("synthetic body commitment result")
	tests := []struct {
		name   string
		change func(*NEVMBlockConnect, error) (*NEVMBlockConnect, error)
	}{
		{"nil-receiver", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) { return nil, err }},
		{"missing-provenance", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) { n.payload = nil; return n, err }},
		{"changed-nevm-hash", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) { n.Blockhash[0] ^= 1; return n, err }},
		{"changed-sys-pair", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) {
			n.Sysblockhash = string(common.Hash{9}.Bytes())
			return n, err
		}},
		{"short-sys-pair", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) {
			n.Sysblockhash = n.Sysblockhash[1:]
			return n, err
		}},
		{"missing-block", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) { n.Block = nil; return n, err }},
		{"missing-checked-provenance", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) { n.payload.block = nil; return n, err }},
		{"different-block-pointer", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) {
			n.Block = NewBlockWithHeader(n.Block.Header())
			return n, err
		}},
		{"wrong-error-block", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) {
			return n, MarkNEVMPayloadError(cause, NewBlockWithHeader(n.Block.Header()))
		}},
		{"changed-context-tx-root", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) {
			n.payload.txRoot[0] ^= 1
			return n, err
		}},
		{"changed-context-receipt-root", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) {
			n.payload.receiptRoot[0] ^= 1
			return n, err
		}},
		{"different-context-block-hash", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) {
			n.payload.nevmHash[0] ^= 1
			n.Blockhash = n.payload.nevmHash
			return n, err
		}},
		{"unmarked", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) { return n, cause }},
		{"wrapped-unmarked", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) {
			return n, fmt.Errorf("outer: %w", cause)
		}},
		{"nil-error", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) { return n, nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			n, _ := nevmPayloadTestConnect(t)
			err := MarkNEVMPayloadError(cause, n.Block)
			n, err = test.change(n, err)
			nevmPayloadTestAssertNoRejection(t, n, err)
		})
	}
}

func TestNEVMPayloadRawFingerprint(t *testing.T) {
	var nevmHash, txRoot, receiptRoot, sysHash common.Hash
	for i := 0; i < common.HashLength; i++ {
		nevmHash[i], txRoot[i], receiptRoot[i], sysHash[i] = byte(i), byte(i+32), byte(i+64), byte(i+96)
	}
	n := &NEVMBlockConnect{
		Blockhash: nevmHash, Sysblockhash: string(sysHash[:]),
		payload: &nevmPayloadContext{nevmHash: nevmHash, txRoot: txRoot, receiptRoot: receiptRoot, sysHash: sysHash},
	}
	cause := errors.New("synthetic raw payload result")
	err := n.rejectPayload(cause, []byte("benign local fingerprint fixture"))
	// Independently computed SHA-256 of the literal domain (including NUL),
	// byte values 0..127 in field order, and the fixture string above.
	want := common.HexToHash("40eedc11769e15ed1de925895606a70fee885b59b12bb7e9d72f5e089ec1c0e8")
	gotNEVM, gotSYS, digest, ok := n.PayloadRejection(fmt.Errorf("outer: %w", err))
	if !ok || gotNEVM != nevmHash || gotSYS != sysHash || digest != want || !errors.Is(err, cause) {
		t.Fatalf("raw fingerprint = (%s, %s, %s, %t), want (%s, %s, %s, true)", gotNEVM, gotSYS, digest, ok, nevmHash, sysHash, want)
	}
	copyOfContext := *n.payload
	n.payload = &copyOfContext
	nevmPayloadTestAssertNoRejection(t, n, err)
	for _, missing := range []string{"nevm", "sys"} {
		t.Run("missing-"+missing+"-pair", func(t *testing.T) {
			copy := *n.payload
			if missing == "nevm" {
				copy.nevmHash = common.Hash{}
			} else {
				copy.sysHash = common.Hash{}
			}
			unpaired := &NEVMBlockConnect{payload: &copy}
			if got := unpaired.rejectPayload(cause, []byte("fixture")); got != cause {
				t.Fatal("raw payload with an incomplete pair was marked")
			}
		})
	}
}

func TestNEVMPayloadDeserializeEnvelopeMismatch(t *testing.T) {
	for _, field := range []string{"transaction-root", "receipt-root", "block-hash", "block-hash-and-transaction-root", "block-hash-and-receipt-root"} {
		t.Run(field, func(t *testing.T) {
			envelope := nevmPayloadTestWire(t)
			expected := common.Hash{0xa1, 0xb2, 0xc3}
			switch field {
			case "transaction-root":
				envelope.TxRoot = expected.Bytes()
			case "receipt-root":
				envelope.ReceiptRoot = expected.Bytes()
			case "block-hash":
				envelope.NEVMBlockHash = expected.Bytes()
			case "block-hash-and-transaction-root":
				envelope.NEVMBlockHash, envelope.TxRoot = expected.Bytes(), expected.Bytes()
			case "block-hash-and-receipt-root":
				envelope.NEVMBlockHash, envelope.ReceiptRoot = expected.Bytes(), expected.Bytes()
			}
			var n NEVMBlockConnect
			err := n.Deserialize(nevmPayloadTestSerialize(t, envelope))
			if n.Block == nil || n.payload.block != nil {
				t.Fatal("envelope rejection recorded successful decoded-block provenance")
			}
			if field == "transaction-root" || field == "receipt-root" {
				if !n.HasCommittedRootContradiction(err) {
					t.Fatalf("matched-header root contradiction was not immutable: %v", err)
				}
				nevmPayloadTestAssertNoRejection(t, &n, err)
			} else {
				if n.Block.Hash() == expected || n.HasCommittedRootContradiction(err) {
					t.Fatal("different decoded header cannot authenticate an immutable contradiction")
				}
				nevmPayloadTestAssertRejection(t, &n, err, envelope)
			}
		})
	}
}

func TestNEVMCommittedRootProvenanceFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		change func(*NEVMBlockConnect, error) (*NEVMBlockConnect, error)
	}{
		{"nil-receiver", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) { return nil, err }},
		{"missing-context", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) { n.payload = nil; return n, err }},
		{"copied-context", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) {
			copy := *n.payload
			n.payload = &copy
			return n, err
		}},
		{"missing-block", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) { n.Block = nil; return n, err }},
		{"different-block-pointer", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) {
			n.Block = NewBlockWithHeader(n.Block.Header())
			return n, err
		}},
		{"changed-nevm-hash", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) { n.Blockhash[0] ^= 1; return n, err }},
		{"changed-sys-pair", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) {
			n.Sysblockhash = string(common.Hash{9}.Bytes())
			return n, err
		}},
		{"short-sys-pair", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) {
			n.Sysblockhash = n.Sysblockhash[1:]
			return n, err
		}},
		{"no-root-contradiction", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) {
			n.payload.txRoot, n.payload.receiptRoot = n.Block.TxHash(), n.Block.ReceiptHash()
			return n, err
		}},
		{"unmarked-text", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) { return n, errors.New(err.Error()) }},
		{"wrapped-unmarked-text", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) {
			return n, fmt.Errorf("outer: %w", errors.New(err.Error()))
		}},
		{"nil-error", func(n *NEVMBlockConnect, err error) (*NEVMBlockConnect, error) { return n, nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope := nevmPayloadTestWire(t)
			envelope.TxRoot = common.Hash{0xa1}.Bytes()
			n := new(NEVMBlockConnect)
			err := n.Deserialize(nevmPayloadTestSerialize(t, envelope))
			wrapped := fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", err))
			if !n.HasCommittedRootContradiction(wrapped) || !errors.Is(wrapped, err) {
				t.Fatalf("fixture lost marked contradiction through wrapping: %v", wrapped)
			}
			n, err = test.change(n, err)
			if n.HasCommittedRootContradiction(err) {
				t.Fatal("uncorrelated error authorized an immutable rejection")
			}
		})
	}
}

func TestNEVMCommittedRootDeserializeClearsProvenance(t *testing.T) {
	for _, mode := range []string{"same-contradictory-wire", "valid-wire", "malformed-rlp", "end-of-input"} {
		t.Run(mode, func(t *testing.T) {
			envelope := nevmPayloadTestWire(t)
			envelope.TxRoot = common.Hash{0xa1}.Bytes()
			var n NEVMBlockConnect
			oldErr := n.Deserialize(nevmPayloadTestSerialize(t, envelope))
			if !n.HasCommittedRootContradiction(oldErr) {
				t.Fatalf("fixture did not produce an immutable rejection: %v", oldErr)
			}
			oldBlock, oldContext := n.Block, n.payload
			var err error
			switch mode {
			case "same-contradictory-wire":
				err = n.Deserialize(nevmPayloadTestSerialize(t, envelope))
				if !n.HasCommittedRootContradiction(err) {
					t.Fatalf("new contradictory decode was not authenticated: %v", err)
				}
			case "valid-wire":
				err = n.Deserialize(nevmPayloadTestSerialize(t, nevmPayloadTestWire(t)))
				if err != nil {
					t.Fatal(err)
				}
			case "malformed-rlp":
				envelope.NEVMBlockData = []byte{0xff}
				err = n.Deserialize(nevmPayloadTestSerialize(t, envelope))
				if n.Block != oldBlock {
					t.Fatal("fixture did not exercise a failure before Block assignment")
				}
				nevmPayloadTestAssertRejection(t, &n, err, envelope)
			case "end-of-input":
				err = n.Deserialize(nil)
				if !errors.Is(err, io.EOF) || n.payload != nil {
					t.Fatalf("end-of-input retained provenance or changed error: %v", err)
				}
			}
			if n.payload == oldContext || n.HasCommittedRootContradiction(oldErr) {
				t.Fatal("reused receiver retained prior immutable-rejection authority")
			}
			if mode != "same-contradictory-wire" && n.HasCommittedRootContradiction(err) {
				t.Fatal("new decode improperly inherited an immutable rejection")
			}
		})
	}
}

func TestNEVMPayloadDeserializeClearsProvenance(t *testing.T) {
	for _, mode := range []string{"same-valid-wire", "end-of-input"} {
		t.Run(mode, func(t *testing.T) {
			n, envelope := nevmPayloadTestConnect(t)
			cause := errors.New("synthetic prior result")
			oldBodyError := MarkNEVMPayloadError(cause, n.Block)
			oldRawError := n.rejectPayload(cause, envelope.NEVMBlockData)
			oldProvenance := n.payload
			if mode == "same-valid-wire" {
				if err := n.Deserialize(nevmPayloadTestSerialize(t, envelope)); err != nil {
					t.Fatal(err)
				}
				if n.payload == nil || n.payload == oldProvenance {
					t.Fatal("successful Deserialize did not replace provenance")
				}
				nevmPayloadTestAssertRejection(t, n, MarkNEVMPayloadError(cause, n.Block), envelope)
			} else {
				if err := n.Deserialize(nil); !errors.Is(err, io.EOF) {
					t.Fatalf("Deserialize at end of input = %v, want EOF", err)
				}
				if n.payload != nil {
					t.Fatal("failed Deserialize retained prior provenance")
				}
			}
			nevmPayloadTestAssertNoRejection(t, n, oldBodyError)
			nevmPayloadTestAssertNoRejection(t, n, oldRawError)
		})
	}
}

func nevmPayloadTestWire(t *testing.T) wire.NEVMBlockWire {
	t.Helper()
	block := NewBlockWithHeader(&Header{
		ParentHash: common.Hash{1}, UncleHash: EmptyUncleHash, TxHash: EmptyTxsHash, ReceiptHash: EmptyReceiptsHash,
		Difficulty: new(big.Int), Number: big.NewInt(7), GasLimit: 30000000, Time: 42, Extra: []byte("local provenance fixture"),
	})
	raw, err := rlp.EncodeToBytes(block)
	if err != nil {
		t.Fatal(err)
	}
	return wire.NEVMBlockWire{
		NEVMBlockHash: block.Hash().Bytes(), TxRoot: block.TxHash().Bytes(), ReceiptRoot: block.ReceiptHash().Bytes(),
		NEVMBlockData: raw, SYSBlockHash: common.Hash{0x21, 0x43}.Bytes(), BTCPrevHash: common.Hash{0x65}.Bytes(),
	}
}

func nevmPayloadTestSerialize(t *testing.T, envelope wire.NEVMBlockWire) []byte {
	t.Helper()
	var encoded bytes.Buffer
	if err := envelope.Serialize(&encoded); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

func nevmPayloadTestConnect(t *testing.T) (*NEVMBlockConnect, wire.NEVMBlockWire) {
	t.Helper()
	envelope := nevmPayloadTestWire(t)
	var n NEVMBlockConnect
	if err := n.Deserialize(nevmPayloadTestSerialize(t, envelope)); err != nil {
		t.Fatal(err)
	}
	return &n, envelope
}

func nevmPayloadTestAssertRejection(t *testing.T, n *NEVMBlockConnect, err error, envelope wire.NEVMBlockWire) {
	t.Helper()
	preimage := bytes.Join([][]byte{
		[]byte("syscoin-nevm-payload-v1\x00"), envelope.NEVMBlockHash, envelope.TxRoot,
		envelope.ReceiptRoot, envelope.SYSBlockHash, envelope.NEVMBlockData,
	}, nil)
	want := common.Hash(sha256.Sum256(preimage))
	nevmHash, sysHash, digest, ok := n.PayloadRejection(err)
	if !ok || nevmHash != common.BytesToHash(envelope.NEVMBlockHash) || sysHash != common.BytesToHash(envelope.SYSBlockHash) || digest != want {
		t.Fatalf("payload rejection = (%s, %s, %s, %t), want envelope pair and digest %s", nevmHash, sysHash, digest, ok, want)
	}
}

func nevmPayloadTestAssertNoRejection(t *testing.T, n *NEVMBlockConnect, err error) {
	t.Helper()
	nevmHash, sysHash, digest, ok := n.PayloadRejection(err)
	if ok || nevmHash != (common.Hash{}) || sysHash != (common.Hash{}) || digest != (common.Hash{}) {
		t.Fatalf("unexpected payload authorization = (%s, %s, %s, %t)", nevmHash, sysHash, digest, ok)
	}
}
