// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package eth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/syscoin/syscoinwire/syscoin/wire"
)

func nevmPayloadTestReply(t *testing.T, encoded []byte) string {
	t.Helper()
	var payload wire.NEVMBlockWire
	if err := payload.Deserialize(bytes.NewReader(encoded)); err != nil {
		t.Fatal(err)
	}
	preimage := []byte("syscoin-nevm-payload-v1\x00")
	for _, field := range [][]byte{payload.NEVMBlockHash, payload.TxRoot, payload.ReceiptRoot, payload.SYSBlockHash, payload.NEVMBlockData} {
		preimage = append(preimage, field...)
	}
	digest := sha256.Sum256(preimage)
	display := func(raw []byte) string {
		reversed := make([]byte, len(raw))
		for i := range raw {
			reversed[len(raw)-1-i] = raw[i]
		}
		return hex.EncodeToString(reversed)
	}
	return "payload-invalid:" + display(payload.NEVMBlockHash) + ":" + display(payload.SYSBlockHash) + ":" + display(digest[:])
}

func TestNEVMPayloadResultCorrelation(t *testing.T) {
	block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(1)})
	encoded := nevmConnectTestPayload(t, makeNEVMConnect(block, common.HexToHash("0x123456").Bytes()))
	var pair types.NEVMBlockConnect
	if err := pair.Deserialize(encoded); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("synthetic representation classification")
	marked := fmt.Errorf("wrapped: %w", types.MarkNEVMPayloadError(sentinel, pair.Block))
	err := nevmInsertError(marked, 1, []*types.NEVMBlockConnect{nil, &pair})
	if !errors.Is(err, sentinel) {
		t.Fatal("classification lost the original error")
	}
	want := nevmPayloadTestReply(t, encoded)
	for _, result := range []string{nevmConnectResult(err), nevmFlushResult(fmt.Errorf("outer: %w", err))} {
		if result != want {
			t.Fatalf("rejection %q, want %q", result, want)
		}
	}
	for _, test := range []struct {
		name string
		err  error
	}{
		{"unpaired", marked},
		{"negative-index", nevmInsertError(marked, -1, []*types.NEVMBlockConnect{&pair})},
		{"past-end-index", nevmInsertError(marked, 1, []*types.NEVMBlockConnect{&pair})},
		{"missing-pair", nevmConnectError(marked, nil)},
		{"unmarked-text", nevmConnectError(errors.New(want), &pair)},
		{"different-block", nevmConnectError(types.MarkNEVMPayloadError(sentinel, block), &pair)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := nevmConnectResult(test.err); got != "error:"+test.err.Error() {
				t.Fatalf("uncorrelated error classified as %q", got)
			}
		})
	}
}

func TestNEVMPayloadValidationIsPure(t *testing.T) {
	eth, genesis, engine := newNEVMPairTestEthereum(t, false)
	genDB, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, 2, nil)
	defer genDB.Close()
	first := makeNEVMConnect(blocks[0], common.HexToHash("0x1234").Bytes())
	if err := eth.AddBlock(first); err != nil {
		t.Fatal(err)
	}
	encoded := nevmConnectTestPayload(t, makeNEVMConnect(blocks[1], common.HexToHash("0x5678").Bytes()))
	// This checker needs no Ethereum instance, ancestor lookup or execution.
	if got := (&ZMQRep{}).handleNEVMValidate(encoded); got != "payload-valid" {
		t.Fatalf("pure handler returned %q", got)
	}
	timestamp := eth.timeLastBlock
	reply := nevmConnectTestReply(t, eth)
	if got := reply("nevmvalidate", encoded); got != "payload-valid" {
		t.Fatalf("validation topic returned %q", got)
	}
	if eth.blockchain.CurrentBlock().Hash() != genesis.ToBlock().Hash() ||
		len(eth.blockConnectBuffer) != 1 || eth.blockConnectBuffer[0] != first ||
		len(eth.blockchain.ReadSYSHash(1)) != 0 || eth.timeLastBlock != timestamp {
		t.Fatal("pure validation changed chain, pairing, buffer or timestamp")
	}
}

func TestNEVMPayloadBufferedRetryRetainsProvenance(t *testing.T) {
	eth, genesis, engine := newNEVMPairTestEthereum(t, false)
	genDB, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, 1, nil)
	defer genDB.Close()
	encoded := nevmConnectTestPayload(t, makeNEVMConnect(blocks[0], common.HexToHash("0x1234").Bytes()))
	var original, retry types.NEVMBlockConnect
	for _, pair := range []*types.NEVMBlockConnect{&original, &retry} {
		if err := pair.Deserialize(encoded); err != nil {
			t.Fatal(err)
		}
		if err := eth.AddBlock(pair); err != nil {
			t.Fatal(err)
		}
	}
	if len(eth.blockConnectBuffer) != 1 || eth.blockConnectBuffer[0] != &original {
		t.Fatal("retry replaced buffered provenance")
	}
	sentinel := errors.New("synthetic buffered classification")
	marked := types.MarkNEVMPayloadError(sentinel, original.Block)
	if got := nevmFlushResult(nevmInsertError(marked, 0, eth.blockConnectBuffer)); got != nevmPayloadTestReply(t, encoded) {
		t.Fatalf("original buffered pair correlation returned %q", got)
	}
	marked = types.MarkNEVMPayloadError(sentinel, retry.Block)
	if got := nevmFlushResult(nevmInsertError(marked, 0, eth.blockConnectBuffer)); got != "flush-failed: "+sentinel.Error() {
		t.Fatalf("retry provenance substituted into buffered error: %q", got)
	}
}

func TestNEVMCommittedRootContradictions(t *testing.T) {
	block := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), UncleHash: types.EmptyUncleHash,
		TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash,
	})
	for _, field := range []string{"transaction-root", "receipt-root"} {
		for _, candidateOnly := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/candidate-only-%v", field, candidateOnly), func(t *testing.T) {
				sysHash := common.HexToHash("0x1234").Bytes()
				if candidateOnly {
					sysHash = nil
				}
				pair := makeNEVMConnect(block, sysHash)
				var envelope wire.NEVMBlockWire
				if err := envelope.Deserialize(bytes.NewReader(nevmConnectTestPayload(t, pair))); err != nil {
					t.Fatal(err)
				}
				// The committed NEVM hash already authenticates this exact header.
				// Changing a separately committed root makes the tuple impossible
				// to satisfy by replacing the uncommitted block representation.
				if field == "transaction-root" {
					envelope.TxRoot = common.Hash{0xa1}.Bytes()
				} else {
					envelope.ReceiptRoot = common.Hash{0xb2}.Bytes()
				}
				var encoded bytes.Buffer
				if err := envelope.Serialize(&encoded); err != nil {
					t.Fatal(err)
				}
				want := nevmConnectTestInvalidReply(pair)
				for _, result := range []string{
					(&ZMQRep{}).handleNEVMConnect(encoded.Bytes()),
					(&ZMQRep{}).handleNEVMValidate(encoded.Bytes()),
				} {
					if result != want {
						t.Errorf("committed-root contradiction returned %q, want %q", result, want)
					}
				}
			})
		}
	}
}

func TestNEVMCommittedRootRepairableRepresentations(t *testing.T) {
	block := types.NewBlockWithHeader(&types.Header{
		Number: big.NewInt(1), UncleHash: types.EmptyUncleHash,
		TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash,
	})
	for _, mode := range []string{"different-header", "different-header-and-tx-root", "different-header-and-receipt-root", "malformed-rlp", "body-tx-root"} {
		t.Run(mode, func(t *testing.T) {
			candidate := block
			if mode == "body-tx-root" {
				header := block.Header()
				header.TxHash = common.Hash{0xa1}
				candidate = types.NewBlockWithHeader(header)
			}
			pair := makeNEVMConnect(candidate, common.HexToHash("0x1234").Bytes())
			var envelope wire.NEVMBlockWire
			if err := envelope.Deserialize(bytes.NewReader(nevmConnectTestPayload(t, pair))); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "different-header":
				envelope.NEVMBlockHash = common.Hash{0xc3}.Bytes()
			case "different-header-and-tx-root":
				envelope.NEVMBlockHash, envelope.TxRoot = common.Hash{0xc3}.Bytes(), common.Hash{0xa1}.Bytes()
			case "different-header-and-receipt-root":
				envelope.NEVMBlockHash, envelope.ReceiptRoot = common.Hash{0xc3}.Bytes(), common.Hash{0xb2}.Bytes()
			case "malformed-rlp":
				envelope.NEVMBlockData = []byte{0xff}
			}
			var encoded bytes.Buffer
			if err := envelope.Serialize(&encoded); err != nil {
				t.Fatal(err)
			}
			want := nevmPayloadTestReply(t, encoded.Bytes())
			if got := (&ZMQRep{}).handleNEVMValidate(encoded.Bytes()); got != want {
				t.Fatalf("replaceable representation returned %q, want %q", got, want)
			}
			if mode != "body-tx-root" {
				if got := (&ZMQRep{}).handleNEVMConnect(encoded.Bytes()); got != want {
					t.Fatalf("replaceable connect representation returned %q, want %q", got, want)
				}
			}
		})
	}
}
