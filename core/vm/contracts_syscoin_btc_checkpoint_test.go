package vm

import (
	"encoding/binary"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
)

func TestBTCCheckpointIndex_BatchInputAndGas(t *testing.T) {
	p := &btccheckpointindex{}

	// bad length
	if gas := p.RequiredGas([]byte{}); gas != 0 {
		t.Fatalf("expected 0 gas for empty input, got %d", gas)
	}
	if gas := p.RequiredGas(make([]byte, 31)); gas != 0 {
		t.Fatalf("expected 0 gas for bad length, got %d", gas)
	}

	// too large (k=101)
	if gas := p.RequiredGas(make([]byte, 32*(btcCheckpointBatchMaxItems+1))); gas != 0 {
		t.Fatalf("expected 0 gas for oversized batch, got %d", gas)
	}

	// valid sizes
	for _, k := range []int{1, 2, btcCheckpointBatchMaxItems} {
		in := make([]byte, 32*k)
		want := params.BTCCheckpointBatchBaseGas + uint64(k)*params.BTCCheckpointBatchPerItemGas
		if got := p.RequiredGas(in); got != want {
			t.Fatalf("k=%d: expected gas %d, got %d", k, want, got)
		}
	}
}

func TestBTCCheckpointIndex_OutputPacking(t *testing.T) {
	// Prepare 3 distinct hashes.
	h0 := common.HexToHash("0x01")
	h1 := common.HexToHash("0x02")
	h2 := common.HexToHash("0x03")

	indexByHash := map[common.Hash]uint64{
		h0: 1,
		h1: 42,
		// h2 intentionally missing -> 0
	}
	evm := &EVM{
		Context: BlockContext{
			BTCCheckpointIndex: func(h common.Hash) uint64 { return indexByHash[h] },
		},
	}
	interp := &EVMInterpreter{evm: evm}

	in := make([]byte, 0, 32*3)
	in = append(in, h0.Bytes()...)
	in = append(in, h1.Bytes()...)
	in = append(in, h2.Bytes()...)

	out, err := (&btccheckpointindex{}).Run(in, interp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 32*3 {
		t.Fatalf("expected %d bytes output, got %d", 32*3, len(out))
	}
	got0 := binary.BigEndian.Uint64(out[24:32])
	got1 := binary.BigEndian.Uint64(out[56:64])
	got2 := binary.BigEndian.Uint64(out[88:96])
	if got0 != 1 || got1 != 42 || got2 != 0 {
		t.Fatalf("unexpected packed indices: got [%d,%d,%d]", got0, got1, got2)
	}
}

func TestBTCCheckpointIndex_Errors(t *testing.T) {
	p := &btccheckpointindex{}
	evm := &EVM{Context: BlockContext{BTCCheckpointIndex: func(common.Hash) uint64 { return 0 }}}
	interp := &EVMInterpreter{evm: evm}

	if _, err := p.Run(make([]byte, 31), interp); err != errBTCCheckpointInvalidInputLength {
		t.Fatalf("expected %v, got %v", errBTCCheckpointInvalidInputLength, err)
	}
	if _, err := p.Run(make([]byte, 32*(btcCheckpointBatchMaxItems+1)), interp); err != errBTCCheckpointBatchTooLarge {
		t.Fatalf("expected %v, got %v", errBTCCheckpointBatchTooLarge, err)
	}
}

func TestBTCCheckpointHashByIndex_BatchInputAndGas(t *testing.T) {
	p := &btccheckpointhashbyindex{}

	if gas := p.RequiredGas([]byte{}); gas != 0 {
		t.Fatalf("expected 0 gas for empty input, got %d", gas)
	}
	if gas := p.RequiredGas(make([]byte, 7)); gas != 0 {
		t.Fatalf("expected 0 gas for bad length, got %d", gas)
	}
	if gas := p.RequiredGas(make([]byte, 8*(btcCheckpointBatchMaxItems+1))); gas != 0 {
		t.Fatalf("expected 0 gas for oversized batch, got %d", gas)
	}
	for _, k := range []int{1, 2, btcCheckpointBatchMaxItems} {
		in := make([]byte, 8*k)
		want := params.BTCCheckpointBatchBaseGas + uint64(k)*params.BTCCheckpointBatchPerItemGas
		if got := p.RequiredGas(in); got != want {
			t.Fatalf("k=%d: expected gas %d, got %d", k, want, got)
		}
	}
}

func TestBTCCheckpointHashByIndex_OutputPacking(t *testing.T) {
	h1 := common.HexToHash("0x1111")
	h3 := common.HexToHash("0x3333")

	hashByIndex := map[uint64][]byte{
		1: h1.Bytes(),
		// 2 intentionally missing -> empty -> zero hash in output slot
		3: h3.Bytes(),
	}
	evm := &EVM{
		Context: BlockContext{
			BTCCheckpointHashByIndex: func(idx uint64) []byte { return hashByIndex[idx] },
		},
	}
	interp := &EVMInterpreter{evm: evm}

	in := make([]byte, 0, 8*3)
	for _, idx := range []uint64{1, 2, 3} {
		var tmp [8]byte
		binary.BigEndian.PutUint64(tmp[:], idx)
		in = append(in, tmp[:]...)
	}

	out, err := (&btccheckpointhashbyindex{}).Run(in, interp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 32*3 {
		t.Fatalf("expected %d bytes output, got %d", 32*3, len(out))
	}
	if got := common.BytesToHash(out[0:32]); got != h1 {
		t.Fatalf("idx=1: expected %s, got %s", h1, got)
	}
	if got := common.BytesToHash(out[32:64]); got != (common.Hash{}) {
		t.Fatalf("idx=2: expected zero hash, got %s", got)
	}
	if got := common.BytesToHash(out[64:96]); got != h3 {
		t.Fatalf("idx=3: expected %s, got %s", h3, got)
	}
}

func TestBTCCheckpointHashByIndex_Errors(t *testing.T) {
	p := &btccheckpointhashbyindex{}
	evm := &EVM{Context: BlockContext{BTCCheckpointHashByIndex: func(uint64) []byte { return nil }}}
	interp := &EVMInterpreter{evm: evm}

	if _, err := p.Run(make([]byte, 7), interp); err != errBTCCheckpointIndexInvalidInputLength {
		t.Fatalf("expected %v, got %v", errBTCCheckpointIndexInvalidInputLength, err)
	}
	if _, err := p.Run(make([]byte, 8*(btcCheckpointBatchMaxItems+1)), interp); err != errBTCCheckpointBatchTooLarge {
		t.Fatalf("expected %v, got %v", errBTCCheckpointBatchTooLarge, err)
	}
}

func TestBTCLastCheckpointIndex_OutputAndErrors(t *testing.T) {
	p := &btclastcheckpointindex{}
	evm := &EVM{
		Context: BlockContext{
			BTCCheckpointLastIndex: func() uint64 { return 123 },
		},
	}
	interp := &EVMInterpreter{evm: evm}

	if _, err := p.Run([]byte{0x01}, interp); err != errBTCCheckpointIndexInvalidInputLength {
		t.Fatalf("expected %v, got %v", errBTCCheckpointIndexInvalidInputLength, err)
	}
	out, err := p.Run(nil, interp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("expected 32 bytes output, got %d", len(out))
	}
	if got := binary.BigEndian.Uint64(out[24:32]); got != 123 {
		t.Fatalf("expected 123, got %d", got)
	}
}

