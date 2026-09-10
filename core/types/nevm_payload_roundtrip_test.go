package types

import (
	"bytes"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// These tests exercise byte preservation for canonical block payloads without
// importing or executing a block. The source outer lists are assembled without
// Block.EncodeRLP so the round trip also checks its optional body-field handling.
func TestNEVMPayloadCanonicalTransactionRoundTrip(t *testing.T) {
	to := common.Address{0x12}
	accesses := AccessList{{Address: common.Address{0x34}, StorageKeys: []common.Hash{{0x56}, {}}}}
	tests := []struct {
		name string
		tx   TxData
	}{
		{"legacy", &LegacyTx{
			Nonce: 1, GasPrice: big.NewInt(2), Gas: 21000, To: &to,
			Value: big.NewInt(3), Data: []byte{0, 1},
			V: big.NewInt(27), R: big.NewInt(4), S: big.NewInt(5),
		}},
		{"access-list", &AccessListTx{
			ChainID: big.NewInt(57), Nonce: 1, GasPrice: big.NewInt(2), Gas: 30000,
			To: &to, Value: big.NewInt(3), Data: []byte{0, 1}, AccessList: accesses,
			V: big.NewInt(1), R: big.NewInt(4), S: big.NewInt(5),
		}},
		{"dynamic-fee", &DynamicFeeTx{
			ChainID: big.NewInt(57), Nonce: 1, GasTipCap: big.NewInt(2), GasFeeCap: big.NewInt(3), Gas: 30000,
			To: &to, Value: big.NewInt(4), Data: []byte{0, 1}, AccessList: accesses,
			V: big.NewInt(1), R: big.NewInt(5), S: big.NewInt(6),
		}},
		{"blob", &BlobTx{
			ChainID: uint256.NewInt(57), Nonce: 1, GasTipCap: uint256.NewInt(2), GasFeeCap: uint256.NewInt(3), Gas: 30000,
			To: to, Value: uint256.NewInt(4), Data: []byte{0, 1}, AccessList: accesses,
			BlobFeeCap: uint256.NewInt(5), BlobHashes: []common.Hash{{1, 2}},
			V: uint256.NewInt(1), R: uint256.NewInt(6), S: uint256.NewInt(7),
		}},
		{"set-code", &SetCodeTx{
			ChainID: uint256.NewInt(57), Nonce: 1, GasTipCap: uint256.NewInt(2), GasFeeCap: uint256.NewInt(3), Gas: 30000,
			To: to, Value: uint256.NewInt(4), Data: []byte{0, 1}, AccessList: accesses,
			AuthList: []SetCodeAuthorization{{
				ChainID: *uint256.NewInt(57), Address: common.Address{0x78}, Nonce: 2,
				V: 1, R: *uint256.NewInt(5), S: *uint256.NewInt(6),
			}},
			V: uint256.NewInt(1), R: uint256.NewInt(7), S: uint256.NewInt(8),
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tx := NewTx(test.tx)
			block := nevmCanonicalBlockRoundTrip(t, nevmCanonicalHeaderFields(), []*Transaction{tx}, nil)
			if got := block.Transactions(); len(got) != 1 || got[0].Type() != tx.Type() {
				t.Fatalf("transaction type changed after decoding: %v", got)
			}
			if !reflect.DeepEqual(block.Transactions()[0].inner, tx.inner) {
				t.Fatal("transaction fields changed after decoding")
			}
		})
	}
}

func TestNEVMPayloadCanonicalHeaderRoundTrip(t *testing.T) {
	// Every possible trailing-field boundary is distinct, including an explicitly
	// present zero value at the end of the header.
	zeroSuffix := []any{new(big.Int), common.Hash{}, uint64(0), uint64(0), common.Hash{}, common.Hash{}}
	for count := 0; count <= len(zeroSuffix); count++ {
		t.Run(fmt.Sprintf("zero-suffix-fields-%d", count), func(t *testing.T) {
			fields := append(nevmCanonicalHeaderFields(), zeroSuffix[:count]...)
			block := nevmCanonicalBlockRoundTrip(t, fields, nil, nil)
			header := block.Header()
			present := []bool{
				header.BaseFee != nil, header.WithdrawalsHash != nil,
				header.BlobGasUsed != nil, header.ExcessBlobGas != nil,
				header.ParentBeaconRoot != nil, header.RequestsHash != nil,
			}
			for i, got := range present {
				if want := i < count; got != want {
					t.Fatalf("optional field %d presence = %t, want %t", i, got, want)
				}
			}
		})
	}
	t.Run("populated-suffix", func(t *testing.T) {
		fields := append(nevmCanonicalHeaderFields(), big.NewInt(7), common.Hash{8}, uint64(9), uint64(10), common.Hash{11}, common.Hash{12})
		nevmCanonicalBlockRoundTrip(t, fields, nil, nil)
	})
}

func TestNEVMPayloadCanonicalWithdrawalsRoundTrip(t *testing.T) {
	tests := []struct {
		name        string
		withdrawals []*Withdrawal
	}{
		{"omitted", nil},
		{"empty", []*Withdrawal{}},
		{"populated", []*Withdrawal{{Index: 1, Validator: 2, Address: common.Address{3}, Amount: 4}, {}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			block := nevmCanonicalBlockRoundTrip(t, nevmCanonicalHeaderFields(), nil, test.withdrawals)
			if !reflect.DeepEqual([]*Withdrawal(block.Withdrawals()), test.withdrawals) {
				t.Fatalf("withdrawals changed after decoding: got %#v, want %#v", block.Withdrawals(), test.withdrawals)
			}
		})
	}
}

func TestNEVMPayloadCanonicalBlobSidecarRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		sidecar *BlobTxSidecar
	}{
		{"omitted", nil},
		{"empty-arrays", &BlobTxSidecar{
			Blobs: []kzg4844.Blob{}, Commitments: []kzg4844.Commitment{}, Proofs: []kzg4844.Proof{},
		}},
		{"populated-arrays", &BlobTxSidecar{
			Blobs: []kzg4844.Blob{{1}}, Commitments: []kzg4844.Commitment{{2}}, Proofs: []kzg4844.Proof{{3}},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tx := NewTx(&BlobTx{
				ChainID: uint256.NewInt(57), Gas: 21000, To: common.Address{1},
				BlobHashes: []common.Hash{{1, 2}}, Sidecar: test.sidecar,
			})
			block := nevmCanonicalBlockRoundTrip(t, nevmCanonicalHeaderFields(), []*Transaction{tx}, nil)
			if got := block.Transactions()[0].BlobTxSidecar(); !reflect.DeepEqual(got, test.sidecar) {
				t.Fatal("blob sidecar presence or contents changed after decoding")
			}
		})
	}
}

func nevmCanonicalHeaderFields() []any {
	return []any{
		common.Hash{1}, EmptyUncleHash, common.Address{2}, common.Hash{3}, EmptyTxsHash, EmptyReceiptsHash,
		Bloom{}, big.NewInt(1), big.NewInt(2), uint64(30000000), uint64(0), uint64(3),
		[]byte("NEVM canonical round trip"), common.Hash{4}, BlockNonce{},
	}
}

func nevmCanonicalBlockRoundTrip(t *testing.T, header []any, txs []*Transaction, withdrawals []*Withdrawal) *Block {
	t.Helper()
	// Include an uncle to check that its header bytes are preserved too.
	fields := []any{header, txs, []any{nevmCanonicalHeaderFields()}}
	if withdrawals != nil {
		fields = append(fields, withdrawals)
	}
	payload, err := rlp.EncodeToBytes(fields)
	if err != nil {
		t.Fatalf("encode canonical payload: %v", err)
	}
	var block Block
	if err := rlp.DecodeBytes(payload, &block); err != nil {
		t.Fatalf("decode canonical payload: %v", err)
	}
	var encoded bytes.Buffer
	if err := rlp.Encode(&encoded, &block); err != nil {
		t.Fatalf("re-encode canonical payload: %v", err)
	}
	if !bytes.Equal(encoded.Bytes(), payload) {
		t.Fatalf("canonical payload changed after decoding and re-encoding (source %d bytes, output %d bytes)", len(payload), encoded.Len())
	}
	return &block
}
