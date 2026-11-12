// SYSCOIN: Security regression coverage.
package snap

import (
	"bytes"
	"io"
	"math"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/tracker"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

type responseTestRW struct {
	id  uint64
	msg p2p.Msg
}

func (rw *responseTestRW) ReadMsg() (p2p.Msg, error) {
	if rw.msg.Payload == nil {
		return p2p.Msg{}, io.EOF
	}
	msg := rw.msg
	rw.msg = p2p.Msg{}
	return msg, nil
}
func (rw *responseTestRW) WriteMsg(msg p2p.Msg) error {
	var envelope struct {
		ID   uint64
		Tail []rlp.RawValue `rlp:"tail"`
	}
	if err := msg.Decode(&envelope); err != nil {
		return err
	}
	rw.id = envelope.ID
	return nil
}
func (rw *responseTestRW) reply(t *testing.T, code uint64, fields ...interface{}) {
	t.Helper()
	encoded, err := rlp.EncodeToBytes(fields)
	if err != nil {
		t.Fatal(err)
	}
	rw.msg = p2p.Msg{Code: code, Size: uint32(len(encoded)), Payload: bytes.NewReader(encoded)}
}

type responseTestBackend struct{ packets int }

func (b *responseTestBackend) Chain() *core.BlockChain          { return nil }
func (b *responseTestBackend) RunPeer(p *Peer, h Handler) error { return h(p) }
func (b *responseTestBackend) PeerInfo(enode.ID) interface{}    { return nil }
func (b *responseTestBackend) Handle(*Peer, Packet) error       { b.packets++; return nil }

func TestResponseHandlersValidateBeforeDecode(t *testing.T) {
	for _, code := range []uint64{AccountRangeMsg, StorageRangesMsg, ByteCodesMsg, TrieNodesMsg} {
		for _, tc := range []struct {
			name     string
			tracked  bool
			response uint64
			count    int
			want     error
		}{
			{"unsolicited", false, code, 1, tracker.ErrUnrequestedResponse},
			{"mismatched", true, code + 1, 1, tracker.ErrResponseType},
			{"excessive", true, code, 2, tracker.ErrResponseLimit},
		} {
			t.Run(PacketName(code)+"/"+tc.name, func(t *testing.T) {
				rw := new(responseTestRW)
				peer := NewFakePeer(SNAP1, "testpeer", rw)
				if tc.tracked {
					peer.responses.Track(7, tc.response, tracker.ResponseLimits{Items: 1, Bytes: 64, ProofItems: 128})
				}
				fields := []interface{}{uint64(7), make([]uint64, tc.count)}
				if code == AccountRangeMsg || code == StorageRangesMsg {
					fields = append(fields, []uint64{})
				}
				rw.reply(t, code, fields...)
				backend := new(responseTestBackend)
				err := HandleMessage(backend, peer)
				if err == nil || !strings.Contains(err.Error(), tc.want.Error()) {
					t.Fatalf("have %v, want %v", err, tc.want)
				}
				if backend.packets != 0 {
					t.Fatal("invalid response delivered")
				}
			})
		}
	}
}

func TestRequestedResponses(t *testing.T) {
	for _, tc := range []struct {
		name    string
		code    uint64
		request func(*Peer) error
	}{
		{"accounts", AccountRangeMsg, func(p *Peer) error {
			return p.RequestAccountRange(7, common.Hash{}, common.Hash{}, common.MaxHash, 1024)
		}},
		{"storage", StorageRangesMsg, func(p *Peer) error {
			return p.RequestStorageRanges(7, common.Hash{}, []common.Hash{{1}}, nil, nil, 1024)
		}},
		{"codes", ByteCodesMsg, func(p *Peer) error { return p.RequestByteCodes(7, []common.Hash{{1}}, 1024) }},
		{"nodes", TrieNodesMsg, func(p *Peer) error { return p.RequestTrieNodes(7, common.Hash{}, []TrieNodePathSet{{[]byte{1}}}, 1024) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rw := new(responseTestRW)
			peer := NewFakePeer(SNAP1, "testpeer", rw)
			if err := tc.request(peer); err != nil {
				t.Fatal(err)
			}
			fields := []interface{}{rw.id, []rlp.RawValue{}}
			if tc.code == AccountRangeMsg || tc.code == StorageRangesMsg {
				fields = append(fields, []rlp.RawValue{})
			}
			rw.reply(t, tc.code, fields...)
			backend := new(responseTestBackend)
			if err := HandleMessage(backend, peer); err != nil {
				t.Fatal(err)
			}
			if backend.packets != 1 {
				t.Fatal("valid response not delivered")
			}
			rw.reply(t, tc.code, fields...)
			if err := HandleMessage(backend, peer); err == nil || !strings.Contains(err.Error(), tracker.ErrUnrequestedResponse.Error()) {
				t.Fatalf("duplicate response: %v", err)
			}
		})
	}
}

func TestRangeResponseLimits(t *testing.T) {
	for _, code := range []uint64{AccountRangeMsg, StorageRangesMsg} {
		t.Run(PacketName(code), func(t *testing.T) {
			for _, proof := range []bool{false, true} {
				rw := new(responseTestRW)
				peer := NewFakePeer(SNAP1, "testpeer", rw)
				peer.responses.Track(7, code, tracker.ResponseLimits{Items: -1, Bytes: 128, ProofItems: 128})
				var data, proofs [][]byte
				if proof {
					proofs = make([][]byte, 129)
				} else {
					data = [][]byte{make([]byte, 129)}
				}
				rw.reply(t, code, uint64(7), data, proofs)
				if err := HandleMessage(new(responseTestBackend), peer); err == nil || !strings.Contains(err.Error(), tracker.ErrResponseLimit.Error()) {
					t.Fatal(err)
				}
			}
		})
	}
}

// The range byte limit is soft: a server can return one account or storage slot
// larger than the requested budget. Exercise the largest consensus field sizes
// to ensure the fixed allowance also covers the response's RLP list framing.
func TestSmallRangeResponseBudgets(t *testing.T) {
	account := &AccountData{
		Hash: common.MaxHash,
		Body: types.SlimAccountRLP(types.StateAccount{
			Nonce:    math.MaxUint64,
			Balance:  new(uint256.Int).SetAllOne(),
			Root:     common.MaxHash,
			CodeHash: common.MaxHash.Bytes(),
		}),
	}
	slot, err := rlp.EncodeToBytes(common.MaxHash)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		code  uint64
		bytes uint64
		data  interface{}
	}{
		{"account/zero", AccountRangeMsg, 0, []*AccountData{account}},
		{"account/one", AccountRangeMsg, 1, []*AccountData{account}},
		{"storage/one", StorageRangesMsg, 1, [][]*StorageData{{{Hash: common.MaxHash, Body: slot}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := rlp.EncodeToBytes(tc.data)
			if err != nil {
				t.Fatal(err)
			}
			if len(encoded) > rangeResponseSlack {
				t.Fatalf("one maximum-size item needs %d bytes, exceeding slack %d", len(encoded), rangeResponseSlack)
			}
			t.Logf("maximum-size item with list framing: %d bytes", len(encoded))
			for _, oversized := range []bool{false, true} {
				name := "valid"
				if oversized {
					name = "oversized"
				}
				t.Run(name, func(t *testing.T) {
					rw := new(responseTestRW)
					peer := NewFakePeer(SNAP1, "testpeer", rw)
					if tc.code == AccountRangeMsg {
						err = peer.RequestAccountRange(7, common.Hash{}, common.Hash{}, common.MaxHash, tc.bytes)
					} else {
						err = peer.RequestStorageRanges(7, common.Hash{}, []common.Hash{{1}}, nil, nil, tc.bytes)
					}
					if err != nil {
						t.Fatal(err)
					}
					data := tc.data
					if oversized {
						// Keep the top-level item count valid, but exceed the whole
						// payload allowance before the item can be decoded.
						data = [][]byte{make([]byte, 2*tc.bytes+rangeResponseSlack+1)}
					}
					rw.reply(t, tc.code, uint64(7), data, [][]byte{})
					backend := new(responseTestBackend)
					err = HandleMessage(backend, peer)
					if oversized {
						if err == nil || !strings.Contains(err.Error(), tracker.ErrResponseLimit.Error()) || backend.packets != 0 {
							t.Fatalf("oversized response: error %v, delivered %d packets", err, backend.packets)
						}
					} else if err != nil || backend.packets != 1 {
						t.Fatalf("valid soft-limit response: error %v, delivered %d packets", err, backend.packets)
					}
				})
			}
		})
	}
}

func PacketName(code uint64) string {
	switch code {
	case AccountRangeMsg:
		return "accounts"
	case StorageRangesMsg:
		return "storage"
	case ByteCodesMsg:
		return "codes"
	default:
		return "nodes"
	}
}
