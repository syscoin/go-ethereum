package eth

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/tracker"
	"github.com/ethereum/go-ethereum/rlp"
)

type responseTestRW struct{ id uint64 }

func (rw *responseTestRW) ReadMsg() (p2p.Msg, error) { return p2p.Msg{}, io.EOF }
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

func TestResponseHandlersValidateBeforeDecode(t *testing.T) {
	for _, handler := range []struct {
		name string
		code uint64
		run  msgHandler
	}{
		{"headers", BlockHeadersMsg, handleBlockHeaders},
		{"bodies", BlockBodiesMsg, handleBlockBodies},
		{"receipts", ReceiptsMsg, handleReceipts},
		{"transactions", PooledTransactionsMsg, handlePooledTransactions},
	} {
		for _, test := range []struct {
			name    string
			tracked bool
			code    uint64
			items   int
			want    error
		}{
			{"unsolicited", false, handler.code, 1, tracker.ErrUnrequestedResponse},
			{"mismatched", true, handler.code + 1, 1, tracker.ErrResponseType},
			{"excessive", true, handler.code, 2, tracker.ErrResponseLimit},
		} {
			t.Run(handler.name+"/"+test.name, func(t *testing.T) {
				peer := &Peer{responses: tracker.NewResponseTracker(time.Minute)}
				if test.tracked {
					peer.responses.Track(7, test.code, tracker.ResponseLimits{Items: 1, Bytes: maxMessageSize})
				}
				// Scalars are not valid headers, bodies, receipts, or transactions.
				// The request checks must reject them before attempting item decoding.
				items := make([]uint64, test.items)
				encoded, _ := rlp.EncodeToBytes([]interface{}{uint64(7), items})
				err := handler.run(&testBackend{}, decoder{encoded}, peer)
				if err == nil || !strings.Contains(err.Error(), test.want.Error()) {
					t.Fatalf("have %v, want %v", err, test.want)
				}
			})
		}
	}
}

func TestRequestedResponses(t *testing.T) {
	for _, test := range []struct {
		name    string
		code    uint64
		run     msgHandler
		request func(*Peer, chan *Response) (*Request, error)
	}{
		{"headers", BlockHeadersMsg, handleBlockHeaders, func(p *Peer, sink chan *Response) (*Request, error) {
			return p.RequestHeadersByNumber(0, 1, 0, false, sink)
		}},
		{"bodies", BlockBodiesMsg, handleBlockBodies, func(p *Peer, sink chan *Response) (*Request, error) { return p.RequestBodies([]common.Hash{{1}}, sink) }},
		{"receipts", ReceiptsMsg, handleReceipts, func(p *Peer, sink chan *Response) (*Request, error) {
			return p.RequestReceipts([]common.Hash{{1}}, sink)
		}},
		{"transactions", PooledTransactionsMsg, handlePooledTransactions, func(p *Peer, sink chan *Response) (*Request, error) { return nil, p.RequestTxs([]common.Hash{{1}}) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			rw := new(responseTestRW)
			peer := NewPeer(ETH68, p2p.NewPeer(enode.ID{}, "test", nil), rw, nil)
			defer peer.Close()
			sink := make(chan *Response)
			req, err := test.request(peer, sink)
			if err != nil {
				t.Fatal(err)
			}
			if req != nil {
				defer req.Close()
			}
			encoded, _ := rlp.EncodeToBytes([]interface{}{rw.id, []rlp.RawValue{}})
			done := make(chan error, 1)
			go func() { done <- test.run(&testBackend{}, decoder{encoded}, peer) }()
			if req != nil {
				select {
				case res := <-sink:
					if res.Req != req {
						t.Fatal("wrong request")
					}
					res.Done <- nil
				case err := <-done:
					t.Fatalf("response not dispatched: %v", err)
				case <-time.After(time.Second):
					t.Fatal("response not dispatched")
				}
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("response handler did not finish")
			}
			// A fulfilled request cannot authorize another response.
			if err := test.run(&testBackend{}, decoder{encoded}, peer); err == nil || !strings.Contains(err.Error(), tracker.ErrUnrequestedResponse.Error()) {
				t.Fatalf("duplicate response: %v", err)
			}
			if req != nil {
				cancelled, err := test.request(peer, sink)
				if err != nil {
					t.Fatal(err)
				}
				if err := cancelled.Close(); err != nil {
					t.Fatal(err)
				}
				// A late response is discarded without decoding the invalid item.
				encoded, _ = rlp.EncodeToBytes([]interface{}{rw.id, []uint64{1}})
				if err := test.run(&testBackend{}, decoder{encoded}, peer); err != nil {
					t.Fatalf("cancelled response: %v", err)
				}
			}
		})
	}
}

func TestHeaderSkipWarningBound(t *testing.T) {
	backend := newTestBackend(0)
	defer backend.close()
	var output bytes.Buffer
	previous := log.Root()
	log.SetDefault(log.NewLogger(slog.NewTextHandler(&output, nil)))
	defer log.SetDefault(previous)
	for i := 0; i < 2; i++ {
		peer := &Peer{Peer: p2p.NewPeer(enode.ID{byte(i)}, "test", nil)}
		for j := 0; j < 100; j++ {
			query := &GetBlockHeadersRequest{
				Origin: HashOrNumber{Hash: backend.chain.GetHeaderByNumber(0).Hash()},
				Amount: 2, Skip: math.MaxUint64,
			}
			if headers := serviceNonContiguousBlockHeaderQuery(backend.chain, query, peer); len(headers) != 1 {
				t.Fatalf("got %d headers", len(headers))
			}
		}
	}
	if got := strings.Count(output.String(), "GetBlockHeaders skip overflow"); got != 2 {
		t.Fatalf("got %d warnings, want one per peer", got)
	}
	if strings.Contains(output.String(), "attacker=") || strings.Contains(output.String(), "caps=") {
		t.Fatal("warning contains peer information dump")
	}
}

func TestResponseMetadataGate(t *testing.T) {
	for _, state := range []string{"rejected", "cancelled", "invalid-metadata"} {
		t.Run(state, func(t *testing.T) {
			peer := &Peer{resDispatch: make(chan *response), term: make(chan struct{})}
			sink := make(chan *Response, 1)
			req := &Request{cancel: make(chan struct{}), sink: sink}
			if state == "cancelled" {
				close(req.cancel)
			}
			go func() {
				op := <-peer.resDispatch
				op.res.Req = req
				if state == "rejected" {
					op.fail <- errDanglingResponse
				} else {
					op.fail <- nil
				}
			}()
			called := false
			invalid := errors.New("invalid raw metadata")
			err := peer.dispatchResponse(new(Response), func() (interface{}, error) {
				called = true
				return nil, invalid
			})
			if state == "invalid-metadata" {
				if !called || !errors.Is(err, invalid) {
					t.Fatalf("metadata error lost: called %v, error %v", called, err)
				}
			} else if called || err != nil {
				t.Fatalf("metadata called for %s response: called %v, error %v", state, called, err)
			}
			select {
			case <-sink:
				t.Fatal("invalid response delivered")
			default:
			}
		})
	}
}
