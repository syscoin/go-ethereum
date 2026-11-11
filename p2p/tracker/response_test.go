package tracker

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/rlp"
)

type cancellingReader struct {
	*bytes.Reader
	tracker *ResponseTracker
}

func (r *cancellingReader) ReadByte() (byte, error) {
	// The first two bytes are the outer list and request ID. Cancel when
	// reading the payload, after the initial request check has succeeded.
	if r.Len() == 2 {
		r.tracker.Cancel(7)
	}
	return r.Reader.ReadByte()
}

func TestResponseCancelledWhileReading(t *testing.T) {
	tr := NewResponseTracker(time.Minute)
	tr.Track(7, 2, ResponseLimits{Items: 1, Bytes: 64})
	encoded, _ := rlp.EncodeToBytes([]interface{}{uint64(7), []uint64{1}})
	var id uint64
	var items []uint64
	decoder := &ResponseDecoder{Tracker: tr, Code: 2, ID: &id, Values: []interface{}{&items}}
	reader := &cancellingReader{Reader: bytes.NewReader(encoded), tracker: tr}
	if err := rlp.NewStream(reader, uint64(len(encoded))).Decode(decoder); !errors.Is(err, ErrResponseCancelled) {
		t.Fatal(err)
	}
	if !decoder.Cancelled || items != nil {
		t.Fatal("cancelled response was decoded")
	}
}

func TestResponseValidation(t *testing.T) {
	for _, tc := range []struct {
		name         string
		request      bool
		responseCode uint64
		items        []uint64
		limits       ResponseLimits
		want         error
	}{
		{"unsolicited", false, 2, []uint64{1}, ResponseLimits{}, ErrUnrequestedResponse},
		{"mismatched", true, 3, []uint64{1}, ResponseLimits{Items: 1, Bytes: 64}, ErrResponseType},
		{"excessive items", true, 2, []uint64{1, 2}, ResponseLimits{Items: 1, Bytes: 64}, ErrResponseLimit},
		{"excessive bytes", true, 2, []uint64{1, 2}, ResponseLimits{Items: 2, Bytes: 1}, ErrResponseLimit},
		{"valid", true, 2, []uint64{1}, ResponseLimits{Items: 1, Bytes: 64}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := NewResponseTracker(time.Minute)
			if tc.request {
				if err := tr.Track(7, 2, tc.limits); err != nil {
					t.Fatal(err)
				}
			}
			encoded, _ := rlp.EncodeToBytes([]interface{}{uint64(7), tc.items})
			var id uint64
			var items []uint64
			err := rlp.DecodeBytes(encoded, &ResponseDecoder{Tracker: tr, Code: tc.responseCode, ID: &id, Values: []interface{}{&items}})
			if !errors.Is(err, tc.want) {
				t.Fatalf("have %v, want %v", err, tc.want)
			}
			if tc.want != nil && items != nil {
				t.Fatal("rejected response was decoded")
			}
			if tc.want == nil {
				if id != 7 || len(items) != 1 || items[0] != 1 {
					t.Fatalf("wrong response: %d %v", id, items)
				}
				if _, err := tr.limits(7, 2); !errors.Is(err, ErrUnrequestedResponse) {
					t.Fatalf("request retained: %v", err)
				}
			}
		})
	}
}

func TestResponseRequestLifecycle(t *testing.T) {
	tr := NewResponseTracker(time.Minute)
	limits := ResponseLimits{Items: 1, Bytes: 64}
	if err := tr.Track(7, 2, limits); err != nil {
		t.Fatal(err)
	}
	if err := tr.Track(7, 3, limits); !errors.Is(err, ErrRequestID) {
		t.Fatal(err)
	}
	if _, err := tr.limits(7, 2); err != nil {
		t.Fatal("duplicate changed active request", err)
	}
	tr.Cancel(7)
	if _, err := tr.limits(7, 2); !errors.Is(err, ErrResponseCancelled) {
		t.Fatal(err)
	}
	tr.Forget(7)
	if err := tr.Track(7, 2, limits); err != nil {
		t.Fatal(err)
	}
	req := tr.pending[7].Value.(activeRequest)
	req.expiry = time.Now().Add(-time.Second)
	tr.pending[7].Value = req
	if _, err := tr.limits(7, 2); !errors.Is(err, ErrUnrequestedResponse) {
		t.Fatal(err)
	}
}

func TestResponseProofLimit(t *testing.T) {
	tr := NewResponseTracker(time.Minute)
	tr.Track(7, 2, ResponseLimits{Items: 1, Bytes: 64, ProofItems: 1})
	encoded, _ := rlp.EncodeToBytes([]interface{}{uint64(7), []uint64{1}, []uint64{1, 2}})
	var id uint64
	var items, proofs []uint64
	err := rlp.DecodeBytes(encoded, &ResponseDecoder{Tracker: tr, Code: 2, ID: &id, Values: []interface{}{&items, &proofs}})
	if !errors.Is(err, ErrResponseLimit) {
		t.Fatal(err)
	}
	if items != nil || proofs != nil {
		t.Fatal("oversized proof decoded")
	}
}
