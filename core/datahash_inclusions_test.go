package core

import (
	"context"
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
)

type lookupFixture struct {
	tip       *types.Header
	id        *big.Int
	journals  map[uint64][]*common.Hash
	headers   map[uint64]*types.Header
	pairings  map[uint64][]byte
	reads     []uint64
	readErr   error
	afterRead func()
	afterHead *types.Header
	headReads int
}

func newLookupFixture(height uint64) *lookupFixture {
	return &lookupFixture{
		tip: &types.Header{Number: new(big.Int).SetUint64(height)}, id: big.NewInt(5700),
		journals: make(map[uint64][]*common.Hash), headers: make(map[uint64]*types.Header), pairings: make(map[uint64][]byte),
	}
}
func (f *lookupFixture) head() *types.Header {
	f.headReads++
	if f.headReads > 1 && f.afterHead != nil {
		return f.afterHead
	}
	return f.tip
}
func (f *lookupFixture) chainID() *big.Int { return f.id }
func (f *lookupFixture) journal(n uint64) ([]*common.Hash, error) {
	f.reads = append(f.reads, n)
	if f.afterRead != nil {
		f.afterRead()
	}
	return f.journals[n], f.readErr
}
func (f *lookupFixture) canonicalHeader(n uint64) *types.Header { return f.headers[n] }
func (f *lookupFixture) syscoinHash(n uint64) ([]byte, error)   { return f.pairings[n], nil }
func (f *lookupFixture) add(n uint64, hashes ...*common.Hash) {
	f.journals[n] = hashes
	f.headers[n] = &types.Header{Number: new(big.Int).SetUint64(n)}
	f.pairings[n] = make([]byte, common.HashLength)
	f.pairings[n][0], f.pairings[n][31] = 0x12, 0x34
}

func TestDataHashLookupBoundedPaginationAndDuplicates(t *testing.T) {
	f := newLookupFixture(rawdb.DataBlockLimit + 7)
	a, b := common.HexToHash("0x01"), common.HexToHash("0x02")
	f.add(f.tip.Number.Uint64(), &a, &a)
	f.add(f.tip.Number.Uint64()-1, &a, &b)
	page, err := readDataHashInclusions(context.Background(), f, []common.Hash{a, b}, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Inclusions) != 2 || page.Inclusions[0].DataHash != a || page.Inclusions[1].DataHash != b {
		t.Fatalf("unexpected candidates: %+v", page.Inclusions)
	}
	if page.Inclusions[0].SyscoinBlockHash[0] != 0x34 || page.Inclusions[0].SyscoinBlockHash[31] != 0x12 {
		t.Fatal("Core display hash has wrong byte order")
	}
	if page.Exhausted || page.NextBefore == nil || uint64(*page.NextBefore) != f.tip.Number.Uint64()-2 {
		t.Fatalf("wrong next cursor: %+v", page)
	}
	if uint64(*page.SearchedFrom) != f.tip.Number.Uint64()-1 || uint64(*page.SearchedTo) != f.tip.Number.Uint64() {
		t.Fatal("wrong scanned range")
	}
	if !reflect.DeepEqual(f.reads, []uint64{f.tip.Number.Uint64(), f.tip.Number.Uint64() - 1}) {
		t.Fatalf("unbounded reads: %v", f.reads)
	}
	before := uint64(9)
	f.reads = nil
	page, err = readDataHashInclusions(context.Background(), f, []common.Hash{a}, &before, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !page.Exhausted || page.NextBefore != nil || !reflect.DeepEqual(f.reads, []uint64{9, 8}) {
		t.Fatalf("window floor not enforced: %+v %v", page, f.reads)
	}
}

func TestDataHashLookupRejectsInvalidRequestsBeforeReads(t *testing.T) {
	hash := common.HexToHash("0x01")
	tooMany := make([]common.Hash, MaxDataHashLookupHashes+1)
	for i := range tooMany {
		tooMany[i] = common.BigToHash(big.NewInt(int64(i + 1)))
	}
	for name, hashes := range map[string][]common.Hash{"empty": nil, "too_many": tooMany, "zero": {{}}, "duplicate": {hash, hash}} {
		t.Run(name, func(t *testing.T) {
			f := newLookupFixture(10)
			if _, err := readDataHashInclusions(context.Background(), f, hashes, nil, 1); err == nil {
				t.Fatal("invalid hashes accepted")
			}
			if len(f.reads) != 0 {
				t.Fatal("invalid request performed reads")
			}
		})
	}
	for _, limit := range []uint64{0, MaxDataHashLookupBlocks + 1} {
		if _, err := readDataHashInclusions(context.Background(), newLookupFixture(10), []common.Hash{hash}, nil, limit); err == nil {
			t.Fatal("invalid block bound accepted")
		}
	}
	future := uint64(11)
	if _, err := readDataHashInclusions(context.Background(), newLookupFixture(10), []common.Hash{hash}, &future, 1); err == nil {
		t.Fatal("future cursor accepted")
	}
}

func TestDataHashLookupEmptyAndCancelledRanges(t *testing.T) {
	hash := common.HexToHash("0x01")
	f := newLookupFixture(0)
	page, err := readDataHashInclusions(context.Background(), f, []common.Hash{hash}, nil, 1024)
	if err != nil || !page.Exhausted || len(f.reads) != 0 || page.SearchedFrom != nil || page.SearchedTo != nil {
		t.Fatalf("wrong genesis result: %+v %v", page, err)
	}
	f = newLookupFixture(rawdb.DataBlockLimit + 10)
	before := uint64(10)
	page, err = readDataHashInclusions(context.Background(), f, []common.Hash{hash}, &before, 1024)
	if err != nil || !page.Exhausted || len(f.reads) != 0 {
		t.Fatal("read outside retained window")
	}
	f = newLookupFixture(20)
	ctx, cancel := context.WithCancel(context.Background())
	f.afterRead = cancel
	if _, err := readDataHashInclusions(ctx, f, []common.Hash{hash}, nil, 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if len(f.reads) != 1 {
		t.Fatalf("continued after cancellation: %v", f.reads)
	}
}

func TestDataHashLookupRejectsCorruptCandidatesAndChangedHead(t *testing.T) {
	hash := common.HexToHash("0x01")
	tests := map[string]func(*lookupFixture){
		"missing_header":    func(f *lookupFixture) { delete(f.headers, 10) },
		"stale_header":      func(f *lookupFixture) { f.headers[10].Number = big.NewInt(9) },
		"missing_pairing":   func(f *lookupFixture) { delete(f.pairings, 10) },
		"short_pairing":     func(f *lookupFixture) { f.pairings[10] = []byte{1} },
		"long_pairing":      func(f *lookupFixture) { f.pairings[10] = make([]byte, 33) },
		"zero_pairing":      func(f *lookupFixture) { f.pairings[10] = make([]byte, 32) },
		"nil_journal_hash":  func(f *lookupFixture) { f.journals[10] = []*common.Hash{nil} },
		"oversized_journal": func(f *lookupFixture) { f.journals[10] = make([]*common.Hash, 33) },
		"read_error":        func(f *lookupFixture) { f.readErr = errors.New("disk failed") },
		"changed_head":      func(f *lookupFixture) { f.afterHead = &types.Header{Number: big.NewInt(11)} },
		"invalid_chain":     func(f *lookupFixture) { f.id = nil },
		"invalid_head":      func(f *lookupFixture) { f.tip = nil },
	}
	for name, corrupt := range tests {
		t.Run(name, func(t *testing.T) {
			f := newLookupFixture(10)
			f.add(10, &hash)
			corrupt(f)
			if _, err := readDataHashInclusions(context.Background(), f, []common.Hash{hash}, nil, 1); err == nil {
				t.Fatal("corruption accepted")
			}
		})
	}
}

func TestDataHashLookupMaximumRequestRemainsBounded(t *testing.T) {
	f := newLookupFixture(2000)
	hashes := make([]common.Hash, MaxDataHashLookupHashes)
	for i := range hashes {
		hashes[i] = common.BigToHash(big.NewInt(int64(i + 1)))
	}
	page, err := readDataHashInclusions(context.Background(), f, hashes, nil, MaxDataHashLookupBlocks)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.reads) != MaxDataHashLookupBlocks || len(page.Inclusions) != 0 || page.NextBefore == nil || *page.NextBefore != 976 {
		t.Fatalf("wrong maximum bound: reads=%d page=%+v", len(f.reads), page)
	}
}
