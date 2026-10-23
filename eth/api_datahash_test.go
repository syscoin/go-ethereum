package eth

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/rpc"
)

type dataHashAPIFixture struct {
	hashes []common.Hash
	before *uint64
	limit  uint64
}

func (f *dataHashAPIFixture) GetDataHashInclusions(_ context.Context, hashes []common.Hash, before *uint64, limit uint64) (*core.DataHashInclusionPage, error) {
	f.hashes, f.before, f.limit = hashes, before, limit
	return &core.DataHashInclusionPage{Inclusions: []core.DataHashInclusionCandidate{}, Exhausted: true}, nil
}

func TestDataHashLookupRPCArguments(t *testing.T) {
	f := new(dataHashAPIFixture)
	server := rpc.NewServer()
	defer server.Stop()
	if err := server.RegisterName("eth", &DataHashAPI{chain: f}); err != nil {
		t.Fatal(err)
	}
	client := rpc.DialInProc(server)
	defer client.Close()
	hash := common.HexToHash("0x01")
	var page core.DataHashInclusionPage
	if err := client.CallContext(context.Background(), &page, "eth_getDataHashInclusions", []common.Hash{hash}); err != nil {
		t.Fatal(err)
	}
	if len(f.hashes) != 1 || f.hashes[0] != hash || f.before != nil || f.limit != core.DefaultDataHashLookupBlocks || !page.Exhausted {
		t.Fatalf("wrong default query: %+v", f)
	}
	if err := client.CallContext(context.Background(), &page, "eth_getDataHashInclusions", []common.Hash{hash}, hexutil.Uint64(100), hexutil.Uint64(1024)); err != nil {
		t.Fatal(err)
	}
	if f.before == nil || *f.before != 100 || f.limit != 1024 {
		t.Fatalf("wrong explicit query: %+v", f)
	}
	if err := client.CallContext(context.Background(), &page, "eth_getDataHashInclusions", []string{"0x01"}); err == nil {
		t.Fatal("non-32-byte input accepted")
	}
}
