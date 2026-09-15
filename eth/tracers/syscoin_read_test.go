// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package tracers

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
)

type syscoinReadBackend struct {
	*testBackend
	generation        atomic.Uint64
	changeOnSelection bool
	beforeCheck       func()
}

func (b *syscoinReadBackend) BeginSyscoinMetadataRead() func() error {
	generation := b.generation.Load()
	return func() error {
		if b.beforeCheck != nil {
			b.beforeCheck()
		}
		if b.generation.Load() != generation {
			return core.ErrSyscoinMetadataChanged
		}
		return nil
	}
}

func (b *syscoinReadBackend) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	block, err := b.testBackend.BlockByNumber(ctx, number)
	if b.changeOnSelection {
		b.generation.Add(1)
	}
	return block, err
}

func (b *syscoinReadBackend) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	block, err := b.testBackend.BlockByHash(ctx, hash)
	if b.changeOnSelection {
		b.generation.Add(1)
	}
	return block, err
}

func newSyscoinReadBackend(t *testing.T, blocks int) *syscoinReadBackend {
	t.Helper()
	backend := makeSyscoinReadBackend(t, blocks)
	t.Cleanup(backend.teardown)
	return backend
}

// makeSyscoinReadBackend leaves cleanup to tests that must first join workers.
func makeSyscoinReadBackend(t *testing.T, blocks int) *syscoinReadBackend {
	t.Helper()
	accounts := newAccounts(2)
	genesis := &core.Genesis{
		Config: params.TestChainConfig,
		Alloc: types.GenesisAlloc{
			accounts[0].addr: {Balance: big.NewInt(params.Ether)},
		},
	}
	b := newTestBackend(t, blocks, genesis, func(i int, block *core.BlockGen) {
		tx, err := types.SignTx(types.NewTransaction(uint64(i), accounts[1].addr, big.NewInt(1), params.TxGas, block.BaseFee(), nil), types.HomesteadSigner{}, accounts[0].key)
		if err != nil {
			t.Fatal(err)
		}
		block.AddTx(tx)
	})
	return &syscoinReadBackend{testBackend: b}
}

func TestSyscoinTraceMetadataRead(t *testing.T) {
	backend := newSyscoinReadBackend(t, 2)
	api := NewAPI(backend)
	block := backend.chain.GetBlockByNumber(1)
	rawdb.WriteBadBlock(backend.chaindb, block)
	blob, err := rlp.EncodeToBytes(block)
	if err != nil {
		t.Fatal(err)
	}
	file := t.TempDir() + "/block.rlp"
	if err := os.WriteFile(file, blob, 0600); err != nil {
		t.Fatal(err)
	}
	to := common.Address{1}
	cases := []struct {
		name string
		call func() (interface{}, error)
	}{
		{"block_number", func() (interface{}, error) { return api.TraceBlockByNumber(context.Background(), 1, nil) }},
		{"block_hash", func() (interface{}, error) { return api.TraceBlockByHash(context.Background(), block.Hash(), nil) }},
		{"raw_block", func() (interface{}, error) { return api.TraceBlock(context.Background(), blob, nil) }},
		{"block_file", func() (interface{}, error) { return api.TraceBlockFromFile(context.Background(), file, nil) }},
		{"bad_block", func() (interface{}, error) { return api.TraceBadBlock(context.Background(), block.Hash(), nil) }},
		{"intermediate_roots", func() (interface{}, error) { return api.IntermediateRoots(context.Background(), block.Hash(), nil) }},
		{"transaction", func() (interface{}, error) {
			return api.TraceTransaction(context.Background(), block.Transactions()[0].Hash(), nil)
		}},
		{"call", func() (interface{}, error) {
			return api.TraceCall(context.Background(), ethapi.TransactionArgs{To: &to}, rpc.BlockNumberOrHashWithNumber(1), nil)
		}},
		{"call_tx_index", func() (interface{}, error) {
			return api.TraceCall(context.Background(), ethapi.TransactionArgs{To: &to}, rpc.BlockNumberOrHashWithNumber(1), &TraceCallConfig{TxIndex: new(hexutil.Uint)})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend.changeOnSelection = false
			if _, err := tc.call(); err != nil {
				t.Fatalf("stable generation failed: %v", err)
			}
			backend.changeOnSelection = true
			result, err := tc.call()
			if !errors.Is(err, core.ErrSyscoinMetadataChanged) {
				t.Fatalf("got %v, want metadata invalidation", err)
			}
			if result != nil && !reflect.ValueOf(result).IsNil() {
				t.Fatalf("invalidated result was not discarded: %#v", result)
			}
		})
	}
	// Even failed block selection must not conceal an intervening publication.
	if result, err := api.TraceBlockByNumber(context.Background(), 100, nil); result != nil || !errors.Is(err, core.ErrSyscoinMetadataChanged) {
		t.Fatalf("selection error was not replaced: result %v, err %v", result, err)
	}
}

func TestSyscoinTraceFileMetadataCleanup(t *testing.T) {
	backend := newSyscoinReadBackend(t, 1)
	api := NewAPI(backend)
	block := backend.chain.GetBlockByNumber(1)
	rawdb.WriteBadBlock(backend.chaindb, block)
	directory := t.TempDir()
	t.Setenv("TMPDIR", directory)
	for _, bad := range []bool{false, true} {
		// State release runs after the files were written but before validation.
		backend.relHook = func() { backend.generation.Add(1) }
		var files []string
		var err error
		if bad {
			files, err = api.StandardTraceBadBlockToFile(context.Background(), block.Hash(), nil)
		} else {
			files, err = api.StandardTraceBlockToFile(context.Background(), block.Hash(), nil)
		}
		if files != nil || !errors.Is(err, core.ErrSyscoinMetadataChanged) {
			t.Fatalf("invalidated file trace returned files %v, err %v", files, err)
		}
		entries, err := os.ReadDir(directory)
		if err != nil || len(entries) != 0 {
			t.Fatalf("invalidated trace files remain: %v, err %v", entries, err)
		}
	}
}

func TestSyscoinTraceChainMetadataRead(t *testing.T) {
	for _, invalidate := range []bool{false, true} {
		t.Run(map[bool]string{false: "stable", true: "changed_after_first_notification"}[invalidate], func(t *testing.T) {
			backend := newSyscoinReadBackend(t, 3)
			var checks, refs, releases atomic.Uint64
			backend.refHook = func() { refs.Add(1) }
			backend.relHook = func() { releases.Add(1) }
			backend.beforeCheck = func() {
				// The first check covers selection; the next accepts block 1.
				if checks.Add(1) == 3 && invalidate {
					backend.generation.Add(1)
				}
			}
			server := rpc.NewServer()
			if err := server.RegisterName("debug", NewAPI(backend)); err != nil {
				t.Fatal(err)
			}
			defer server.Stop()
			client := rpc.DialInProc(server)
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			results := make(chan *blockTraceResult, 4)
			sub, err := client.Subscribe(ctx, "debug", results, "traceChain", "0x0", "0x3")
			if err != nil {
				t.Fatal(err)
			}
			defer sub.Unsubscribe()
			want := 3
			if invalidate {
				want = 2
			}
			for i := 0; i < want; i++ {
				select {
				case result := <-results:
					if invalidate && i == 1 {
						if result.Error != core.ErrSyscoinMetadataChanged.Error() || len(result.Traces) != 0 {
							t.Fatalf("want terminal invalidation without traces, got %#v", result)
						}
					} else if result.Error != "" || len(result.Traces) != 1 || uint64(result.Block) != uint64(i+1) {
						t.Fatalf("unexpected valid notification: %#v", result)
					}
				case <-ctx.Done():
					t.Fatal("trace chain did not publish expected results")
				}
			}
			for refs.Load() != releases.Load() {
				select {
				case <-ctx.Done():
					t.Fatalf("state references leaked: refs %d, releases %d", refs.Load(), releases.Load())
				case <-time.After(time.Millisecond):
				}
			}
			select {
			case result := <-results:
				t.Fatalf("unexpected notification after completion: %#v", result)
			default:
			}
		})
	}
}

func TestSyscoinTraceChainAbortReleasesQueuedStates(t *testing.T) {
	// Block every worker and queue at least one further task before aborting.
	// The extra second task makes the first queued send happen before the
	// producer signals that the final state has been prepared.
	blocks := runtime.NumCPU() + 2
	if blocks >= maximumPendingTraceStates {
		t.Skip("worker count exceeds the state tracker test bound")
	}
	backend := makeSyscoinReadBackend(t, blocks)
	var refs, releases atomic.Uint64
	prepared := make(chan struct{})
	backend.refHook = func() {
		if refs.Add(1) == uint64(blocks) {
			close(prepared)
		}
	}
	backend.relHook = func() { releases.Add(1) }
	resume := make(chan struct{})
	var resumeOnce sync.Once
	tracerName := "syscoinQueuedStateAbortTracer"
	DefaultDirectory.Register(tracerName, func(*Context, json.RawMessage, *params.ChainConfig) (*Tracer, error) {
		<-resume
		return &Tracer{
			Hooks:     &tracing.Hooks{},
			GetResult: func() (json.RawMessage, error) { return json.RawMessage("{}"), nil },
			Stop:      func(error) {},
		}, nil
	}, false)
	closed := make(chan error)
	var closeOnce sync.Once
	api := NewAPI(backend)
	results := api.traceChain(backend.chain.GetBlockByNumber(0), backend.chain.GetBlockByNumber(uint64(blocks)), &TraceConfig{Tracer: &tracerName}, closed)
	defer func() {
		// A setup/assertion timeout must also join workers before mutating
		// their tracer registry or shutting down the state backend.
		closeOnce.Do(func() { close(closed) })
		resumeOnce.Do(func() { close(resume) })
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		for {
			select {
			case _, ok := <-results:
				if !ok {
					delete(DefaultDirectory.elems, tracerName)
					backend.teardown()
					return
				}
			case <-timer.C:
				// Leave resources intact if workers cannot be joined safely.
				t.Error("trace workers did not stop during cleanup")
				return
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	select {
	case <-prepared:
	case <-ctx.Done():
		t.Fatal("workers did not accumulate queued state")
	}
	closeOnce.Do(func() { close(closed) })
	resumeOnce.Do(func() { close(resume) })
	for {
		select {
		case _, ok := <-results:
			if !ok {
				if got := releases.Load(); got != uint64(blocks) {
					t.Fatalf("aborted trace leaked queued states: refs %d, releases %d", refs.Load(), got)
				}
				return
			}
		case <-ctx.Done():
			t.Fatal("aborted workers did not finish draining")
		}
	}
}
