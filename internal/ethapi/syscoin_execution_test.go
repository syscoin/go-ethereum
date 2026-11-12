package ethapi

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

// The real publication locking is covered by eth's integration tests. This
// backend makes generation changes deterministic at each execution entry point,
// including a later estimator/access-list iteration or simulated block.
type syscoinExecutionBackend struct {
	*testBackend
	generation, begins, checks, metadataReads int
	changeAfterSelection, changeDuringReads   bool
	selectionError                            error
}

func (b *syscoinExecutionBackend) BeginSyscoinMetadataRead() func() error {
	b.begins++
	generation := b.generation
	return func() error {
		b.checks++
		if generation != b.generation {
			return core.ErrSyscoinMetadataChanged
		}
		return nil
	}
}

func (b *syscoinExecutionBackend) StateAndHeaderByNumberOrHash(ctx context.Context, number rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	statedb, header, err := b.testBackend.StateAndHeaderByNumberOrHash(ctx, number)
	if b.changeAfterSelection {
		b.generation++
	}
	if b.selectionError != nil {
		return nil, nil, b.selectionError
	}
	return statedb, header, err
}

func (b *syscoinExecutionBackend) ReadDataHash(ctx context.Context, hash common.Hash) ([]byte, error) {
	b.metadataReads++
	if b.changeDuringReads && b.metadataReads == 2 {
		b.generation++
	}
	return b.testBackend.ReadDataHash(ctx, hash)
}

func (b *syscoinExecutionBackend) GetEVM(ctx context.Context, statedb *state.StateDB, header *types.Header, config *vm.Config, blockContext *vm.BlockContext) *vm.EVM {
	// Route this mock EVM through the injectable metadata reader when AccessList
	// asks it to construct its own context, rather than providing one like DoCall.
	if blockContext == nil {
		context := core.NewEVMBlockContext(header, NewChainContext(ctx, b), nil)
		blockContext = &context
	}
	return b.testBackend.GetEVM(ctx, statedb, header, config, blockContext)
}

func TestSyscoinExecutionReadScopes(t *testing.T) {
	for _, entry := range []string{"estimate", "accesslist", "simulate"} {
		for _, scenario := range []string{"stable", "after-selection", "later-metadata-read", "selection-error", "changed-selection-error"} {
			t.Run(entry+"/"+scenario, func(t *testing.T) {
				config := *params.AllEthashProtocolChanges
				config.SyscoinBlock, config.NexusBlock = big.NewInt(0), big.NewInt(0)
				contract := common.HexToAddress("0x7777")
				genesis := &core.Genesis{
					Config: &config, BaseFee: big.NewInt(params.InitialBaseFee), GasLimit: 5_000_000,
					Alloc: types.GenesisAlloc{
						// Read slot zero, then return DA precompile(0x1234). The slot
						// ensures AccessList executes at least twice to converge.
						contract: {Code: common.FromHex("600054506112346000526020600060206000606361fffffa5060206000f3")},
					},
				}
				base := newTestBackend(t, 0, genesis, ethash.NewFaker(), nil)
				t.Cleanup(func() { base.chain.Stop(); base.db.Close(); base.accman.Close() })
				backend := &syscoinExecutionBackend{
					testBackend:          base,
					changeAfterSelection: scenario == "after-selection" || scenario == "changed-selection-error",
					changeDuringReads:    scenario == "later-metadata-read",
				}
				selectionErr := errors.New("injected state/header selection failure")
				if scenario == "selection-error" || scenario == "changed-selection-error" {
					backend.selectionError = selectionErr
				}
				gas := hexutil.Uint64(1_000_000)
				args := TransactionArgs{From: &base.acc.Address, To: &contract, Gas: &gas}
				number := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
				var (
					gasUsed uint64
					list    types.AccessList
					blocks  []*simBlockResult
					vmErr   error
					err     error
				)
				switch entry {
				case "estimate":
					var estimate hexutil.Uint64
					estimate, err = DoEstimateGas(context.Background(), backend, args, number, nil, nil, uint64(gas))
					gasUsed = uint64(estimate)
				case "accesslist":
					list, gasUsed, vmErr, err = AccessList(context.Background(), backend, number, args, nil)
				case "simulate":
					opts := simOpts{BlockStateCalls: []simBlock{{Calls: []TransactionArgs{args}}, {Calls: []TransactionArgs{args}}}}
					blocks, err = NewBlockChainAPI(backend).SimulateV1(context.Background(), opts, &number)
				}
				if backend.begins != 1 || backend.checks != 1 {
					t.Fatalf("read scope began %d times and checked %d times, want once each", backend.begins, backend.checks)
				}
				wantErr := backend.selectionError
				if backend.changeAfterSelection || backend.changeDuringReads {
					wantErr = core.ErrSyscoinMetadataChanged
				}
				if !errors.Is(err, wantErr) {
					t.Fatalf("execution error %v, want %v", err, wantErr)
				}
				if wantErr != nil {
					if gasUsed != 0 || list != nil || blocks != nil || vmErr != nil {
						t.Fatalf("failed scope retained execution output: gas=%d list=%v blocks=%v vmErr=%v", gasUsed, list, blocks, vmErr)
					}
				} else {
					if vmErr != nil {
						t.Fatalf("stable execution failed: %v", vmErr)
					}
					switch entry {
					case "estimate":
						if gasUsed <= params.TxGas {
							t.Fatalf("stable estimate %d did not execute the contract", gasUsed)
						}
					case "accesslist":
						if gasUsed <= params.TxGas || len(list) != 1 || list[0].Address != contract || len(list[0].StorageKeys) != 1 || list[0].StorageKeys[0] != (common.Hash{}) {
							t.Fatalf("stable access list gas=%d list=%v", gasUsed, list)
						}
					case "simulate":
						if len(blocks) != 2 {
							t.Fatalf("simulated %d blocks, want two", len(blocks))
						}
						for i, block := range blocks {
							if len(block.Calls) != 1 || uint64(block.Calls[0].Status) != types.ReceiptStatusSuccessful || !bytes.Equal(block.Calls[0].ReturnValue, common.HexToHash("0x1234").Bytes()) {
								t.Fatalf("stable simulated block %d calls=%v", i, block.Calls)
							}
						}
					}
				}
				if (scenario == "stable" || scenario == "later-metadata-read") && backend.metadataReads < 2 {
					t.Fatalf("only %d metadata reads; did not exercise repeated execution", backend.metadataReads)
				}
			})
		}
	}
}
