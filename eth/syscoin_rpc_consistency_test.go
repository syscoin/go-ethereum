package eth

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/syscoin/syscoinwire/syscoin/wire"
)

// A read may span many EVM steps, but must not keep canonical imports waiting.
// These hooks stop the RPC after header selection or inside its metadata read,
// allowing a complete canonical update before execution resumes.
type syscoinRPCPausedBackend struct {
	*EthAPIBackend
	afterHeader    func()
	beforeMetadata func()
}

func (b *syscoinRPCPausedBackend) StateAndHeaderByNumberOrHash(ctx context.Context, number rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	state, header, err := b.EthAPIBackend.StateAndHeaderByNumberOrHash(ctx, number)
	if err == nil && b.afterHeader != nil {
		b.afterHeader()
	}
	return state, header, err
}

func (b *syscoinRPCPausedBackend) ReadDataHash(ctx context.Context, hash common.Hash) ([]byte, error) {
	if b.beforeMetadata != nil {
		b.beforeMetadata()
	}
	return b.EthAPIBackend.ReadDataHash(ctx, hash)
}

func (b *syscoinRPCPausedBackend) GetNEVMAddress(ctx context.Context, address common.Address) ([]byte, error) {
	if b.beforeMetadata != nil {
		b.beforeMetadata()
	}
	return b.EthAPIBackend.GetNEVMAddress(ctx, address)
}

func (b *syscoinRPCPausedBackend) ReadBTCCheckpointLastIndex(ctx context.Context) (uint64, error) {
	if b.beforeMetadata != nil {
		b.beforeMetadata()
	}
	return b.EthAPIBackend.ReadBTCCheckpointLastIndex(ctx)
}

type syscoinRPCFixture struct {
	eth     *Ethereum
	backend *EthAPIBackend
	db      *disconnectTestDB
	block   *types.Block
	da      common.Hash
	address common.Address
}

func newSyscoinRPCFixture(t *testing.T, scheme, operation string) *syscoinRPCFixture {
	t.Helper()
	config := *params.AllEthashProtocolChanges
	config.SyscoinBlock, config.NexusBlock = big.NewInt(0), big.NewInt(0)
	genesis := &core.Genesis{Config: &config, BaseFee: big.NewInt(params.InitialBaseFee), GasLimit: 5_000_000}
	engine := ethash.NewFaker()
	db := &disconnectTestDB{Database: rawdb.NewMemoryDatabase()}
	chain, err := core.NewBlockChain(db, core.DefaultCacheConfigWithScheme(scheme), genesis, nil, engine, vm.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { chain.Stop(); db.Close() })
	genDB, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, 1, nil)
	t.Cleanup(func() { genDB.Close() })
	f := &syscoinRPCFixture{
		eth: &Ethereum{blockchain: chain, chainDb: db, engine: engine}, db: db, block: blocks[0],
		da: common.HexToHash("0x1234"), address: common.HexToAddress("0x3456"),
	}
	f.backend = &EthAPIBackend{eth: f.eth}
	connect := makeNEVMConnect(f.block, bytes.Repeat([]byte{0x45}, common.HashLength))
	connect.VersionHashes = []*common.Hash{&f.da}
	connect.BTCPrevHash = common.HexToHash("0x2345")
	connect.Diff.AddedMNNEVM = []wire.NEVMAddressEntry{{Address: f.address.Bytes(), CollateralHeight: 12}}
	f.block.NevmBlockConnect = connect
	if operation != "connect" {
		if _, err := chain.InsertChain(blocks); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *syscoinRPCFixture) mutate(operation string) error {
	switch operation {
	case "connect":
		_, err := f.eth.blockchain.InsertChain(types.Blocks{f.block})
		return err
	case "disconnect":
		disconnect := makeNEVMDisconnect([]byte(f.block.NevmBlockConnect.Sysblockhash))
		disconnect.Diff.RemovedMNNEVM = []wire.NEVMRemoveEntry{{Address: f.address.Bytes()}}
		return f.eth.DeleteBlock(disconnect)
	default:
		return f.eth.blockchain.SetHead(0)
	}
}

func (f *syscoinRPCFixture) call(backend ethapi.Backend, metadata string) (*core.ExecutionResult, error) {
	var address common.Address
	var input hexutil.Bytes
	switch metadata {
	case "da":
		address, input = common.BytesToAddress([]byte{0x63}), f.da.Bytes()
	case "address":
		address, input = common.BytesToAddress([]byte{0x62}), f.address.Bytes()
	default:
		address = common.BytesToAddress([]byte{0x65})
	}
	gas := hexutil.Uint64(1_000_000)
	return ethapi.DoCall(context.Background(), backend, ethapi.TransactionArgs{To: &address, Input: &input, Gas: &gas},
		rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber), nil, nil, 5*time.Second, uint64(gas))
}

func (f *syscoinRPCFixture) checkCall(t *testing.T, metadata string) {
	t.Helper()
	result, err := f.call(f.backend, metadata)
	if err != nil || result == nil || result.Err != nil {
		t.Fatalf("stable %s call: result=%v err=%v", metadata, result, err)
	}
	var want []byte
	switch metadata {
	case "da":
		want = rawdb.ReadDataHash(f.db, f.da)
	case "address":
		want = common.LeftPadBytes(rawdb.GetNEVMAddress(f.db, f.address), 32)
	default:
		want = make([]byte, 32)
		binary.BigEndian.PutUint64(want[24:], rawdb.ReadBTCCheckpointLastIndex(f.db))
	}
	if !bytes.Equal(result.Return(), want) {
		t.Fatalf("stable %s call returned %x, want %x", metadata, result.Return(), want)
	}
}

func syscoinRPCWait(t *testing.T, ready <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestSyscoinRPCCanonicalChangeInvalidatesCall(t *testing.T) {
	for _, scheme := range []string{rawdb.HashScheme, rawdb.PathScheme} {
		for _, operation := range []string{"connect", "disconnect", "sethead"} {
			for _, metadata := range []string{"da", "address", "btc"} {
				for _, pauseAt := range []string{"header", "metadata"} {
					t.Run(scheme+"/"+operation+"/"+metadata+"/"+pauseAt, func(t *testing.T) {
						f := newSyscoinRPCFixture(t, scheme, operation)
						f.checkCall(t, metadata) // Include already-warm metadata caches.
						paused, resume := make(chan struct{}), make(chan struct{})
						var release sync.Once
						defer release.Do(func() { close(resume) })
						hook := func() { close(paused); <-resume }
						backend := &syscoinRPCPausedBackend{EthAPIBackend: f.backend}
						if pauseAt == "header" {
							backend.afterHeader = hook
						} else {
							backend.beforeMetadata = hook
						}
						type response struct {
							result *core.ExecutionResult
							err    error
						}
						called := make(chan response, 1)
						go func() { result, err := f.call(backend, metadata); called <- response{result, err} }()
						syscoinRPCWait(t, paused, "paused RPC")
						updated := make(chan error, 1)
						go func() { updated <- f.mutate(operation) }()
						select {
						case err := <-updated:
							if err != nil {
								t.Fatal(err)
							}
						case <-time.After(5 * time.Second):
							t.Fatal("paused RPC prevented canonical update")
						}
						release.Do(func() { close(resume) })
						select {
						case got := <-called:
							if got.result != nil || !errors.Is(got.err, core.ErrSyscoinMetadataChanged) {
								t.Fatalf("mixed-generation call returned result=%v err=%v", got.result, got.err)
							}
						case <-time.After(5 * time.Second):
							t.Fatal("RPC did not finish after canonical update")
						}
						f.checkCall(t, metadata)
					})
				}
			}
		}
	}
}

// Begin must not capture an apparently stable generation between durable commit
// and publication of the matching cache/head. Existing atomic-write tests inspect
// this exact boundary; the callback cannot call a read scope synchronously because
// it runs inside the writer's publication lock.
func TestSyscoinRPCReadWaitsForCanonicalPublication(t *testing.T) {
	for _, scheme := range []string{rawdb.HashScheme, rawdb.PathScheme} {
		for _, operation := range []string{"connect", "disconnect", "sethead"} {
			t.Run(scheme+"/"+operation, func(t *testing.T) {
				f := newSyscoinRPCFixture(t, scheme, operation)
				validateOld := f.backend.BeginSyscoinMetadataRead()
				oldHead := f.eth.blockchain.CurrentBlock().Hash()
				committed, resume := make(chan struct{}), make(chan struct{})
				var release, committedOnce sync.Once
				defer release.Do(func() { close(resume) })
				f.db.mu.Lock()
				f.db.afterWrite = func() {
					if rawdb.ReadHeadBlockHash(f.db) == oldHead {
						return // Body/state persistence is not canonical publication.
					}
					committedOnce.Do(func() { close(committed); <-resume })
				}
				f.db.mu.Unlock()
				updated := make(chan error, 1)
				go func() { updated <- f.mutate(operation) }()
				syscoinRPCWait(t, committed, "durable canonical commit")
				if f.eth.blockchain.CurrentBlock().Hash() != oldHead {
					t.Fatal("test did not stop before cached head publication")
				}
				started := make(chan struct{})
				opened := make(chan func() error, 1)
				go func() { close(started); opened <- f.backend.BeginSyscoinMetadataRead() }()
				syscoinRPCWait(t, started, "read scope start")
				readStarted := make(chan struct{}, 4)
				checked := make(chan error, 1)
				read := make(chan string, 3)
				go func() { readStarted <- struct{}{}; checked <- validateOld() }()
				go func() {
					readStarted <- struct{}{}
					f.backend.ReadDataHash(context.Background(), f.da)
					read <- "DA"
				}()
				go func() {
					readStarted <- struct{}{}
					f.backend.GetNEVMAddress(context.Background(), f.address)
					read <- "address"
				}()
				go func() {
					readStarted <- struct{}{}
					f.backend.ReadBTCCheckpointLastIndex(context.Background())
					read <- "BTC"
				}()
				for i := 0; i < 4; i++ {
					syscoinRPCWait(t, readStarted, "metadata lookup or scope validation")
				}
				select {
				case <-opened:
					t.Fatal("read scope opened between durable commit and head publication")
				case <-checked:
					t.Fatal("read scope validated between durable commit and head publication")
				case metadata := <-read:
					t.Fatalf("%s lookup completed between durable commit and head publication", metadata)
				case <-time.After(25 * time.Millisecond):
				}
				release.Do(func() { close(resume) })
				select {
				case err := <-updated:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("canonical update did not finish")
				}
				select {
				case validate := <-opened:
					if err := validate(); err != nil {
						t.Fatalf("post-publication scope: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("read scope did not open after canonical publication")
				}
				select {
				case err := <-checked:
					if !errors.Is(err, core.ErrSyscoinMetadataChanged) {
						t.Fatalf("old scope after canonical publication: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("old scope did not validate after canonical publication")
				}
				for i := 0; i < 3; i++ {
					select {
					case <-read:
					case <-time.After(5 * time.Second):
						t.Fatal("metadata lookup did not finish after canonical publication")
					}
				}
				for _, metadata := range []string{"da", "address", "btc"} {
					f.checkCall(t, metadata)
				}
			})
		}
	}
}

func TestSyscoinRPCFailedPublicationAndRetry(t *testing.T) {
	for _, operation := range []string{"connect", "disconnect", "sethead"} {
		t.Run(operation, func(t *testing.T) {
			f := newSyscoinRPCFixture(t, rawdb.HashScheme, operation)
			validate := f.backend.BeginSyscoinMetadataRead()
			oldHead := f.eth.blockchain.CurrentBlock().Hash()
			writeErr := errors.New("injected canonical write failure")
			f.db.mu.Lock()
			if operation == "connect" {
				// Preserve the initial body write, then fail canonical publication.
				f.db.afterWrite = func() { f.db.fail = writeErr }
			} else {
				f.db.fail = writeErr
			}
			f.db.mu.Unlock()
			if err := f.mutate(operation); !errors.Is(err, writeErr) {
				t.Fatalf("failed update: %v", err)
			}
			f.db.mu.Lock()
			f.db.afterWrite, f.db.fail = nil, nil
			f.db.mu.Unlock()
			if f.eth.blockchain.CurrentBlock().Hash() != oldHead {
				t.Fatal("failed publication changed cached head")
			}
			if err := validate(); !errors.Is(err, core.ErrSyscoinMetadataChanged) {
				t.Fatalf("failed publication did not conservatively invalidate reader: %v", err)
			}
			for _, metadata := range []string{"da", "address", "btc"} {
				f.checkCall(t, metadata)
			}
			validate = f.backend.BeginSyscoinMetadataRead()
			if err := f.mutate(operation); err != nil {
				t.Fatalf("retry: %v", err)
			}
			if err := validate(); !errors.Is(err, core.ErrSyscoinMetadataChanged) {
				t.Fatalf("retry did not invalidate reader: %v", err)
			}
			for _, metadata := range []string{"da", "address", "btc"} {
				f.checkCall(t, metadata)
			}
		})
	}
}
