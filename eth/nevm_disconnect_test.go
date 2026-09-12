package eth

import (
	"bytes"
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/syscoin/syscoinwire/syscoin/wire"
)

// SYSCOIN: observe every durable batch boundary, including the first one after
// which a process could crash. Failure injection must not publish caches/events.
type disconnectTestDB struct {
	ethdb.Database
	mu         sync.Mutex
	afterWrite func()
	fail       error
}

type disconnectTestBatch struct {
	ethdb.Batch
	db *disconnectTestDB
}

func (db *disconnectTestDB) NewBatch() ethdb.Batch {
	return &disconnectTestBatch{Batch: db.Database.NewBatch(), db: db}
}

func (b *disconnectTestBatch) Write() error {
	b.db.mu.Lock()
	defer b.db.mu.Unlock()
	if b.db.fail != nil {
		return b.db.fail
	}
	if err := b.Batch.Write(); err != nil {
		return err
	}
	if b.db.afterWrite != nil {
		b.db.afterWrite()
	}
	return nil
}

func TestNEVMDisconnectAtomicPublication(t *testing.T) {
	for _, test := range []struct {
		name, scheme string
		fail         bool
	}{
		{"hash-atomic", rawdb.HashScheme, false}, {"hash-failed-write-retry", rawdb.HashScheme, true},
		{"path-atomic", rawdb.PathScheme, false}, {"path-failed-write-retry", rawdb.PathScheme, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := *params.AllEthashProtocolChanges
			config.SyscoinBlock = big.NewInt(0)
			key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
			if err != nil {
				t.Fatal(err)
			}
			contract := common.HexToAddress("0x7777")
			genesis := &core.Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: &config, Alloc: types.GenesisAlloc{
				crypto.PubkeyToAddress(key.PublicKey): {Balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)},
				contract:                              {Code: common.FromHex("0x60006000a000")}, // LOG0, then STOP.
			}}
			engine := ethash.NewFaker()
			db := &disconnectTestDB{Database: rawdb.NewMemoryDatabase()}
			defer db.Close()
			chain, err := core.NewBlockChain(db, core.DefaultCacheConfigWithScheme(test.scheme), genesis, nil, engine, vm.Config{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if chain != nil {
					chain.Stop()
				}
			}()
			eth := &Ethereum{blockchain: chain, chainDb: db}
			var tx *types.Transaction
			genDB, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, 1, func(_ int, b *core.BlockGen) {
				tx = types.MustSignNewTx(key, b.Signer(), &types.LegacyTx{To: &contract, Gas: 100_000, GasPrice: big.NewInt(params.InitialBaseFee)})
				b.AddTx(tx)
			})
			defer genDB.Close()
			tip := blocks[0]
			data := common.HexToHash("0x1111")
			btc := common.HexToHash("0x2222")
			addr := common.HexToAddress("0x3333")
			sys := bytes.Repeat([]byte{0x44}, common.HashLength)
			connect := makeNEVMConnect(tip, sys)
			connect.VersionHashes = []*common.Hash{&data}
			connect.BTCPrevHash = btc
			connect.Diff.AddedMNNEVM = []wire.NEVMAddressEntry{{Address: addr.Bytes(), CollateralHeight: 12}}
			tip.NevmBlockConnect = connect
			if _, err := chain.InsertChain(blocks); err != nil {
				t.Fatal(err)
			}
			disconnect := makeNEVMDisconnect(sys)
			disconnect.Diff.RemovedMNNEVM = []wire.NEVMRemoveEntry{{Address: addr.Bytes()}}
			check := func(present, caches bool) {
				t.Helper()
				wantHead := tip.ParentHash()
				if present {
					wantHead = tip.Hash()
				}
				if rawdb.ReadHeadBlockHash(db) != wantHead || rawdb.ReadHeadHeaderHash(db) != wantHead || rawdb.ReadHeadFastBlockHash(db) != wantHead ||
					(rawdb.ReadCanonicalHash(db, 1) == tip.Hash()) != present ||
					(len(rawdb.ReadDataHash(db, data)) > 0) != present ||
					(len(rawdb.ReadSYSHash(db, 1)) > 0) != present ||
					(rawdb.ReadBTCCheckpointIndexByHash(db, btc) == 1) != present ||
					(rawdb.ReadBTCCheckpointLastIndex(db) == 1) != present ||
					(rawdb.ReadTxLookupEntry(db, tx.Hash()) != nil) != present ||
					(len(rawdb.GetNEVMAddress(db, addr)) > 0) != present {
					t.Error("durable head and rollback metadata disagree")
				}
				if caches && (chain.CurrentBlock().Hash() != wantHead ||
					(len(chain.ReadDataHash(data)) > 0) != present ||
					(len(chain.ReadSYSHash(1)) > 0) != present ||
					(chain.BTCCheckpointIndex(btc) == 1) != present ||
					(chain.ReadBTCCheckpointLastIndex() == 1) != present ||
					(len(chain.GetNEVMAddress(addr)) > 0) != present) {
					t.Error("published head and metadata caches disagree")
				}
				if caches {
					lookup, _, err := chain.GetTransactionLookup(tx.Hash())
					if err != nil || (lookup != nil) != present {
						t.Errorf("transaction lookup after rollback: %v, %v", lookup, err)
					}
				}
			}
			check(true, true) // Warm every retained cache before disconnect.
			events := make(chan core.ChainHeadEvent, 2)
			sub := chain.SubscribeChainHeadEvent(events)
			defer sub.Unsubscribe()
			removed := make(chan core.RemovedLogsEvent, 2)
			logSub := chain.SubscribeRemovedLogsEvent(removed)
			defer logSub.Unsubscribe()
			if test.fail {
				writeErr := errors.New("injected disconnect write failure")
				db.mu.Lock()
				db.fail = writeErr
				db.mu.Unlock()
				if err := eth.DeleteBlock(disconnect); !errors.Is(err, writeErr) {
					t.Fatalf("disconnect error: %v", err)
				}
				check(true, true)
				select {
				case <-events:
					t.Fatal("failed disconnect published a head event")
				default:
				}
				select {
				case <-removed:
					t.Fatal("failed disconnect published removed logs")
				default:
				}
				db.mu.Lock()
				db.fail = nil
				db.mu.Unlock()
			}
			writes := 0
			db.mu.Lock()
			db.afterWrite = func() {
				writes++
				check(false, false)
				if chain.CurrentBlock().Hash() != tip.Hash() {
					t.Error("new head published before durable commit returned")
				}
				select {
				case <-events:
					t.Error("head event published before durable commit returned")
				default:
				}
				select {
				case <-removed:
					t.Error("removed logs published before durable commit returned")
				default:
				}
			}
			db.mu.Unlock()
			if err := eth.DeleteBlock(disconnect); err != nil {
				t.Fatal(err)
			}
			db.mu.Lock()
			db.afterWrite = nil
			db.mu.Unlock()
			if writes != 1 {
				t.Errorf("disconnect committed %d batches, want one", writes)
			}
			check(false, true)
			select {
			case event := <-events:
				if event.Header.Hash() != tip.ParentHash() {
					t.Error("wrong rollback event head")
				}
			default:
				t.Error("successful disconnect did not publish head event")
			}
			select {
			case event := <-removed:
				if len(event.Logs) != 1 || !event.Logs[0].Removed || event.Logs[0].TxHash != tx.Hash() {
					t.Error("wrong rollback logs")
				}
			default:
				t.Error("successful disconnect did not publish removed logs")
			}
			chain.Stop()
			chain, err = core.NewBlockChain(db, core.DefaultCacheConfigWithScheme(test.scheme), genesis, nil, engine, vm.Config{}, nil)
			if err != nil {
				t.Fatalf("restart after disconnect: %v", err)
			}
			check(false, true)
		})
	}
}

// SYSCOIN: body/state persistence must not publish canonical metadata early.
// Supplied Core pairs deliberately re-execute even if their block is stored.
func TestNEVMConnectAtomicMetadata(t *testing.T) {
	for _, test := range []struct {
		name         string
		stored, fail bool
	}{
		{"fresh", false, false}, {"stored-reexecution", true, false},
		{"fresh-failed-write-retry", false, true}, {"stored-failed-write-retry", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := *params.AllEthashProtocolChanges
			config.SyscoinBlock = big.NewInt(0)
			genesis := &core.Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: &config}
			engine := ethash.NewFaker()
			db := &disconnectTestDB{Database: rawdb.NewMemoryDatabase()}
			defer db.Close()
			chain, err := core.NewBlockChain(db, core.DefaultCacheConfigWithScheme(rawdb.HashScheme), genesis, nil, engine, vm.Config{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if chain != nil {
					chain.Stop()
				}
			}()
			genDB, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, 1, nil)
			defer genDB.Close()
			block := blocks[0]
			hash, btc, addr := common.HexToHash("0x1234"), common.HexToHash("0x2345"), common.HexToAddress("0x3456")
			connect := makeNEVMConnect(block, bytes.Repeat([]byte{0x45}, common.HashLength))
			connect.VersionHashes = []*common.Hash{&hash}
			connect.BTCPrevHash = btc
			connect.Diff.AddedMNNEVM = []wire.NEVMAddressEntry{{Address: addr.Bytes(), CollateralHeight: 3}}
			block.NevmBlockConnect = connect
			if test.stored {
				rawdb.WriteBlock(db, block)
				rawdb.WriteReceipts(db, block.Hash(), 1, nil)
			}
			check := func() {
				t.Helper()
				present := rawdb.ReadHeadBlockHash(db) == block.Hash()
				if (len(rawdb.ReadDataHash(db, hash)) > 0) != present ||
					(len(rawdb.ReadSYSHash(db, 1)) > 0) != present ||
					(rawdb.ReadBTCCheckpointIndexByHash(db, btc) == 1) != present ||
					(len(rawdb.GetNEVMAddress(db, addr)) > 0) != (present && len(connect.Diff.AddedMNNEVM) > 0) {
					t.Error("connect committed metadata separately from canonical head")
				}
			}
			if test.fail {
				writeErr := errors.New("injected canonical connect write failure")
				events := make(chan core.ChainHeadEvent, 1)
				sub := chain.SubscribeChainHeadEvent(events)
				defer sub.Unsubscribe()
				db.mu.Lock()
				db.afterWrite = func() {
					check()
					// At block 1 in hash mode, trie state stays in memory. After its
					// body batch, the next write is the canonical metadata/head batch.
					db.fail = writeErr
				}
				db.mu.Unlock()
				_, insertErr := chain.InsertChain(blocks)
				db.mu.Lock()
				db.fail, db.afterWrite = nil, nil
				db.mu.Unlock()
				if !errors.Is(insertErr, writeErr) {
					t.Fatalf("connect error: %v", insertErr)
				}
				check()
				if rawdb.ReadHeadBlockHash(db) != block.ParentHash() || chain.CurrentBlock().Hash() != block.ParentHash() ||
					len(chain.ReadDataHash(hash)) != 0 || len(chain.ReadSYSHash(1)) != 0 || chain.BTCCheckpointIndex(btc) != 0 || len(chain.GetNEVMAddress(addr)) != 0 {
					t.Fatal("failed connect published its head or metadata caches")
				}
				select {
				case <-events:
					t.Fatal("failed connect published a head event")
				default:
				}
				chain.Stop()
				chain, err = core.NewBlockChain(db, core.DefaultCacheConfigWithScheme(rawdb.HashScheme), genesis, nil, engine, vm.Config{}, nil)
				if err != nil {
					t.Fatalf("restart after failed connect: %v", err)
				}
				check()
				// Retry the stored EVM block with a different Core pair and no address
				// diff. The failed pair must not have left its address behind.
				connect.Sysblockhash = string(bytes.Repeat([]byte{0x46}, common.HashLength))
				connect.Diff.AddedMNNEVM = nil
			}
			db.mu.Lock()
			db.afterWrite = check
			db.mu.Unlock()
			if _, err := chain.InsertChain(blocks); err != nil {
				t.Fatal(err)
			}
			db.mu.Lock()
			db.afterWrite = nil
			db.mu.Unlock()
			check()
			if len(chain.ReadDataHash(hash)) == 0 || string(chain.ReadSYSHash(1)) != connect.Sysblockhash || chain.BTCCheckpointIndex(btc) != 1 || (len(chain.GetNEVMAddress(addr)) > 0) != !test.fail {
				t.Fatal("successful connect did not publish metadata caches")
			}
		})
	}
}
