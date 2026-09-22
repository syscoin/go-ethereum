package eth

import (
	"bytes"
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
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
	readMu     sync.Mutex
	readKey    []byte
	readValue  []byte
	readErr    error
	readHits   int
}

// SYSCOIN: embedding Database must not hide the fixture's optional barrier.
func (db *disconnectTestDB) SyncKeyValue() error {
	return ethdb.SyncKeyValue(db.Database)
}

func (db *disconnectTestDB) Get(key []byte) ([]byte, error) {
	db.readMu.Lock()
	defer db.readMu.Unlock()
	if db.readKey != nil && bytes.Equal(key, db.readKey) {
		db.readHits++
		return bytes.Clone(db.readValue), db.readErr
	}
	return db.Database.Get(key)
}

type disconnectReceiptKeyCapture struct{ key []byte }

func (c *disconnectReceiptKeyCapture) Put(key, _ []byte) error {
	c.key = bytes.Clone(key)
	return nil
}

func (c *disconnectReceiptKeyCapture) Delete([]byte) error {
	return errors.New("unexpected delete while capturing receipt key")
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
		receiptFault string
		empty        bool
	}{
		{"hash-atomic", rawdb.HashScheme, false, "", false}, {"hash-failed-write-retry", rawdb.HashScheme, true, "", false},
		{"path-atomic", rawdb.PathScheme, false, "", false}, {"path-failed-write-retry", rawdb.PathScheme, true, "", false},
		{"hash-receipt-io", rawdb.HashScheme, false, "io", false}, {"path-receipt-io", rawdb.PathScheme, false, "io", false},
		{"hash-receipt-missing", rawdb.HashScheme, false, "missing", false}, {"path-receipt-missing", rawdb.PathScheme, false, "missing", false},
		{"hash-receipt-malformed", rawdb.HashScheme, false, "malformed", false}, {"path-receipt-malformed", rawdb.PathScheme, false, "malformed", false},
		{"hash-receipt-count", rawdb.HashScheme, false, "count", false}, {"path-receipt-count", rawdb.PathScheme, false, "count", false},
		{"hash-empty-tip", rawdb.HashScheme, false, "", true}, {"path-empty-tip", rawdb.PathScheme, false, "", true},
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
			db := &disconnectTestDB{Database: newNEVMTestMemoryDatabase()}
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
			genDB, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, 2, func(i int, b *core.BlockGen) {
				if i == 1 && test.empty {
					tx = nil
					return
				}
				tx = types.MustSignNewTx(key, b.Signer(), &types.LegacyTx{Nonce: uint64(i), To: &contract, Gas: 100_000, GasPrice: big.NewInt(params.InitialBaseFee)})
				b.AddTx(tx)
			})
			defer genDB.Close()
			parent, tip := blocks[0], blocks[1]
			height := tip.NumberU64()
			parentSYS := bytes.Repeat([]byte{0x43}, common.HashLength)
			parent.NevmBlockConnect = makeNEVMConnect(parent, parentSYS)
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
					(rawdb.ReadCanonicalHash(db, height) == tip.Hash()) != present ||
					(len(rawdb.ReadDataHash(db, data)) > 0) != present ||
					(len(rawdb.ReadSYSHash(db, height)) > 0) != present ||
					(rawdb.ReadBTCCheckpointIndexByHash(db, btc) == 1) != present ||
					(rawdb.ReadBTCCheckpointLastIndex(db) == 1) != present ||
					(tx != nil && (rawdb.ReadTxLookupEntry(db, tx.Hash()) != nil) != present) ||
					(len(rawdb.GetNEVMAddress(db, addr)) > 0) != present {
					t.Error("durable head and rollback metadata disagree")
				}
				if rawdb.ReadCanonicalHash(db, parent.NumberU64()) != parent.Hash() ||
					!bytes.Equal(rawdb.ReadSYSHash(db, parent.NumberU64()), parentSYS) {
					t.Error("rollback changed the retained canonical parent")
				}
				if caches && (chain.CurrentBlock().Hash() != wantHead ||
					(len(chain.ReadDataHash(data)) > 0) != present ||
					(len(chain.ReadSYSHash(height)) > 0) != present ||
					(chain.BTCCheckpointIndex(btc) == 1) != present ||
					(chain.ReadBTCCheckpointLastIndex() == 1) != present ||
					(len(chain.GetNEVMAddress(addr)) > 0) != present) {
					t.Error("published head and metadata caches disagree")
				}
				if caches && tx != nil {
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
			added := make(chan []*types.Log, 4)
			addedSub := chain.SubscribeLogsEvent(added)
			defer addedSub.Unsubscribe()
			chainEvents := make(chan core.ChainEvent, 2)
			chainSub := chain.SubscribeChainEvent(chainEvents)
			defer chainSub.Unsubscribe()
			checkNoAddedLogs := func() {
				select {
				case logs := <-added:
					t.Errorf("disconnect published added logs from unchanged parent: %v", logs)
				default:
				}
			}
			parentReceipts := chain.GetReceiptsByHash(parent.Hash())
			if len(parentReceipts) != 1 || len(parentReceipts[0].Logs) != 1 {
				t.Fatal("retained parent must contain a receipt log")
			}
			// Cancelling a queued child must not publish persisted-chain events.
			bufferedBlocks, _ := core.GenerateChain(&config, tip, engine, genDB, 1, nil)
			bufferedSYS := bytes.Repeat([]byte{0x55}, common.HashLength)
			eth.blockConnectBuffer = []*types.NEVMBlockConnect{makeNEVMConnect(bufferedBlocks[0], bufferedSYS)}
			if err := eth.DeleteBlock(makeNEVMDisconnect(bufferedSYS)); err != nil {
				t.Fatal(err)
			}
			check(true, true)
			checkNoAddedLogs()
			if len(events) != 0 || len(removed) != 0 || len(chainEvents) != 0 || len(eth.blockConnectBuffer) != 0 {
				t.Fatal("buffered cancellation changed persisted-chain notifications")
			}
			if test.receiptFault != "" {
				capture := new(disconnectReceiptKeyCapture)
				rawdb.WriteReceipts(capture, tip.Hash(), height, nil)
				readErr := errors.New("injected receipt read failure")
				db.readMu.Lock()
				db.readKey, db.readHits = capture.key, 0
				switch test.receiptFault {
				case "io":
					db.readErr = readErr
				case "missing":
					db.readErr = ethdb.ErrKeyNotFound
				case "malformed":
					db.readValue = []byte{0xff}
				case "count":
					db.readValue = []byte{0xc0} // Valid RLP empty list for a nonempty block.
				}
				db.readMu.Unlock()
				failedWrites := 0
				db.mu.Lock()
				db.afterWrite = func() { failedWrites++ }
				db.mu.Unlock()
				checkGeneration := chain.BeginSyscoinMetadataRead()
				err := eth.DeleteBlock(disconnect)
				db.mu.Lock()
				db.afterWrite = nil
				db.mu.Unlock()
				db.readMu.Lock()
				hits := db.readHits
				db.readKey, db.readValue, db.readErr = nil, nil, nil
				db.readMu.Unlock()
				if hits == 0 {
					t.Fatal("disconnect did not attempt the injected receipt read")
				}
				if err == nil {
					t.Error("receipt read fault was accepted as successful disconnect")
				}
				var invalid *consensus.InvalidBlockError
				if errors.As(err, &invalid) || (test.receiptFault == "io" && !errors.Is(err, readErr)) {
					t.Errorf("receipt failure was not preserved as a local error: %v", err)
				}
				if failedWrites != 0 || len(events) != 0 || len(removed) != 0 || len(chainEvents) != 0 || len(added) != 0 {
					t.Error("receipt preflight failure committed metadata or published events")
				}
				if err := checkGeneration(); err != nil {
					t.Errorf("receipt preflight failure changed metadata generation: %v", err)
				}
				check(true, true)
				if err == nil {
					return // Baseline already moved the head; that is not a failed-operation retry.
				}
			}
			if test.fail {
				writeErr := errors.New("injected disconnect write failure")
				db.mu.Lock()
				db.fail = writeErr
				db.mu.Unlock()
				if err := eth.DeleteBlock(disconnect); !errors.Is(err, writeErr) {
					t.Fatalf("disconnect error: %v", err)
				}
				check(true, true)
				checkNoAddedLogs()
				if len(chainEvents) != 0 {
					t.Fatal("failed disconnect published a chain event")
				}
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
				checkNoAddedLogs()
				if len(chainEvents) != 0 {
					t.Error("chain event published before durable commit returned")
				}
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
			checkNoAddedLogs()
			select {
			case event := <-chainEvents:
				if event.Header.Hash() != parent.Hash() {
					t.Error("wrong rollback chain event head")
				}
			default:
				t.Error("successful disconnect did not publish chain event")
			}
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
				if tx == nil || len(event.Logs) != 1 || !event.Logs[0].Removed || event.Logs[0].TxHash != tx.Hash() ||
					event.Logs[0].BlockHash != tip.Hash() {
					t.Error("wrong rollback logs")
				}
			default:
				if !test.empty {
					t.Error("successful disconnect did not publish removed logs")
				}
			}
			chain.Stop()
			chain, err = core.NewBlockChain(db, core.DefaultCacheConfigWithScheme(test.scheme), genesis, nil, engine, vm.Config{}, nil)
			if err != nil {
				t.Fatalf("restart after disconnect: %v", err)
			}
			check(false, true)
			// A genuinely connected replacement still publishes its added logs.
			replacements, _ := core.GenerateChain(&config, parent, engine, genDB, 1, func(_ int, b *core.BlockGen) {
				b.SetExtra([]byte("replacement"))
				b.AddTx(types.MustSignNewTx(key, b.Signer(), &types.LegacyTx{
					Nonce: 1, To: &contract, Gas: 100_000, GasPrice: big.NewInt(params.InitialBaseFee), Data: []byte{1},
				}))
			})
			replacement := replacements[0]
			replacement.NevmBlockConnect = makeNEVMConnect(replacement, bytes.Repeat([]byte{0x66}, common.HashLength))
			replacementLogs := make(chan []*types.Log, 2)
			replacementSub := chain.SubscribeLogsEvent(replacementLogs)
			defer replacementSub.Unsubscribe()
			if _, err := chain.InsertChain(replacements); err != nil {
				t.Fatal(err)
			}
			select {
			case logs := <-replacementLogs:
				if len(logs) != 1 || logs[0].Removed || logs[0].BlockHash != replacement.Hash() ||
					logs[0].TxHash != replacement.Transactions()[0].Hash() {
					t.Fatal("wrong added logs for replacement child")
				}
			default:
				t.Fatal("replacement child did not publish added logs")
			}
			if len(replacementLogs) != 0 {
				t.Fatal("replacement child published extra log events")
			}
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
			db := &disconnectTestDB{Database: newNEVMTestMemoryDatabase()}
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
			// SYSCOIN: arm the canonical batch fault only after baseline storage
			// maintenance, so it still targets metadata publication.
			if err := chain.SyncSyscoinPair(0, common.Hash{}.Bytes()); err != nil {
				t.Fatal(err)
			}
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
