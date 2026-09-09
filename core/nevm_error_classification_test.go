// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package core

import (
	"bytes"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/syscoin/syscoinwire/syscoin/wire"
)

func assertInvalidBlockClass(t *testing.T, err error, invalid bool) {
	t.Helper()
	var tagged *consensus.InvalidBlockError
	if errors.As(err, &tagged) != invalid {
		t.Fatalf("invalid marker = %v, want %v; error: %v", tagged != nil, invalid, err)
	}
}

func classificationChain(t *testing.T, db ethdb.Database) (*BlockChain, *Genesis, *ethash.Ethash) {
	t.Helper()
	config := *params.AllEthashProtocolChanges
	config.SyscoinBlock = big.NewInt(0)
	genesis := &Genesis{Config: &config, BaseFee: big.NewInt(params.InitialBaseFee)}
	engine := ethash.NewFaker()
	chain, err := NewBlockChain(db, DefaultCacheConfigWithScheme(rawdb.HashScheme), genesis, nil, engine, vm.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(chain.Stop)
	return chain, genesis, engine
}

func pairClassificationBlock(block *types.Block) {
	block.NevmBlockConnect = &types.NEVMBlockConnect{
		Block: block, Sysblockhash: string(bytes.Repeat([]byte{0x42}, common.HashLength)),
		Diff: new(wire.NEVMAddressDiff),
	}
}

func TestNEVMImportErrorClassification(t *testing.T) {
	for _, name := range []string{"valid", "header", "state", "mutable-body", "future", "unknown-parent"} {
		t.Run(name, func(t *testing.T) {
			db := rawdb.NewMemoryDatabase()
			t.Cleanup(func() { db.Close() })
			chain, genesis, engine := classificationChain(t, db)
			genDB, blocks, _ := GenerateChainWithGenesis(genesis, engine, 1, nil)
			defer genDB.Close()
			header := blocks[0].Header()
			switch name {
			case "header":
				header.GasUsed = header.GasLimit + 1
			case "state":
				header.Root[0] ^= 1
			case "mutable-body":
				header.TxHash[0] ^= 1
			case "future":
				header.Time = uint64(time.Now().Add(time.Hour).Unix())
			case "unknown-parent":
				header.ParentHash[0] ^= 1
			}
			block := types.NewBlockWithHeader(header).WithBody(*blocks[0].Body())
			pairClassificationBlock(block)
			_, err := chain.InsertChain(types.Blocks{block})
			if name == "valid" {
				if err != nil || chain.CurrentBlock().Hash() != block.Hash() {
					t.Fatalf("valid import: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected rejected import")
			}
			assertInvalidBlockClass(t, err, name == "header" || name == "state")
			if chain.CurrentBlock().Hash() != genesis.ToBlock().Hash() {
				t.Fatal("rejected import changed the canonical head")
			}
		})
	}
}

type classificationFaultDB struct {
	ethdb.Database
	fault      error
	faultKey   []byte
	captureKey bool
}

func (db *classificationFaultDB) Get(key []byte) ([]byte, error) {
	if db.fault != nil && (db.faultKey == nil || bytes.Equal(key, db.faultKey)) {
		return nil, db.fault
	}
	return db.Database.Get(key)
}

func (db *classificationFaultDB) Put(key, value []byte) error {
	if db.captureKey {
		db.faultKey = bytes.Clone(key)
	}
	return db.Database.Put(key, value)
}

func TestNEVMProcessorChainReadErrorOverridesInvalidity(t *testing.T) {
	db := &classificationFaultDB{Database: rawdb.NewMemoryDatabase()}
	t.Cleanup(func() { db.Close() })
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatal(err)
	}
	config := *params.AllEthashProtocolChanges
	config.SyscoinBlock = big.NewInt(0)
	contract := common.HexToAddress("0x7777")
	genesis := &Genesis{Config: &config, BaseFee: big.NewInt(params.InitialBaseFee), Alloc: types.GenesisAlloc{
		crypto.PubkeyToAddress(key.PublicKey): {Balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)},
		contract:                              {Code: []byte{byte(vm.PUSH1), 1, byte(vm.SYSBLOCKHASH), byte(vm.POP), byte(vm.STOP)}},
	}}
	engine := ethash.NewFaker()
	chain, err := NewBlockChain(db, DefaultCacheConfigWithScheme(rawdb.HashScheme), genesis, nil, engine, vm.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(chain.Stop)
	newTx := func(nonce uint64) *types.Transaction {
		return types.MustSignNewTx(key, types.LatestSigner(&config), &types.LegacyTx{
			Nonce: nonce, To: &contract, Gas: 50000, GasPrice: big.NewInt(params.InitialBaseFee),
		})
	}
	genDB, blocks, _ := GenerateChainWithGenesis(genesis, engine, 2, func(i int, b *BlockGen) {
		if i == 1 {
			b.AddTxWithChain(chain, newTx(0))
			b.AddTxWithChain(chain, newTx(1))
		}
	})
	defer genDB.Close()
	pairClassificationBlock(blocks[0])
	if _, err := chain.InsertChain(blocks[:1]); err != nil {
		t.Fatal(err)
	}
	db.captureKey = true
	rawdb.WriteSYSHash(db, blocks[0].NevmBlockConnect.Sysblockhash, 1)
	db.captureKey = false
	chain.hc.SYSHashCache.Purge()
	for _, mode := range []string{"valid", "read-failure", "read-before-transaction-failure"} {
		t.Run(mode, func(t *testing.T) {
			block := blocks[1]
			if mode == "read-before-transaction-failure" {
				txs := types.Transactions{newTx(0), newTx(2)}
				header := block.Header()
				header.TxHash = types.DeriveSha(txs, trie.NewStackTrie(nil))
				block = types.NewBlockWithHeader(header).WithBody(types.Body{Transactions: txs})
			}
			statedb, err := state.New(blocks[0].Root(), chain.statedb)
			if err != nil {
				t.Fatal(err)
			}
			localErr := errors.New("SYS execution lookup unavailable")
			if mode != "valid" {
				db.fault = localErr
			}
			result, err := chain.processor.Process(block, statedb, vm.Config{})
			db.fault = nil
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if err := chain.validator.ValidateState(block, statedb, result, false); err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, localErr) || !strings.Contains(err.Error(), "execution chain read") {
				t.Fatalf("execution collector did not preserve local failure: %v", err)
			}
			assertInvalidBlockClass(t, err, false)
		})
	}
}

func TestNEVMExecutionChainReadClassification(t *testing.T) {
	db := &classificationFaultDB{Database: rawdb.NewMemoryDatabase()}
	t.Cleanup(func() { db.Close() })
	chain, _, _ := classificationChain(t, db)
	address, hash := common.HexToAddress("0x1234"), common.HexToHash("0x2345")
	rawdb.WriteSYSHash(db, string(hash.Bytes()), 1)
	rawdb.StoreNEVMAddress(db, address, []byte{0, 0, 0, 1})
	rawdb.WriteBTCCheckpointIndexByHash(db, hash, 1)
	rawdb.WriteBTCCheckpointHashByIndex(db, 1, hash)
	rawdb.WriteBTCCheckpointLastIndex(db, 1)
	chain.hc.BTCCheckpointLastIndex.Store(1)
	for name, read := range map[string]func(*executionChainContext){
		"sys":       func(c *executionChainContext) { c.ReadSYSHash(1) },
		"address":   func(c *executionChainContext) { c.GetNEVMAddress(address) },
		"btc-index": func(c *executionChainContext) { c.BTCCheckpointIndex(hash) },
		"btc-last":  func(c *executionChainContext) { c.ReadBTCCheckpointLastIndex() },
		"btc-hash":  func(c *executionChainContext) { c.ReadBTCCheckpointHashByIndex(1) },
		"data-hash": func(c *executionChainContext) { c.ReadDataHash(hash) },
	} {
		t.Run(name, func(t *testing.T) {
			context := &executionChainContext{HeaderChain: chain.hc}
			read(context)
			if context.err != nil {
				t.Fatalf("ordinary metadata read: %v", context.err)
			}
			readErr := errors.New("local metadata read unavailable")
			db.fault = readErr
			context = &executionChainContext{HeaderChain: chain.hc}
			read(context)
			db.fault = nil
			if !errors.Is(context.err, readErr) {
				t.Fatalf("read error not preserved: %v", context.err)
			}
			assertInvalidBlockClass(t, context.err, false)
		})
	}
	context := &executionChainContext{HeaderChain: chain.hc}
	context.ReadSYSHash(0) // An unpaired genesis is legitimate.
	if context.err != nil {
		t.Fatal(context.err)
	}
	context.GetHeader(common.HexToHash("0xdead"), 1)
	if context.err == nil {
		t.Fatal("missing execution header was ignored")
	}
	assertInvalidBlockClass(t, context.err, false)
	context = &executionChainContext{HeaderChain: chain.hc}
	context.ReadSYSHash(2)
	if context.err == nil {
		t.Fatal("missing active Syscoin pair was ignored")
	}
}

type classificationStateDatabase struct {
	state.Database
	readErr, updateErr error
}

type classificationStateReader struct {
	state.Reader
	err error
}

func (r *classificationStateReader) Account(common.Address) (*types.StateAccount, error) {
	return nil, r.err
}

func (db *classificationStateDatabase) Reader(root common.Hash) (state.Reader, error) {
	reader, err := db.Database.Reader(root)
	if err == nil && db.readErr != nil {
		reader = &classificationStateReader{Reader: reader, err: db.readErr}
	}
	return reader, err
}

type classificationStateTrie struct {
	state.Trie
	err error
}

func (tr *classificationStateTrie) UpdateAccount(common.Address, *types.StateAccount, int) error {
	return tr.err
}

func (db *classificationStateDatabase) OpenTrie(root common.Hash) (state.Trie, error) {
	tr, err := db.Database.OpenTrie(root)
	if err == nil && db.updateErr != nil {
		tr = &classificationStateTrie{Trie: tr, err: db.updateErr}
	}
	return tr, err
}

func TestNEVMStateLocalErrorsOverrideInvalidity(t *testing.T) {
	for _, duringRoot := range []bool{false, true} {
		name := "read"
		if duringRoot {
			name = "intermediate-root"
		}
		t.Run(name, func(t *testing.T) {
			localErr := errors.New("local state unavailable")
			db := &classificationStateDatabase{Database: state.NewDatabaseForTesting()}
			if duringRoot {
				db.updateErr = localErr
			} else {
				db.readErr = localErr
			}
			statedb, err := state.New(types.EmptyRootHash, db)
			if err != nil {
				t.Fatal(err)
			}
			statedb.SetNonce(common.HexToAddress("0x1234"), 1, tracing.NonceChangeUnspecified)
			block := types.NewBlockWithHeader(&types.Header{
				Number: big.NewInt(1), Root: common.HexToHash("0x1234"),
				TxHash: types.EmptyTxsHash, UncleHash: types.EmptyUncleHash, ReceiptHash: types.EmptyReceiptsHash,
			})
			validator := &BlockValidator{config: params.AllEthashProtocolChanges}
			err = validator.ValidateState(block, statedb, &ProcessResult{}, false)
			if err == nil || !strings.Contains(err.Error(), localErr.Error()) {
				t.Fatalf("local state failure not propagated: %v", err)
			}
			assertInvalidBlockClass(t, err, false)
		})
	}
}

func TestNEVMTransactionErrorRequiresCommittedBody(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { db.Close() })
	chain, genesis, engine := classificationChain(t, db)
	genDB, blocks, _ := GenerateChainWithGenesis(genesis, engine, 1, nil)
	defer genDB.Close()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	tx := types.MustSignNewTx(key, types.LatestSigner(genesis.Config), &types.LegacyTx{
		Nonce: 1, To: &common.Address{}, Gas: 21000, GasPrice: big.NewInt(params.InitialBaseFee),
	})
	header := blocks[0].Header()
	header.TxHash = types.DeriveSha(types.Transactions{tx}, trie.NewStackTrie(nil))
	block := types.NewBlockWithHeader(header).WithBody(types.Body{Transactions: []*types.Transaction{tx}})
	for _, localFailure := range []bool{false, true} {
		stateDB := &classificationStateDatabase{Database: chain.statedb}
		localErr := errors.New("account state read unavailable")
		if localFailure {
			stateDB.readErr = localErr
		}
		statedb, err := state.New(genesis.ToBlock().Root(), stateDB)
		if err != nil {
			t.Fatal(err)
		}
		_, err = chain.processor.Process(block, statedb, vm.Config{})
		if err == nil {
			t.Fatal("expected transaction error")
		}
		assertInvalidBlockClass(t, err, !localFailure)
		if localFailure && !errors.Is(err, localErr) {
			t.Fatalf("local read error lost: %v", err)
		}
	}
	// The same transaction bytes attached to a different header commitment are
	// a replaceable payload error and must not receive the invalid-block marker.
	header.TxHash = types.EmptyTxsHash
	block = types.NewBlockWithHeader(header).WithBody(*block.Body())
	statedb, err := state.New(genesis.ToBlock().Root(), chain.statedb)
	if err != nil {
		t.Fatal(err)
	}
	_, err = chain.processor.Process(block, statedb, vm.Config{})
	if err == nil {
		t.Fatal("expected transaction error")
	}
	assertInvalidBlockClass(t, err, false)
}
