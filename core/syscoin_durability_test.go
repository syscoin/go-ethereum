// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/ethereum/go-ethereum/triedb/pathdb"
	"github.com/syscoin/syscoinwire/syscoin/wire"
)

// Ordinary writes and batches change the applied database. A simulated power
// loss preserves only the complete KV image captured by a successful fence.
// In particular, neither reading the current pair nor stopping the original
// chain can make its unsynced cancellation survive in a previously copied image.
type syscoinDurabilityDB struct {
	ethdb.Database
	mu         sync.Mutex
	durable    map[string][]byte
	syncErr    error
	journalErr error
	rootErr    error
	rootReads  int
	syncCalls  int
}

func (db *syscoinDurabilityDB) Get(key []byte) ([]byte, error) {
	if bytes.Equal(key, rawdb.TrieNodeAccountPrefix) {
		db.mu.Lock()
		db.rootReads++
		err := db.rootErr
		db.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	return db.Database.Get(key)
}

func (db *syscoinDurabilityDB) setRootError(err error) int {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.rootErr = err
	return db.rootReads
}

func (db *syscoinDurabilityDB) Put(key, value []byte) error {
	db.mu.Lock()
	err := db.journalErr
	db.mu.Unlock()
	if bytes.Equal(key, []byte("TrieJournal")) && err != nil {
		return err
	}
	return db.Database.Put(key, value)
}

func (db *syscoinDurabilityDB) SyncKeyValue() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.syncCalls++
	if db.syncErr != nil {
		return db.syncErr
	}
	durable := make(map[string][]byte)
	it := db.Database.NewIterator(nil, nil)
	defer it.Release()
	for it.Next() {
		durable[string(it.Key())] = bytes.Clone(it.Value())
	}
	if err := it.Error(); err != nil {
		return err
	}
	db.durable = durable
	return nil
}

func (db *syscoinDurabilityDB) setSyncError(err error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.syncErr = err
}

func (db *syscoinDurabilityDB) calls() int {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.syncCalls
}

func (db *syscoinDurabilityDB) setJournalError(err error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.journalErr = err
}

func (db *syscoinDurabilityDB) crashImage(t *testing.T) ethdb.Database {
	t.Helper()
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.durable == nil {
		t.Fatal("fixture has no durable database image")
	}
	copy := rawdb.NewMemoryDatabase()
	t.Cleanup(func() { copy.Close() })
	for key, value := range db.durable {
		if err := copy.Put([]byte(key), value); err != nil {
			t.Fatal(err)
		}
	}
	return copy
}

func disconnectSyscoinDurabilityChild(t *testing.T, f *syscoinRecoveryFixture) {
	t.Helper()
	// Block 3 added addr[0] and changed addr[1]'s height from 20 to 30.
	if err := f.chain.DisconnectSyscoinBlock(&types.NEVMBlockDisconnect{
		Sysblockhash: f.blocks[2].NevmBlockConnect.Sysblockhash,
		Diff: &wire.NEVMAddressDiff{
			RemovedMNNEVM: []wire.NEVMRemoveEntry{{Address: f.addr[0].Bytes()}},
			UpdatedMNNEVM: []wire.NEVMAddressUpdateEntry{{
				OldAddress: f.addr[1].Bytes(), NewAddress: f.addr[1].Bytes(), CollateralHeight: 20,
			}},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func checkSyscoinDurabilityParent(t *testing.T, f *syscoinRecoveryFixture, chain *BlockChain, db ethdb.Database) {
	t.Helper()
	parent, child := f.blocks[1], f.blocks[2]
	if chain.CurrentBlock().Hash() != parent.Hash() || chain.CurrentHeader().Hash() != parent.Hash() ||
		chain.CurrentSnapBlock().Hash() != parent.Hash() || rawdb.ReadHeadBlockHash(db) != parent.Hash() ||
		rawdb.ReadHeadHeaderHash(db) != parent.Hash() || rawdb.ReadHeadFastBlockHash(db) != parent.Hash() {
		t.Fatal("parent head markers disagree after cancellation")
	}
	if number, hash, ok := chain.CurrentSyscoinPair(); !ok || number != 2 || string(hash) != parent.NevmBlockConnect.Sysblockhash {
		t.Fatalf("parent pair = %d/%x/%t", number, hash, ok)
	}
	if chain.GetCanonicalHash(2) != parent.Hash() || chain.GetCanonicalHash(3) != (common.Hash{}) ||
		!bytes.Equal(rawdb.ReadSYSHash(db, 2), []byte(parent.NevmBlockConnect.Sysblockhash)) ||
		len(rawdb.ReadSYSHash(db, 3)) != 0 || len(chain.ReadSYSHash(3)) != 0 {
		t.Fatal("cancelled child retained canonical or Core pairing metadata")
	}
	for i, hash := range f.da {
		if (len(rawdb.ReadDataHash(db, hash)) != 0) != (i < 2) ||
			(len(chain.ReadDataHash(hash)) != 0) != (i < 2) {
			t.Fatalf("DA membership mismatch after cancellation for index %d", i)
		}
	}
	if rawdb.ReadBTCCheckpointLastIndex(db) != 1 || chain.ReadBTCCheckpointLastIndex() != 1 ||
		rawdb.ReadBTCCheckpointIndexByHash(db, f.btc[1]) != 0 || chain.BTCCheckpointIndex(f.btc[1]) != 0 ||
		rawdb.ReadBTCCheckpointIndexByBlockNumber(db, 3) != 0 ||
		rawdb.ReadTxLookupEntry(db, child.Transactions()[0].Hash()) != nil {
		t.Fatal("cancelled child retained BTC checkpoint or transaction metadata")
	}
	for i, address := range f.addr {
		var want []byte
		if i == 1 {
			want = make([]byte, 4)
			binary.BigEndian.PutUint32(want, 20)
		}
		if !bytes.Equal(chain.GetNEVMAddress(address), want) || !bytes.Equal(rawdb.GetNEVMAddress(db, address), want) {
			t.Fatalf("address inverse did not survive cancellation for %s", address)
		}
	}
	state, err := chain.StateAt(parent.Root())
	if err != nil {
		t.Fatalf("parent EVM state is not readable: %v", err)
	}
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatal(err)
	}
	if nonce := state.GetNonce(crypto.PubkeyToAddress(key.PublicKey)); nonce != 2 {
		t.Fatalf("parent state has transaction nonce %d, want 2", nonce)
	}
	if err := state.Error(); err != nil {
		t.Fatalf("parent EVM state lookup failed: %v", err)
	}
	if rawdb.ReadBlock(db, child.Hash(), 3) == nil || len(rawdb.ReadRawReceipts(db, child.Hash(), 3)) != 1 {
		t.Fatal("cancellation removed the retained child body or receipts")
	}
}

func reopenSyscoinDurabilityChain(t *testing.T, f *syscoinRecoveryFixture, db ethdb.Database) *BlockChain {
	t.Helper()
	chain, err := NewBlockChain(db, f.cache, f.genesis, nil, ethash.NewFaker(), vm.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(chain.Stop)
	return chain
}

func TestSyscoinPairDurabilityAcrossPowerLoss(t *testing.T) {
	for _, scheme := range []string{rawdb.HashScheme, rawdb.PathScheme} {
		t.Run(scheme, func(t *testing.T) {
			db := &syscoinDurabilityDB{Database: rawdb.NewMemoryDatabase()}
			t.Cleanup(func() { db.Close() })
			f := newSyscoinRecoveryFixture(t, scheme, false, db)
			childPair := []byte(f.blocks[2].NevmBlockConnect.Sysblockhash)
			parentPair := []byte(f.blocks[1].NevmBlockConnect.Sysblockhash)
			if err := f.chain.SyncSyscoinPair(3, childPair); err != nil {
				t.Fatal(err)
			}
			if db.calls() != 1 {
				t.Fatal("initial child fence did not reach hot KV storage")
			}
			disconnectSyscoinDurabilityChild(t, f)
			checkSyscoinDurabilityParent(t, f, f.chain, db)

			// Applied P is insufficient: until the fence succeeds, the caller
			// must keep its cancellation obligation. A real storage restart can
			// still restore C, including its address/DA/BTC/transaction metadata.
			failure := errors.New("injected hot KV sync failure")
			db.setSyncError(failure)
			if err := f.chain.SyncSyscoinPair(2, parentPair); !errors.Is(err, failure) {
				t.Fatalf("failed parent fence = %v", err)
			}
			checkSyscoinDurabilityParent(t, f, f.chain, db)
			failedImage := db.crashImage(t)
			restartedAtChild := reopenSyscoinDurabilityChain(t, f, failedImage)
			f.check(t, restartedAtChild, failedImage, 3)
			if !restartedAtChild.HasState(f.blocks[2].Root()) {
				t.Fatal("durable child lost its trie state")
			}

			// Retry after an ambiguous reply must fence the already-applied P;
			// it must not require or repeat the C disconnect.
			db.setSyncError(nil)
			if err := f.chain.SyncSyscoinPair(2, parentPair); err != nil {
				t.Fatal(err)
			}
			if db.calls() != 3 {
				t.Fatal("already-parent retry skipped the storage fence")
			}
			successImage := db.crashImage(t)
			restartedAtParent := reopenSyscoinDurabilityChain(t, f, successImage)
			checkSyscoinDurabilityParent(t, f, restartedAtParent, successImage)

			// A recovery checkpoint must leave the live trie writable. Reapply
			// the authentic child and then fence/reopen that new exact endpoint.
			if _, err := f.chain.InsertChain(types.Blocks{f.blocks[2]}); err != nil {
				t.Fatalf("connection after recovery checkpoint: %v", err)
			}
			if err := f.chain.SyncSyscoinPair(3, childPair); err != nil {
				t.Fatal(err)
			}
			reappliedImage := db.crashImage(t)
			f.check(t, reopenSyscoinDurabilityChain(t, f, reappliedImage), reappliedImage, 3)
		})
	}
}

func TestSyscoinPairDurabilityRequiresExactEndpoint(t *testing.T) {
	for _, scheme := range []string{rawdb.HashScheme, rawdb.PathScheme} {
		t.Run(scheme, func(t *testing.T) {
			db := &syscoinDurabilityDB{Database: rawdb.NewMemoryDatabase()}
			t.Cleanup(func() { db.Close() })
			f := newSyscoinRecoveryFixture(t, scheme, false, db)
			childPair := []byte(f.blocks[2].NevmBlockConnect.Sysblockhash)
			for _, wrong := range []struct {
				name   string
				number uint64
				hash   []byte
			}{
				{"parent count with child hash", 2, childPair},
				{"child count with parent hash", 3, []byte(f.blocks[1].NevmBlockConnect.Sysblockhash)},
				{"foreign hash", 3, bytes.Repeat([]byte{0xf1}, common.HashLength)},
				{"short hash", 3, childPair[:common.HashLength-1]},
			} {
				t.Run(wrong.name, func(t *testing.T) {
					if err := f.chain.SyncSyscoinPair(wrong.number, wrong.hash); err == nil {
						t.Fatal("wrong endpoint obtained a durability acknowledgement")
					}
					if db.calls() != 0 {
						t.Fatal("wrong endpoint reached storage sync")
					}
					f.check(t, f.chain, db, 3)
				})
			}
		})
	}
}

func TestSyscoinPairDurabilityPathCheckpointFailure(t *testing.T) {
	db := &syscoinDurabilityDB{Database: rawdb.NewMemoryDatabase()}
	t.Cleanup(func() { db.Close() })
	f := newSyscoinRecoveryFixture(t, rawdb.PathScheme, false, db)
	if err := f.chain.SyncSyscoinPair(3, []byte(f.blocks[2].NevmBlockConnect.Sysblockhash)); err != nil {
		t.Fatal(err)
	}
	disconnectSyscoinDurabilityChild(t, f)
	failure := errors.New("injected trie journal write failure")
	db.setJournalError(failure)
	defer db.setJournalError(nil)
	if err := f.chain.SyncSyscoinPair(2, []byte(f.blocks[1].NevmBlockConnect.Sysblockhash)); !errors.Is(err, failure) {
		t.Fatalf("failed parent trie checkpoint = %v", err)
	}
	if db.calls() != 1 {
		t.Fatal("failed trie checkpoint proceeded to a hot KV durability fence")
	}
	checkSyscoinDurabilityParent(t, f, f.chain, db)
	failedImage := db.crashImage(t)
	f.check(t, reopenSyscoinDurabilityChain(t, f, failedImage), failedImage, 3)
	db.setJournalError(nil)
	if err := f.chain.SyncSyscoinPair(2, []byte(f.blocks[1].NevmBlockConnect.Sysblockhash)); err != nil {
		t.Fatal(err)
	}
	successImage := db.crashImage(t)
	checkSyscoinDurabilityParent(t, f, reopenSyscoinDurabilityChain(t, f, successImage), successImage)
}

// A physical-root read failure must not turn the nonempty disk base B into
// an empty-base journal while the selected endpoint P lives in recent layers.
func TestSyscoinPairDurabilityPathCheckpointRootReadFailure(t *testing.T) {
	db := &syscoinDurabilityDB{Database: rawdb.NewMemoryDatabase()}
	t.Cleanup(func() { db.Close() })
	f := newSyscoinRecoveryFixture(t, rawdb.PathScheme, false, db)
	base, parent, child := f.blocks[0], f.blocks[1], f.blocks[2]
	physical, err := db.Database.Get(rawdb.TrieNodeAccountPrefix)
	if err != nil || len(physical) == 0 || crypto.Keccak256Hash(physical) != base.Root() {
		t.Fatalf("fixture physical base is not committed block B: bytes=%d err=%v", len(physical), err)
	}
	if base.Root() == types.EmptyRootHash || base.Root() == parent.Root() {
		t.Fatal("fixture needs distinct nonempty physical B and recent endpoint P")
	}
	diffs, _, _ := f.chain.TrieDB().Size()
	if diffs == 0 {
		t.Fatal("fixture endpoint has no recent diff state")
	}
	if db.calls() != 0 {
		t.Fatal("healthy forward imports added a hot KV sync")
	}
	if err := f.chain.SyncSyscoinPair(3, []byte(child.NevmBlockConnect.Sysblockhash)); err != nil {
		t.Fatal(err)
	}
	priorJournal := rawdb.ReadTrieJournal(db)
	if len(priorJournal) == 0 || db.calls() != 1 {
		t.Fatal("initial child fence did not establish a usable durable checkpoint")
	}
	priorImage := db.crashImage(t)
	f.check(t, reopenSyscoinDurabilityChain(t, f, priorImage), priorImage, 3)
	disconnectSyscoinDurabilityChild(t, f)
	checkSyscoinDurabilityParent(t, f, f.chain, db)
	if !bytes.Equal(rawdb.ReadAccountTrieNode(db, nil), physical) {
		t.Fatal("ordinary child disconnect changed the physical base B")
	}
	if db.calls() != 1 {
		t.Fatal("ordinary disconnect added a hot KV sync")
	}
	failure := errors.New("injected physical account-root read failure")
	reads := db.setRootError(failure)
	defer db.setRootError(nil)
	// The endpoint is available from real recent layers. This earlier success
	// must not authorize a later unreadable physical base during Checkpoint.
	if !f.chain.HasState(parent.Root()) {
		t.Fatal("parent state was unavailable before checkpoint construction")
	}
	if got := db.setRootError(failure); got != reads {
		t.Fatal("HasState consumed the physical-root fault before checkpoint")
	}
	if err := f.chain.SyncSyscoinPair(2, []byte(parent.NevmBlockConnect.Sysblockhash)); !errors.Is(err, failure) {
		t.Errorf("unreadable physical base obtained durability result %v; want injected error", err)
	}
	if got := db.setRootError(nil); got != reads+1 {
		t.Errorf("physical root reads during checkpoint = %d, want 1", got-reads)
	}
	if db.calls() != 1 {
		t.Errorf("failed physical-root read reached hot KV sync: calls=%d, want 1", db.calls())
	}
	if !bytes.Equal(rawdb.ReadTrieJournal(db), priorJournal) {
		t.Error("failed checkpoint replaced the prior usable trie journal")
	}
	failedImage := db.crashImage(t)
	if !bytes.Equal(rawdb.ReadTrieJournal(failedImage), priorJournal) || rawdb.ReadHeadBlockHash(failedImage) != child.Hash() {
		t.Error("failed checkpoint changed the previously durable child image")
	}
	// Inspect the actual cold trie loader before blockchain repair/rewind can
	// hide an unusable journal. The prior C journal also contains P's layer.
	coldTrie := triedb.NewDatabase(failedImage, &triedb.Config{PathDB: pathdb.Defaults})
	if _, err := coldTrie.NodeReader(parent.Root()); err != nil {
		t.Errorf("previously available P state lost on cold trie reopen: %v", err)
	}
	if err := coldTrie.Close(); err != nil {
		t.Fatal(err)
	}
	checkSyscoinDurabilityParent(t, f, f.chain, db)

	// A transient read failure must leave P retryable and the original live
	// trie writable. Copy the fenced image before any clean Stop can mask it.
	beforeRetry := db.calls()
	if err := f.chain.SyncSyscoinPair(2, []byte(parent.NevmBlockConnect.Sysblockhash)); err != nil {
		t.Fatal(err)
	}
	if db.calls() != beforeRetry+1 {
		t.Fatal("successful checkpoint retry did not reach exactly one hot KV sync")
	}
	successImage := db.crashImage(t)
	checkSyscoinDurabilityParent(t, f, reopenSyscoinDurabilityChain(t, f, successImage), successImage)
	if _, err := f.chain.InsertChain(types.Blocks{child}); err != nil {
		t.Fatalf("live trie was not writable after checkpoint retry: %v", err)
	}
	if db.calls() != beforeRetry+1 {
		t.Fatal("healthy child reapplication added a hot KV sync")
	}
}
