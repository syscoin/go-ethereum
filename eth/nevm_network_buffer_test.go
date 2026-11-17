// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package eth

import (
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/syscoin/syscoinwire/syscoin/wire"
)

func newNEVMNetworkBufferEthereum(t *testing.T, gate *nevmDiscoveryStartupGate) (*Ethereum, *node.Node, *event.TypeMuxSubscription, []*types.NEVMBlockConnect) {
	t.Helper()
	p2pConfig := p2p.Config{ListenAddr: "127.0.0.1:0", DiscAddr: "127.0.0.1:0", DiscoveryV5: true, MaxPeers: 4}
	// SYSCOIN: imports establish a durable baseline, including in this fixture.
	stack, err := node.New(&node.Config{DataDir: t.TempDir(), P2P: p2pConfig})
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatal(err)
	}
	contract := common.HexToAddress("0x7777")
	chainConfig := *params.AllEthashProtocolChanges
	chainConfig.SyscoinBlock = big.NewInt(0)
	genesis := &core.Genesis{Config: &chainConfig, GasLimit: 30_000_000,
		BaseFee: big.NewInt(params.InitialBaseFee), Alloc: make(types.GenesisAlloc)}
	genesis.Alloc[crypto.PubkeyToAddress(key.PublicKey)] = types.Account{Balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)}
	genesis.Alloc[contract] = types.Account{Code: common.FromHex("0x60006000a000"), Balance: new(big.Int)} // LOG0, STOP.
	config := ethconfig.Defaults
	config.Genesis, config.SyncMode = genesis, ethconfig.FullSync
	config.TrieCleanCache, config.TrieDirtyCache, config.SnapshotCache = 16, 16, 0
	config.TxPool.Journal, config.BlobPool.Datadir = "", ""
	config.TxPool.NoLocals, config.LogNoHistory = true, true
	config.EthDiscoveryURLs, config.SnapDiscoveryURLs = nil, nil
	config.NEVMPubEP = "tcp://127.0.0.1:0"
	done := stack.EventMux().Subscribe(downloader.DoneEvent{})
	eth, err := New(stack, &config)
	if err != nil {
		done.Unsubscribe()
		stack.Close()
		t.Fatal(err)
	}
	if gate != nil {
		eth.p2pServer.Logger = log.NewLogger(gate)
	}
	t.Cleanup(func() { stack.Close(); done.Unsubscribe() })
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}
	genDB, blocks, _ := core.GenerateChainWithGenesis(genesis, eth.engine, 3, func(i int, b *core.BlockGen) {
		b.SetDifficulty(big.NewInt(1)) // Syscoin's beacon verifier requires difficulty one.
		b.AddTx(types.MustSignNewTx(key, b.Signer(), &types.LegacyTx{
			Nonce: uint64(i), To: &contract, Gas: 100_000, GasPrice: big.NewInt(params.InitialBaseFee),
		}))
	})
	t.Cleanup(func() { genDB.Close() })
	pairs := make([]*types.NEVMBlockConnect, len(blocks))
	for i, block := range blocks {
		pairs[i] = makeNEVMConnect(block, common.BytesToHash([]byte{0x55, byte(i + 1)}).Bytes())
	}
	data := common.HexToHash("0x1111")
	pairs[0].VersionHashes = []*common.Hash{&data}
	pairs[0].BTCPrevHash = common.HexToHash("0x2222")
	pairs[0].Diff.AddedMNNEVM = []wire.NEVMAddressEntry{{Address: common.HexToAddress("0x3333").Bytes(), CollateralHeight: 12}}
	return eth, stack, done, pairs
}

func TestNEVMNetworkBufferFixtureImportsWithExplicitFlush(t *testing.T) {
	eth, _, _, pairs := newNEVMNetworkBufferEthereum(t, nil)
	reply := nevmConnectTestReply(t, eth)
	if got := reply("nevmconnect", nevmConnectTestPayload(t, pairs[0])); got != "connected" {
		t.Fatalf("fixture pair admission: %q", got)
	}
	if got := reply("nevmcomms", []byte("\x05flush")); got != "flushed" {
		t.Fatalf("fixture explicit flush: %q", got)
	}
	checkNEVMNetworkBufferCommitted(t, eth, pairs[0])
}

func startNEVMBufferedNetwork(t *testing.T, eth *Ethereum) {
	t.Helper()
	if reply := eth.zmqRep.handleNEVMComms("\fstartnetwork"); reply != "ack" {
		t.Fatalf("startnetwork reply: %q", reply)
	}
	eth.lock.Lock()
	eth.timeLastBlock = time.Now().Add(-6 * time.Second).Unix()
	eth.lock.Unlock()
}

func checkNEVMNetworkBufferCommitted(t *testing.T, eth *Ethereum, pair *types.NEVMBlockConnect) {
	t.Helper()
	block := pair.Block
	count, sysHash, ok := eth.zmqRep.currentNEVMBlockInfo()
	if !ok || count != block.NumberU64() || sysHash != encodeSyscoinDisplayHash([]byte(pair.Sysblockhash)) ||
		eth.blockchain.CurrentBlock().Hash() != block.Hash() {
		t.Fatalf("network activation left the acknowledged pair unapplied: height=%d want=%d", count, block.NumberU64())
	}
	if got := eth.blockchain.ReadSYSHash(block.NumberU64()); string(got) != pair.Sysblockhash {
		t.Fatal("activated pair has no matching SYS metadata")
	}
	receipts := eth.blockchain.GetReceiptsByHash(block.Hash())
	if len(receipts) != 1 || len(receipts[0].Logs) != 1 || receipts[0].Status != types.ReceiptStatusSuccessful ||
		receipts[0].Logs[0].Address != common.HexToAddress("0x7777") {
		t.Fatal("activated pair is missing its executed LOG receipt")
	}
	if len(eth.blockchain.ReadDataHash(common.HexToHash("0x1111"))) == 0 ||
		eth.blockchain.BTCCheckpointIndex(common.HexToHash("0x2222")) != 1 ||
		len(eth.blockchain.GetNEVMAddress(common.HexToAddress("0x3333"))) == 0 {
		t.Fatal("activated pair is missing its paired metadata")
	}
	eth.bufferLock.Lock()
	remaining := len(eth.blockConnectBuffer)
	eth.bufferLock.Unlock()
	if remaining != 0 {
		t.Fatalf("activation left %d acknowledged pairs buffered", remaining)
	}
}

func TestNEVMNetworkActivationDrainsPartialBuffer(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		name := "settled_tail"
		if concurrent {
			name = "arrival_during_startup"
		}
		t.Run(name, func(t *testing.T) {
			var gate *nevmDiscoveryStartupGate
			if concurrent {
				gate = &nevmDiscoveryStartupGate{entered: make(chan struct{}), release: make(chan struct{})}
			}
			eth, _, done, pairs := newNEVMNetworkBufferEthereum(t, gate)
			reply := nevmConnectTestReply(t, eth)
			if got := reply("nevmconnect", nevmConnectTestPayload(t, pairs[0])); got != "connected" {
				t.Fatalf("partial pair admission: %q", got)
			}
			if eth.blockchain.CurrentBlock().Number.Uint64() != 0 || len(eth.blockConnectBuffer) != 1 {
				t.Fatal("fixture did not retain an acknowledged partial batch")
			}
			startNEVMBufferedNetwork(t, eth)
			last := 0
			if concurrent {
				select {
				case <-gate.entered:
				case <-time.After(5 * time.Second):
					t.Fatal("network worker did not reach startup gate")
				}
				if got := reply("nevmconnect", nevmConnectTestPayload(t, pairs[1])); got != "connected" {
					close(gate.release)
					t.Fatalf("pair arriving during startup: %q", got)
				}
				last = 1
				close(gate.release)
			}
			select {
			case ev := <-done.Chan():
				if ev == nil {
					t.Fatal("network activation failed")
				}
			case <-time.After(8 * time.Second):
				t.Fatal("network activation did not complete")
			}
			checkNEVMNetworkBufferCommitted(t, eth, pairs[last])
			waitNEVMDiscoveryWorker(t, eth)
			// The following live admission must commit immediately, even though it
			// is another batch smaller than the normal threshold.
			if got := reply("nevmconnect", nevmConnectTestPayload(t, pairs[last+1])); got != "connected" {
				t.Fatalf("live pair admission: %q", got)
			}
			checkNEVMNetworkBufferCommitted(t, eth, pairs[last+1])
		})
	}
}

func TestNEVMNetworkActivationRejectsInvalidBufferedTail(t *testing.T) {
	eth, stack, done, pairs := newNEVMNetworkBufferEthereum(t, nil)
	reply := nevmConnectTestReply(t, eth)
	header := pairs[0].Block.Header()
	header.Root = common.HexToHash("0xdeadbeef")
	pairs[0].Block = pairs[0].Block.WithSeal(header)
	if got := reply("nevmconnect", nevmConnectTestPayload(t, pairs[0])); got != "connected" {
		t.Fatalf("invalid tail was not buffered by ordinary admission: %q", got)
	}
	startNEVMBufferedNetwork(t, eth)
	assertNEVMDiscoveryNotAuthorized(t, eth, done)
	stopped := make(chan struct{})
	go func() { stack.Wait(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(8 * time.Second):
		t.Fatal("invalid buffered tail did not stop activation")
	}
}

func TestNEVMNetworkActivationCancelsWithBufferedTail(t *testing.T) {
	eth, stack, done, pairs := newNEVMNetworkBufferEthereum(t, nil)
	reply := nevmConnectTestReply(t, eth)
	if got := reply("nevmconnect", nevmConnectTestPayload(t, pairs[0])); got != "connected" {
		t.Fatalf("partial pair admission: %q", got)
	}
	eth.lock.Lock()
	eth.timeLastBlock = time.Now().Add(time.Hour).Unix()
	eth.lock.Unlock()
	if got := eth.zmqRep.handleNEVMComms("\fstartnetwork"); got != "ack" {
		t.Fatalf("startnetwork reply: %q", got)
	}
	if len(eth.blockConnectBuffer) != 1 {
		t.Fatal("cancellation fixture has no buffered tail")
	}
	closeNEVMDiscoveryStack(t, stack)
	assertNEVMDiscoveryNotAuthorized(t, eth, done)
}

func TestNEVMNetworkActivationSerializesAdmissionDuringDrain(t *testing.T) {
	eth, _, done, pairs := newNEVMNetworkBufferEthereum(t, nil)
	reply := nevmConnectTestReply(t, eth)
	if got := reply("nevmconnect", nevmConnectTestPayload(t, pairs[0])); got != "connected" {
		t.Fatalf("partial pair admission: %q", got)
	}
	// InsertChain updates its atomic head before publishing this event. Leaving
	// the event unconsumed keeps the real activation drain inside InsertChain.
	events := make(chan core.ChainEvent)
	sub := eth.blockchain.SubscribeChainEvent(events)
	defer sub.Unsubscribe()
	startNEVMBufferedNetwork(t, eth)
	deadline := time.After(8 * time.Second)
	for eth.blockchain.CurrentBlock().Hash() != pairs[0].Block.Hash() {
		select {
		case <-deadline:
			t.Fatal("activation did not begin importing the partial buffer")
		case <-time.After(time.Millisecond):
		}
	}
	started := make(chan struct{})
	admitted := make(chan error, 1)
	go func() {
		close(started)
		admitted <- eth.AddBlock(pairs[1])
	}()
	<-started
	select {
	case err := <-admitted:
		t.Fatalf("concurrent admission escaped an unfinished activation drain: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	select {
	case event := <-events:
		if event.Header.Hash() != pairs[0].Block.Hash() {
			t.Fatal("unexpected activation import event")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("activation import did not reach its publication boundary")
	}
	sub.Unsubscribe()
	select {
	case ev := <-done.Chan():
		if ev == nil {
			t.Fatal("activation failed during concurrent admission")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("activation did not finish after drain publication")
	}
	select {
	case err := <-admitted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent admission did not finish after activation")
	}
	waitNEVMDiscoveryWorker(t, eth)
	checkNEVMNetworkBufferCommitted(t, eth, pairs[1])
}
