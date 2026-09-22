// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package eth

import (
	"context"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/go-zeromq/zmq4"
)

// Use the registered JSON-RPC APIs and a real persistent chain so reopening the
// node cannot be mistaken for retaining a test-owned finality cache.
func newNEVMFinalityEthereum(t *testing.T, datadir string, syscoin bool) (*Ethereum, *node.Node, *rpc.Client, *core.Genesis) {
	t.Helper()
	stack, err := node.New(&node.Config{Name: "finality-test", DataDir: datadir, DBEngine: "leveldb",
		P2P: p2p.Config{NoDiscovery: true, MaxPeers: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stack.Close() })
	chainConfig := *params.AllEthashProtocolChanges
	if syscoin {
		chainConfig.SyscoinBlock = big.NewInt(0)
	}
	genesis := &core.Genesis{Config: &chainConfig, GasLimit: 30_000_000, BaseFee: big.NewInt(params.InitialBaseFee)}
	config := ethconfig.Defaults
	config.Genesis, config.SyncMode = genesis, ethconfig.FullSync
	config.TrieCleanCache, config.TrieDirtyCache, config.SnapshotCache = 16, 16, 0
	config.TxPool.Journal, config.BlobPool.Datadir = "", ""
	config.TxPool.NoLocals, config.LogNoHistory = true, true
	config.EthDiscoveryURLs, config.SnapDiscoveryURLs = nil, nil
	config.NEVMPubEP = "tcp://127.0.0.1:0"
	eth, err := New(stack, &config)
	if err != nil {
		t.Fatal(err)
	}
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}
	client := stack.Attach()
	t.Cleanup(client.Close)
	return eth, stack, client, genesis
}

func checkNEVMFinalityBlockRPC(t *testing.T, client *rpc.Client, selector string, want *types.Block) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var result *struct {
		Hash   common.Hash
		Number hexutil.Uint64
	}
	if err := client.CallContext(ctx, &result, "eth_getBlockByNumber", selector, false); err != nil {
		t.Fatalf("get block %s: %v", selector, err)
	}
	if result == nil || result.Hash != want.Hash() || uint64(result.Number) != want.NumberU64() {
		t.Fatalf("get block %s: got %+v, want %d/%s", selector, result, want.NumberU64(), want.Hash())
	}
}

func checkNEVMFinalityUnavailable(t *testing.T, client *rpc.Client) {
	t.Helper()
	for _, selector := range []string{"safe", "finalized"} {
		for _, method := range []string{"eth_getBlockByNumber", "eth_getBalance"} {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			var result interface{}
			var err error
			if method == "eth_getBlockByNumber" {
				err = client.CallContext(ctx, &result, method, selector, false)
			} else {
				err = client.CallContext(ctx, &result, method, common.Address{}, selector)
			}
			cancel()
			if err == nil || err.Error() != selector+" block not found" || result != nil {
				t.Errorf("%s(%s) claimed unsupported finality: result type=%T err=%v", method, selector, result, err)
			}
		}
	}
}

func checkNEVMFinalityHeads(t *testing.T, client *rpc.Client, finalized, safe *types.Block) {
	t.Helper()
	for selector, block := range map[string]*types.Block{"finalized": finalized, "safe": safe} {
		checkNEVMFinalityBlockRPC(t, client, selector, block)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		var tagged, numbered hexutil.Big
		err := client.CallContext(ctx, &tagged, "eth_getBalance", common.Address{}, selector)
		if err == nil {
			err = client.CallContext(ctx, &numbered, "eth_getBalance", common.Address{}, hexutil.EncodeUint64(block.NumberU64()))
		}
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if (*big.Int)(&tagged).Cmp((*big.Int)(&numbered)) != 0 {
			t.Fatalf("%s state did not resolve the explicit head", selector)
		}
	}
}

func nevmFinalityCommand(number uint64, sysHash []byte) string {
	// Core displays its serialized uint256 in the opposite byte order.
	display := append([]byte(nil), sysHash...)
	for i, j := 0, len(display)-1; i < j; i, j = i+1, j-1 {
		display[i], display[j] = display[j], display[i]
	}
	return fmt.Sprintf("finality-v1:%d:%x", number, display)
}

func nevmFinalityRequest(t *testing.T, client zmq4.Socket, payload []byte, want string) {
	t.Helper()
	sendNEVMListenerRequest(t, client, "nevmcomms", string(payload))
	reply, err := client.Recv()
	if err != nil || len(reply.Frames) != 2 || string(reply.Frames[0]) != "nevmcomms" || string(reply.Frames[1]) != want {
		t.Fatalf("finality response: %q err=%v, want %q", reply.Frames, err, want)
	}
}

func TestNEVMFinalityRPCFollowsExecutedCorePair(t *testing.T) {
	datadir := t.TempDir()
	eth, stack, client, genesis := newNEVMFinalityEthereum(t, datadir, true)
	transport := nevmListenerClient(t, eth.zmqRep)
	genDB, blocks, _ := core.GenerateChainWithGenesis(genesis, eth.engine, 20, func(_ int, b *core.BlockGen) {
		b.SetDifficulty(big.NewInt(1))
	})
	t.Cleanup(func() { genDB.Close() })
	sysHash := func(number uint64) []byte { return common.BigToHash(new(big.Int).SetUint64(number)).Bytes() }
	announce := func(number uint64, hash []byte, accepted bool) {
		text := nevmFinalityCommand(number, hash)
		want := "finality-error"
		if accepted {
			want = text
		}
		nevmFinalityRequest(t, transport, append([]byte{byte(len(text))}, text...), want)
	}
	admit := func(first, end int) {
		for _, block := range blocks[first:end] {
			if err := eth.AddBlock(makeNEVMConnect(block, sysHash(block.NumberU64()))); err != nil {
				t.Fatal(err)
			}
		}
	}
	flush := func() {
		if err := eth.flushBufferedBlocks(); err != nil {
			t.Fatal(err)
		}
	}
	admit(0, 15)
	flush()
	checkNEVMFinalityBlockRPC(t, client, "latest", blocks[14])
	checkNEVMFinalityUnavailable(t, client)
	admit(15, 16) // Buffered acknowledgement is not proof of applied execution.
	announce(16, sysHash(16), false)
	announce(21, sysHash(21), false)
	announce(5, sysHash(6), false)
	checkNEVMFinalityBlockRPC(t, client, "latest", blocks[14])
	if len(eth.blockConnectBuffer) != 1 {
		t.Fatal("finality request flushed the pending execution buffer")
	}
	announce(5, sysHash(5), true)
	announce(5, sysHash(5), true) // Lost acknowledgements can be retried exactly.
	checkNEVMFinalityHeads(t, client, blocks[4], blocks[4])
	announce(4, sysHash(4), false)
	announce(5, sysHash(99), false)
	valid := nevmFinalityCommand(5, sysHash(5))
	for _, malformed := range []string{
		"finality-v1:05:" + valid[len("finality-v1:5:"):],
		"finality-v1:-1:" + valid[len("finality-v1:5:"):],
		"finality-v1:18446744073709551616:" + valid[len("finality-v1:5:"):],
		valid + ":extra", valid[:len(valid)-1],
	} {
		nevmFinalityRequest(t, transport, append([]byte{byte(len(malformed))}, malformed...), "finality-error")
	}
	nevmFinalityRequest(t, transport, append([]byte{byte(len(valid) - 1)}, valid...), "finality-error")
	checkNEVMFinalityHeads(t, client, blocks[4], blocks[4])
	flush()
	admit(16, 20)
	flush()
	checkNEVMFinalityBlockRPC(t, client, "latest", blocks[19])
	checkNEVMFinalityHeads(t, client, blocks[4], blocks[4]) // Outage: no new Core boundary.
	announce(10, sysHash(10), true)
	// Keep the ordinary persisted marker below the rollback range: the freezer
	// legitimately treats that separate Ethereum marker as an ancient limit.
	eth.blockchain.SetFinalized(blocks[1].Header())
	eth.blockchain.SetSafe(blocks[19].Header())
	checkNEVMFinalityHeads(t, client, blocks[9], blocks[9])
	for number := uint64(20); number > 10; number-- {
		if err := eth.DeleteBlock(makeNEVMDisconnect(sysHash(number))); err != nil {
			t.Fatal(err)
		}
	}
	checkNEVMFinalityHeads(t, client, blocks[9], blocks[9])
	if err := eth.DeleteBlock(makeNEVMDisconnect(sysHash(10))); err != nil {
		t.Fatal(err)
	}
	checkNEVMFinalityUnavailable(t, client)
	if err := eth.AddBlock(makeNEVMConnect(blocks[9], sysHash(99))); err != nil {
		t.Fatal(err)
	}
	flush()
	announce(10, sysHash(10), false) // Same NEVM block, different active Core pair.
	checkNEVMFinalityUnavailable(t, client)
	announce(10, sysHash(99), true)
	checkNEVMFinalityHeads(t, client, blocks[9], blocks[9])
	if err := stack.Close(); err != nil {
		t.Fatal(err)
	}
	eth, _, client, _ = newNEVMFinalityEthereum(t, datadir, true)
	transport = nevmListenerClient(t, eth.zmqRep)
	checkNEVMFinalityBlockRPC(t, client, "latest", blocks[9])
	checkNEVMFinalityUnavailable(t, client)
	announce(10, sysHash(10), false)
	announce(10, sysHash(99), true) // Re-establish authority from Core after restart.
	checkNEVMFinalityHeads(t, client, blocks[9], blocks[9])
}

func TestNEVMFinalityRPCDoesNotInferAuthorityFromBlockAge(t *testing.T) {
	datadir := t.TempDir()
	eth, stack, client, genesis := newNEVMFinalityEthereum(t, datadir, true)
	genDB, blocks, _ := core.GenerateChainWithGenesis(genesis, eth.engine, 20, func(_ int, b *core.BlockGen) {
		b.SetDifficulty(big.NewInt(1))
	})
	t.Cleanup(func() { genDB.Close() })
	previous := 0
	for _, height := range []int{0, 5, 15, 20} {
		for _, block := range blocks[previous:height] {
			sysHash := common.BigToHash(block.Number()).Bytes()
			if err := eth.AddBlock(makeNEVMConnect(block, sysHash)); err != nil {
				t.Fatalf("admit paired block %d: %v", block.NumberU64(), err)
			}
		}
		if err := eth.flushBufferedBlocks(); err != nil {
			t.Fatalf("apply paired blocks through %d: %v", height, err)
		}
		want := genesis.ToBlock()
		if height > 0 {
			want = blocks[height-1]
		}
		checkNEVMFinalityBlockRPC(t, client, "latest", want)
		checkNEVMFinalityBlockRPC(t, client, hexutil.EncodeUint64(uint64(height)), want)
		t.Run("head_"+hexutil.EncodeUint64(uint64(height)), func(t *testing.T) {
			checkNEVMFinalityUnavailable(t, client)
		})
		previous = height
	}
	// Generic engine setters are not authenticated Core finality. In particular,
	// reopening their persisted hash must not create a trusted Syscoin boundary.
	eth.blockchain.SetFinalized(blocks[4].Header())
	eth.blockchain.SetSafe(blocks[9].Header())
	t.Run("unproven_engine_fields", func(t *testing.T) { checkNEVMFinalityUnavailable(t, client) })
	if err := stack.Close(); err != nil {
		t.Fatal(err)
	}
	eth, _, client, _ = newNEVMFinalityEthereum(t, datadir, true)
	checkNEVMFinalityBlockRPC(t, client, "latest", blocks[19])
	if height, hash, ok := eth.blockchain.CurrentSyscoinPair(); !ok || height != 20 || string(hash) != string(common.BigToHash(big.NewInt(20)).Bytes()) {
		t.Fatalf("restart did not restore the executed Core pair: height=%d hash=%x ok=%v", height, hash, ok)
	}
	t.Run("reopened", func(t *testing.T) { checkNEVMFinalityUnavailable(t, client) })
}

func TestEthereumFinalityRPCPreservesExplicitHeads(t *testing.T) {
	datadir := t.TempDir()
	eth, stack, client, genesis := newNEVMFinalityEthereum(t, datadir, false)
	genDB, blocks, _ := core.GenerateChainWithGenesis(genesis, eth.engine, 20, nil)
	t.Cleanup(func() { genDB.Close() })
	if _, err := eth.blockchain.InsertChain(blocks[:15]); err != nil {
		t.Fatal(err)
	}
	checkNEVMFinalityUnavailable(t, client)
	eth.blockchain.SetFinalized(blocks[4].Header())
	eth.blockchain.SetSafe(blocks[9].Header())
	check := func() { checkNEVMFinalityHeads(t, client, blocks[4], blocks[9]) }
	check()
	if _, err := eth.blockchain.InsertChain(blocks[15:]); err != nil {
		t.Fatal(err)
	}
	checkNEVMFinalityBlockRPC(t, client, "latest", blocks[19])
	check()
	if err := stack.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, client, _ = newNEVMFinalityEthereum(t, datadir, false)
	checkNEVMFinalityBlockRPC(t, client, "latest", blocks[19])
	checkNEVMFinalityBlockRPC(t, client, "finalized", blocks[4])
	// Upstream Geth restores safe from the persisted finalized head on restart.
	checkNEVMFinalityBlockRPC(t, client, "safe", blocks[4])
}
