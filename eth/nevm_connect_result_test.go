// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package eth

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/go-zeromq/zmq4"
	"github.com/syscoin/syscoinwire/syscoin/wire"
)

func nevmConnectTestPayload(t *testing.T, pair *types.NEVMBlockConnect) []byte {
	t.Helper()
	data, err := rlp.EncodeToBytes(pair.Block)
	if err != nil {
		t.Fatal(err)
	}
	sysHash := common.BytesToHash([]byte(pair.Sysblockhash))
	payload := wire.NEVMBlockWire{
		NEVMBlockHash: pair.Block.Hash().Bytes(),
		TxRoot:        pair.Block.TxHash().Bytes(),
		ReceiptRoot:   pair.Block.ReceiptHash().Bytes(),
		NEVMBlockData: data,
		SYSBlockHash:  sysHash[:],
		Diff:          *pair.Diff,
		BTCPrevHash:   pair.BTCPrevHash[:],
	}
	for _, hash := range pair.VersionHashes {
		payload.VersionHashes = append(payload.VersionHashes, hash[:])
	}
	var encoded bytes.Buffer
	if err := payload.Serialize(&encoded); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

func nevmConnectTestReply(t *testing.T, eth *Ethereum) func(string, []byte) string {
	t.Helper()
	server := NewZMQRep(nil, eth, "tcp://127.0.0.1:0")
	if err := server.InitZMQListener(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	client := zmq4.NewReq(ctx, zmq4.WithTimeout(5*time.Second))
	t.Cleanup(func() { client.Close() })
	if err := client.Dial("tcp://" + server.rep.Addr().String()); err != nil {
		t.Fatal(err)
	}
	return func(topic string, payload []byte) string {
		t.Helper()
		if err := client.SendMulti(zmq4.NewMsgFrom([]byte(topic), payload)); err != nil {
			t.Fatal(err)
		}
		reply, err := client.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if len(reply.Frames) != 2 || string(reply.Frames[0]) != topic {
			t.Fatalf("unexpected %s response framing: %q", topic, reply.Frames)
		}
		return string(reply.Frames[1])
	}
}

// Compute the expected display order independently of the production encoder.
func nevmConnectTestInvalidReply(pair *types.NEVMBlockConnect) string {
	nevmHash := pair.Block.Hash()
	sysHash := common.BytesToHash([]byte(pair.Sysblockhash))
	for i := 0; i < common.HashLength/2; i++ {
		nevmHash[i], nevmHash[31-i] = nevmHash[31-i], nevmHash[i]
		sysHash[i], sysHash[31-i] = sysHash[31-i], sysHash[i]
	}
	return "invalid:" + hex.EncodeToString(nevmHash[:]) + ":" + hex.EncodeToString(sysHash[:])
}

func TestNEVMConnectResultRequiresIdentifiedConsensusFailure(t *testing.T) {
	block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(1)})
	pair := makeNEVMConnect(block, common.HexToHash("0x1234").Bytes())
	invalid := fmt.Errorf("wrapped: %w", consensus.MarkInvalidBlock(errors.New("invalid gas used")))
	for _, test := range []struct {
		name  string
		err   error
		index int
		pairs []*types.NEVMBlockConnect
	}{
		{"unmarked", errors.New("invalid:abc:def"), 0, []*types.NEVMBlockConnect{pair}},
		{"unknown", errors.New("unexpected storage error"), 0, []*types.NEVMBlockConnect{pair}},
		{"future", consensus.ErrFutureBlock, 0, []*types.NEVMBlockConnect{pair}},
		{"ancestor", consensus.ErrUnknownAncestor, 0, []*types.NEVMBlockConnect{pair}},
		{"pruned", consensus.ErrPrunedAncestor, 0, []*types.NEVMBlockConnect{pair}},
		{"negative-index", invalid, -1, []*types.NEVMBlockConnect{pair}},
		{"past-end-index", invalid, 1, []*types.NEVMBlockConnect{pair}},
		{"missing-index", invalid, 0, nil},
		{"missing-pair", invalid, 0, []*types.NEVMBlockConnect{nil}},
		{"malformed-pair-hash", invalid, 0, []*types.NEVMBlockConnect{makeNEVMConnect(block, []byte{1})}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := nevmConnectResult(nevmInsertError(test.err, test.index, test.pairs)); got != "error:"+test.err.Error() {
				t.Fatalf("unproven failure classified as %q", got)
			}
		})
	}
	err := nevmInsertError(invalid, 0, []*types.NEVMBlockConnect{pair})
	if !errors.Is(err, invalid) {
		t.Fatal("pair identity wrapper lost its underlying error")
	}
	if got := nevmConnectResult(fmt.Errorf("outer: %w", err)); got != nevmConnectTestInvalidReply(pair) {
		t.Fatalf("identified consensus failure: %q", got)
	}
	// A marker without an established pair must remain operational at the wire.
	if got := nevmConnectResult(invalid); got != "error:"+invalid.Error() {
		t.Fatalf("unpaired marker: %q", got)
	}
}

func TestNEVMConnectWireContract(t *testing.T) {
	eth, genesis, engine := newNEVMPairTestEthereum(t, true)
	genDB, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, 1, nil)
	defer genDB.Close()
	reply := nevmConnectTestReply(t, eth)
	for _, command := range []string{"\x0aconnect-v1", "connect-v1", "\x09connect-v1", "\x0aconnect-v1\x00", "\x06status", "\x04ping"} {
		want := "ack"
		if command == "\x0aconnect-v1" {
			want = "connect-v1"
		}
		if got := reply("nevmcomms", []byte(command)); got != want {
			t.Fatalf("comms %q returned %q, want %q", command, got, want)
		}
	}
	pair := makeNEVMConnect(blocks[0], common.HexToHash("0x123456").Bytes())
	payload := nevmConnectTestPayload(t, pair)
	wrongHash := bytes.Clone(payload)
	wrongHash[0] ^= 1
	wrongTxRoot := bytes.Clone(payload)
	wrongTxRoot[common.HashLength] ^= 1
	// Also exercise an empty body directly at the deserialization boundary.
	if got := (&ZMQRep{eth: eth}).handleNEVMConnect(nil); got != "error:EOF" {
		t.Fatalf("empty payload failure returned %q", got)
	}
	for _, input := range [][]byte{[]byte("invalid:untrusted-payload"), payload[:len(payload)/2], wrongHash, wrongTxRoot} {
		if got := reply("nevmconnect", input); !strings.HasPrefix(got, "error:") {
			t.Fatalf("payload failure returned %q", got)
		}
	}
	// A different supplied body can have the same header hash. Reject its root
	// mismatch operationally, then accept the complete original pair below.
	wrongBody := blocks[0].WithBody(types.Body{Transactions: []*types.Transaction{
		types.NewTx(&types.LegacyTx{Gas: 21_000, GasPrice: big.NewInt(1)}),
	}})
	if got := reply("nevmconnect", nevmConnectTestPayload(t, makeNEVMConnect(wrongBody, []byte(pair.Sysblockhash)))); !strings.HasPrefix(got, "error:") {
		t.Fatalf("supplied body mismatch returned %q", got)
	}
	for i := 0; i < 2; i++ {
		if got := reply("nevmconnect", payload); got != "connected" {
			t.Fatalf("valid connect/retry %d: %q", i, got)
		}
	}
	if eth.blockchain.CurrentBlock().Hash() != pair.Block.Hash() || !bytes.Equal(eth.blockchain.ReadSYSHash(1), []byte(pair.Sysblockhash)) {
		t.Fatal("successful connect did not commit the exact pair")
	}
}

func TestNEVMConnectWireHeaderInvalidPair(t *testing.T) {
	for _, candidateOnly := range []bool{false, true} {
		t.Run(fmt.Sprintf("candidate-only-%v", candidateOnly), func(t *testing.T) {
			eth, genesis, engine := newNEVMPairTestEthereum(t, true)
			genDB, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, 1, func(_ int, b *core.BlockGen) {
				b.SetExtra(bytes.Repeat([]byte{1}, int(params.MaximumExtraDataSize)+1))
			})
			defer genDB.Close()
			sysHash := common.HexToHash("0x123456").Bytes()
			if candidateOnly {
				sysHash = nil
			}
			pair := makeNEVMConnect(blocks[0], sysHash)
			reply := nevmConnectTestReply(t, eth)
			if got := reply("nevmconnect", nevmConnectTestPayload(t, pair)); got != nevmConnectTestInvalidReply(pair) {
				t.Fatalf("header rejection returned %q, want %q", got, nevmConnectTestInvalidReply(pair))
			}
			if eth.blockchain.CurrentBlock().Number.Uint64() != 0 || len(eth.blockConnectBuffer) != 0 {
				t.Fatal("rejected header changed the head or retained a buffered candidate")
			}
		})
	}
}

func TestNEVMConnectBufferedFailureIdentifiesEarlierPair(t *testing.T) {
	eth, genesis, engine := newNEVMPairTestEthereum(t, false)
	batchSize = 3
	genDB, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, 3, func(i int, b *core.BlockGen) {
		if i == 1 {
			b.SetExtra(bytes.Repeat([]byte{1}, int(params.MaximumExtraDataSize)+1))
		}
	})
	defer genDB.Close()
	reply := nevmConnectTestReply(t, eth)
	pairs := make([]*types.NEVMBlockConnect, len(blocks))
	for i, block := range blocks {
		pairs[i] = makeNEVMConnect(block, common.BytesToHash([]byte{0xaa, byte(i + 1)}).Bytes())
		want := "connected"
		if i == 2 {
			want = nevmConnectTestInvalidReply(pairs[1])
		}
		if got := reply("nevmconnect", nevmConnectTestPayload(t, pairs[i])); got != want {
			t.Fatalf("connect %d returned %q, want %q", i, got, want)
		}
	}
	if len(eth.blockConnectBuffer) != 0 || eth.blockchain.CurrentBlock().Hash() != blocks[0].Hash() {
		t.Fatal("failed buffered import did not drop its batch and retain the committed prefix")
	}
}

type nevmHeaderResultEngine struct {
	consensus.Engine
	err error
}

func (e *nevmHeaderResultEngine) VerifyHeader(consensus.ChainHeaderReader, *types.Header) error {
	return e.err
}

func TestNEVMConnectCandidateUnmarkedErrorsRemainOperational(t *testing.T) {
	eth, genesis, engine := newNEVMPairTestEthereum(t, true)
	genDB, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, 1, nil)
	defer genDB.Close()
	verifier := &nevmHeaderResultEngine{Engine: engine}
	eth.engine = verifier
	comms := &ZMQRep{eth: eth}
	payload := nevmConnectTestPayload(t, makeNEVMConnect(blocks[0], nil))
	for _, err := range []error{consensus.ErrUnknownAncestor, consensus.ErrFutureBlock, consensus.ErrPrunedAncestor, errors.New("invalid header"), errors.New("local state unavailable")} {
		verifier.err = err
		if got := comms.handleNEVMConnect(payload); got != "error:"+err.Error() {
			t.Fatalf("unmarked header failure %v returned %q", err, got)
		}
	}
	verifier.err = nil
	if got := comms.handleNEVMConnect(payload); got != "connected" {
		t.Fatalf("valid candidate returned %q", got)
	}
	if eth.blockchain.CurrentBlock().Number.Uint64() != 0 || len(eth.blockConnectBuffer) != 0 {
		t.Fatal("candidate validation modified the canonical pair")
	}
}

func TestNEVMConnectStorageFailureWireRetry(t *testing.T) {
	config := *params.AllEthashProtocolChanges
	config.SyscoinBlock = big.NewInt(0)
	genesis := &core.Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: &config}
	engine := ethash.NewFaker()
	db := &disconnectTestDB{Database: rawdb.NewMemoryDatabase()}
	t.Cleanup(func() { db.Close() })
	chain, err := core.NewBlockChain(db, core.DefaultCacheConfigWithScheme(rawdb.HashScheme), genesis, nil, engine, vm.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(chain.Stop)
	eth := &Ethereum{blockchain: chain, chainDb: db, engine: engine, handler: &handler{peers: &peerSet{}}}
	genDB, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, 1, nil)
	defer genDB.Close()
	pair := makeNEVMConnect(blocks[0], common.HexToHash("0x123456").Bytes())
	payload := nevmConnectTestPayload(t, pair)
	reply := nevmConnectTestReply(t, eth)
	writeErr := errors.New("injected canonical write failure")
	db.mu.Lock()
	db.afterWrite = func() { db.fail = writeErr }
	db.mu.Unlock()
	if got := reply("nevmconnect", payload); !strings.HasPrefix(got, "error:") || !strings.Contains(got, writeErr.Error()) {
		t.Fatalf("storage failure returned %q", got)
	}
	db.mu.Lock()
	db.fail, db.afterWrite = nil, nil
	db.mu.Unlock()
	if chain.CurrentBlock().Number.Uint64() != 0 || rawdb.ReadHeadBlockHash(db) != blocks[0].ParentHash() || len(chain.ReadSYSHash(1)) != 0 || len(eth.blockConnectBuffer) != 0 {
		t.Fatal("failed connect published a pair or retained its failed candidate")
	}
	if got := reply("nevmconnect", payload); got != "connected" {
		t.Fatalf("same candidate retry returned %q", got)
	}
	if chain.CurrentBlock().Hash() != pair.Block.Hash() || !bytes.Equal(chain.ReadSYSHash(1), []byte(pair.Sysblockhash)) {
		t.Fatal("same candidate retry failed to commit its exact pair")
	}
}
