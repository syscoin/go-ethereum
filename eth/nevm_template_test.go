// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package eth

import (
	"bytes"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// SYSCOIN: exercise the actual buffered import through the live template RPC.
// The fixture has no miner: reaching template assembly after a failed flush
// would panic, and the former fatal log would terminate the test process.
func TestNEVMTemplateFlushRejectsEarlierPair(t *testing.T) {
	for _, failure := range []string{"header", "execution", "payload"} {
		t.Run(failure, func(t *testing.T) {
			eth, genesis, engine := newNEVMPairTestEthereum(t, false)
			genDB, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, 2, nil)
			defer genDB.Close()
			header := blocks[1].Header()
			switch failure {
			case "header":
				header.Extra = bytes.Repeat([]byte{1}, int(params.MaximumExtraDataSize)+1)
			case "execution":
				header.Root = common.HexToHash("0xdeadbeef")
			case "payload":
				header.TxHash = common.HexToHash("0xdeadbeef")
			}
			blocks[1] = blocks[1].WithSeal(header)
			var rejected *types.NEVMBlockConnect
			var encoded []byte
			for i, block := range blocks {
				encoded = nevmConnectTestPayload(t, makeNEVMConnect(block, common.BytesToHash([]byte{0x44, byte(i + 1)}).Bytes()))
				pair := new(types.NEVMBlockConnect)
				if err := pair.Deserialize(encoded); err != nil {
					t.Fatal(err)
				}
				if err := eth.AddBlock(pair); err != nil {
					t.Fatalf("buffer pair %d: %v", i, err)
				}
				rejected = pair
			}
			want := nevmConnectTestInvalidReply(rejected)
			if failure == "payload" {
				want = nevmPayloadTestReply(t, encoded)
			}
			checkNEVMTemplateFailure(t, eth, want)
			if len(eth.blockConnectBuffer) != 0 || eth.blockchain.CurrentBlock().Hash() != blocks[0].Hash() {
				t.Fatal("failed template flush did not drop its batch and preserve the accepted prefix")
			}
		})
	}
}

type nevmTemplateSyncFailureDB struct {
	ethdb.Database
	fail error
}

func (db *nevmTemplateSyncFailureDB) SyncKeyValue() error { return db.fail }

func TestNEVMTemplateFlushStorageErrorStaysOperational(t *testing.T) {
	db := &nevmTemplateSyncFailureDB{Database: newNEVMTestMemoryDatabase()}
	eth, genesis, engine := newNEVMPairTestEthereumWithDB(t, false, db)
	genDB, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, 1, nil)
	defer genDB.Close()
	if err := eth.AddBlock(makeNEVMConnect(blocks[0], common.HexToHash("0x1234").Bytes())); err != nil {
		t.Fatal(err)
	}
	// Even a classification-looking message is not evidence of invalidity.
	db.fail = errors.New("invalid:storage:unavailable")
	t.Cleanup(func() { db.fail = nil })
	checkNEVMTemplateFailure(t, eth, "template-failed: sync Syscoin endpoint storage: "+db.fail.Error())
	if len(eth.blockConnectBuffer) != 0 || eth.blockchain.CurrentBlock().Number.Uint64() != 0 {
		t.Fatal("failed durability barrier imported a block or retained the batch")
	}
}

func checkNEVMTemplateFailure(t *testing.T, eth *Ethereum, want string) {
	t.Helper()
	server := NewZMQRep(nil, eth, "tcp://127.0.0.1:0")
	if err := server.InitZMQListener(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	client := nevmListenerClient(t, server)
	sendNEVMListenerRequest(t, client, "nevmblock", "nevmblock")
	reply, err := client.Recv()
	if err != nil || len(reply.Frames) != 3 || string(reply.Frames[0]) != "nevmblock" ||
		string(reply.Frames[1]) != "error" || string(reply.Frames[2]) != want {
		t.Fatalf("template failure reply %q, err=%v; want [nevmblock error %q]", reply.Frames, err, want)
	}
	// The server remains available for Core's reconciliation after the failure.
	sendNEVMListenerRequest(t, client, "nevmcomms", "\x06status")
	reply, err = client.Recv()
	if err != nil || len(reply.Frames) != 2 || string(reply.Frames[0]) != "nevmcomms" || string(reply.Frames[1]) != "ack" {
		t.Fatalf("listener unavailable after template failure: %q, err=%v", reply.Frames, err)
	}
}

func TestNEVMTemplateSuccessRetainsBinaryReply(t *testing.T) {
	eth, _, _, _ := newNEVMDiscoveryLifecycleEthereum(t)
	client := nevmListenerClient(t, eth.zmqRep)
	sendNEVMListenerRequest(t, client, "nevmblock", "nevmblock")
	reply, err := client.Recv()
	if err != nil || len(reply.Frames) != 2 || string(reply.Frames[0]) != "nevmblock" {
		t.Fatalf("successful template reply: %q, err=%v", reply.Frames, err)
	}
	// Like Core's CNEVMBlock, consume three hashes followed by the RLP vector.
	// The existing reply is not a full inbound NEVMBlockConnect: Core has not
	// supplied its pairing hash, and the serializer appends empty metadata.
	payload := reply.Frames[1]
	if len(payload) < 3*common.HashLength {
		t.Fatal("template is missing its committed hashes")
	}
	reader := bytes.NewReader(payload[3*common.HashLength:])
	encoded, err := wire.ReadVarBytes(reader, 0, 32*1024*1024, "NEVMBlockData")
	if err != nil {
		t.Fatal(err)
	}
	var block types.Block
	if err := rlp.DecodeBytes(encoded, &block); err != nil {
		t.Fatal(err)
	}
	if block.NumberU64() != 1 || block.ParentHash() != eth.blockchain.CurrentBlock().Hash() {
		t.Fatal("template does not build on the current tip")
	}
	for i, hash := range []common.Hash{block.Hash(), block.TxHash(), block.ReceiptHash()} {
		if !bytes.Equal(payload[i*common.HashLength:(i+1)*common.HashLength], hash[:]) {
			t.Fatalf("template hash %d does not match its RLP", i)
		}
	}
}
