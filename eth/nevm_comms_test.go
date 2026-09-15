// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package eth

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
)

func TestNEVMCommsFlushCommitsPartialBatches(t *testing.T) {
	eth, gspec, engine := newNEVMPairTestEthereum(t, false)
	// Retain the production buffering threshold instead of the fixture's eight.
	// The fixture cleanup restores the original package value.
	batchSize = 100
	_, blocks, _ := core.GenerateChainWithGenesis(gspec, engine, 69, nil)
	comms := &ZMQRep{eth: eth}

	checkPair := func(number int) {
		t.Helper()
		var sysHash []byte
		if number != 0 {
			sysHash = bytes.Repeat([]byte{byte(number)}, common.HashLength)
		}
		count, pair, ok := comms.currentNEVMBlockInfo()
		if !ok || count != uint64(number) || pair != encodeSyscoinDisplayHash(sysHash) {
			t.Fatalf("blockinfo: ok=%v count=%d pair=%s, want height %d pair %s",
				ok, count, pair, number, encodeSyscoinDisplayHash(sysHash))
		}
	}
	flush := func() {
		t.Helper()
		if reply := comms.handleNEVMComms("\x05flush"); reply != "flushed" {
			t.Fatalf("flush reply: %q", reply)
		}
		if len(eth.blockConnectBuffer) != 0 {
			t.Fatalf("flush left %d buffered blocks", len(eth.blockConnectBuffer))
		}
	}

	flush()
	checkPair(0)
	first := 0
	for batch, end := range []int{64, len(blocks)} {
		checkpoint := common.BytesToHash([]byte{0xbc, byte(batch + 1)})
		for i := first; i < end; i++ {
			connect := makeNEVMConnect(blocks[i], bytes.Repeat([]byte{byte(i + 1)}, common.HashLength))
			if i == first {
				connect.BTCPrevHash = checkpoint
			}
			if err := eth.AddBlock(connect); err != nil {
				t.Fatalf("buffer block %d: %v", i+1, err)
			}
		}
		if got := len(eth.blockConnectBuffer); got != end-first {
			t.Fatalf("buffer length %d, want %d", got, end-first)
		}
		checkPair(first)
		// Ordinary status and an unsupported command retain their read-only ack.
		for _, command := range []string{"\x06status", "\x04ping"} {
			if reply := comms.handleNEVMComms(command); reply != "ack" {
				t.Fatalf("comms %q reply: %q", command, reply)
			}
			checkPair(first)
			if got := len(eth.blockConnectBuffer); got != end-first {
				t.Fatalf("comms %q changed buffer length to %d", command, got)
			}
		}
		flush()
		checkPair(end)
		if got := eth.blockchain.CurrentBlock().Hash(); got != blocks[end-1].Hash() {
			t.Fatalf("committed NEVM hash %s, want %s", got, blocks[end-1].Hash())
		}
		if got := eth.blockchain.BTCCheckpointIndex(checkpoint); got != uint64(batch+1) {
			t.Fatalf("checkpoint index %d, want %d", got, batch+1)
		}
		if got := eth.blockchain.ReadBTCCheckpointLastIndex(); got != uint64(batch+1) {
			t.Fatalf("last checkpoint index %d, want %d", got, batch+1)
		}
		flush()
		checkPair(end)
		if !eth.handler.peers.closed {
			t.Fatal("flush changed the networking mode")
		}
		first = end
	}
}
