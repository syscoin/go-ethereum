// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package eth

import (
	"bytes"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/ethdb/leveldb"
	"github.com/ethereum/go-ethereum/ethdb/pebble"
	"github.com/ethereum/go-ethereum/params"
)

func durablePairCommand(number uint64, hash []byte) (string, string) {
	text := nevmDurablePairPrefix + strconv.FormatUint(number, 10) + ":" + encodeSyscoinDisplayHash(hash)
	return string([]byte{byte(len(text))}) + text, text
}

func TestNEVMDurablePairWire(t *testing.T) {
	for _, backend := range []string{"leveldb", "pebble"} {
		t.Run(backend, func(t *testing.T) {
			var kv ethdb.KeyValueStore
			var err error
			if backend == "leveldb" {
				kv, err = leveldb.New(t.TempDir(), 16, 16, "", false)
			} else {
				kv, err = pebble.New(t.TempDir(), 16, 16, "", false, false)
			}
			if err != nil {
				t.Fatal(err)
			}
			db := rawdb.NewDatabase(kv)
			defer db.Close()
			config := *params.AllEthashProtocolChanges
			config.SyscoinBlock = big.NewInt(0)
			genesis := &core.Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: &config}
			engine := ethash.NewFaker()
			chain, err := core.NewBlockChain(db, core.DefaultCacheConfigWithScheme(rawdb.HashScheme), genesis, nil, engine, vm.Config{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer chain.Stop()
			eth := &Ethereum{blockchain: chain, handler: &handler{peers: &peerSet{closed: true}}, engine: engine}
			comms := &ZMQRep{eth: eth}
			command, text := durablePairCommand(0, nil)
			if reply := comms.handleNEVMComms(command); reply != text {
				t.Fatalf("genesis fence reply %q", reply)
			}
			_, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, 1, nil)
			hash := make([]byte, 32)
			for i := range hash {
				hash[i] = byte(i + 1)
			}
			connect := makeNEVMConnect(blocks[0], hash)
			eth.blockConnectBuffer = append(eth.blockConnectBuffer, connect)
			if reply := comms.handleNEVMComms(command); reply == text {
				t.Fatal("buffered work acknowledged as durable endpoint")
			}
			if reply := comms.handleNEVMComms("\x05flush"); reply != "flushed" {
				t.Fatalf("flush reply %q", reply)
			}
			command, text = durablePairCommand(1, hash)
			malformed := []string{command[1:], command + "x", "\xfd" + command, string([]byte{byte(len(text) - 1)}) + text}
			for _, badText := range []string{
				strings.Replace(text, ":1:", ":01:", 1),
				strings.Replace(text, ":1:", ":+1:", 1),
				strings.Replace(text, ":1:", ":18446744073709551616:", 1),
				strings.ToUpper(text), text[:len(text)-1], text + ":extra",
			} {
				malformed = append(malformed, string([]byte{byte(len(badText))})+badText)
			}
			for _, bad := range malformed {
				if _, _, _, err := parseNEVMDurablePair(bad); err == nil {
					t.Fatalf("parser accepted %q", bad)
				}
				if reply := comms.handleNEVMComms(bad); reply == text {
					t.Fatalf("malformed command acknowledged: %q", bad)
				}
			}
			for _, wrong := range []struct {
				number uint64
				hash   []byte
			}{{2, hash}, {1, bytes.Repeat([]byte{0x44}, 32)}} {
				bad, expected := durablePairCommand(wrong.number, wrong.hash)
				if reply := comms.handleNEVMComms(bad); reply == expected {
					t.Fatal("wrong endpoint acknowledged")
				}
			}
			for i := 0; i < 2; i++ {
				if reply := comms.handleNEVMComms(command); reply != text {
					t.Fatalf("exact fence/retry reply %q, want %q", reply, text)
				}
			}
			if err := eth.DeleteBlock(makeNEVMDisconnect(hash)); err != nil {
				t.Fatal(err)
			}
			command, text = durablePairCommand(0, nil)
			if reply := comms.handleNEVMComms(command); reply != text {
				t.Fatalf("canceled parent fence reply %q", reply)
			}
		})
	}
}

func TestNEVMDurablePairUnsupportedStorage(t *testing.T) {
	eth, _, _ := newNEVMPairTestEthereum(t, false)
	command, text := durablePairCommand(0, nil)
	if reply := (&ZMQRep{eth: eth}).handleNEVMComms(command); reply == text {
		t.Fatal("memory-only backend acknowledged durability")
	}
}
