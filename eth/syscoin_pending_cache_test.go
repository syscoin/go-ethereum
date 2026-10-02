// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package eth

import (
	"bytes"
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

// A pending transaction can depend on Core metadata that is not committed by
// its NEVM parent hash. Exercise the registered storage RPC and real miner cache
// across a supported disconnect/reconnect of identical NEVM bytes.
func TestSyscoinPendingCacheFollowsCorePair(t *testing.T) {
	for _, scheme := range []string{rawdb.HashScheme, rawdb.PathScheme} {
		t.Run(scheme, func(t *testing.T) {
			config := *params.AllEthashProtocolChanges
			config.SyscoinBlock, config.NexusBlock = big.NewInt(0), big.NewInt(0)
			key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
			if err != nil {
				t.Fatal(err)
			}
			sender := crypto.PubkeyToAddress(key.PublicKey)
			probe := common.HexToAddress("0x1000")
			// Read SYSBLOCKHASH(1) through precompile 0x61 and store it in slot 0.
			probeCode := common.FromHex("6700000000000000016000526020602060086018606161fffffa5060205160005500")
			genesis := &core.Genesis{Config: &config, BaseFee: big.NewInt(params.InitialBaseFee), GasLimit: 5_000_000,
				Alloc: types.GenesisAlloc{
					sender: {Balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)},
					probe:  {Code: probeCode},
				},
			}
			engine := ethash.NewFaker()
			db := newNEVMTestMemoryDatabase()
			chain, err := core.NewBlockChain(db, core.DefaultCacheConfigWithScheme(scheme), genesis, nil, engine, vm.Config{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { chain.Stop(); db.Close() })
			poolConfig := legacypool.DefaultConfig
			poolConfig.Journal = ""
			pool, err := txpool.New(poolConfig.PriceLimit, chain, []txpool.SubPool{legacypool.New(poolConfig, chain)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { pool.Close() })
			eth := &Ethereum{blockchain: chain, chainDb: db, engine: engine, txPool: pool,
				handler: &handler{peers: &peerSet{closed: true}}}
			eth.miner = miner.New(eth, miner.DefaultConfig, engine)
			oldBatch := batchSize
			batchSize = 1
			t.Cleanup(func() { batchSize = oldBatch })
			server := rpc.NewServer()
			if err := server.RegisterName("eth", ethapi.NewBlockChainAPI(&EthAPIBackend{eth: eth})); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(server.Stop)
			client := rpc.DialInProc(server)
			t.Cleanup(client.Close)

			genDB, blocks, _ := core.GenerateChainWithGenesis(genesis, engine, 1, nil)
			t.Cleanup(func() { genDB.Close() })
			parent := blocks[0]
			sysA, sysB := bytes.Repeat([]byte{0xa1}, common.HashLength), bytes.Repeat([]byte{0xb1}, common.HashLength)
			if err := eth.AddBlock(makeNEVMConnect(parent, sysA)); err != nil {
				t.Fatal(err)
			}
			if err := pool.Sync(); err != nil {
				t.Fatal(err)
			}
			tx := types.MustSignNewTx(key, types.LatestSigner(&config), &types.LegacyTx{
				To: &probe, Gas: 100_000, GasPrice: new(big.Int).Mul(big.NewInt(params.InitialBaseFee), big.NewInt(2)),
			})
			if errs := pool.Add([]*types.Transaction{tx}, true); len(errs) != 1 || errs[0] != nil {
				t.Fatalf("add pending transaction: %v", errs)
			}
			readStorage := func(selector string) common.Hash {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var got hexutil.Bytes
				if err := client.CallContext(ctx, &got, "eth_getStorageAt", probe, "0x0", selector); err != nil {
					t.Fatalf("%s storage RPC: %v", selector, err)
				}
				return common.BytesToHash(got)
			}
			cachedAt := time.Now()
			if got := readStorage("pending"); got != common.BytesToHash(sysA) {
				t.Fatalf("first pending execution stored %s, want Core pair A %x", got, sysA)
			}
			if got := readStorage("latest"); got != (common.Hash{}) {
				t.Fatalf("pending transaction changed canonical storage: %s", got)
			}
			if err := eth.DeleteBlock(makeNEVMDisconnect(sysA)); err != nil {
				t.Fatal(err)
			}
			if err := eth.AddBlock(makeNEVMConnect(parent, sysB)); err != nil {
				t.Fatal(err)
			}
			if err := pool.Sync(); err != nil {
				t.Fatal(err)
			}
			if chain.CurrentBlock().Hash() != parent.Hash() || !bytes.Equal(chain.ReadSYSHash(1), sysB) {
				t.Fatal("replacement did not retain the same NEVM parent with Core pair B")
			}
			got := readStorage("pending")
			if elapsed := time.Since(cachedAt); elapsed >= 2*time.Second {
				t.Fatalf("fixture exceeded the existing pending cache TTL: %s", elapsed)
			}
			if got != common.BytesToHash(sysB) {
				t.Fatalf("pending RPC reused Core pair A state after same-NEVM-hash reconnect: got %s, want %x", got, sysB)
			}
			if got := readStorage("latest"); got != (common.Hash{}) {
				t.Fatalf("pending regeneration changed canonical storage: %s", got)
			}
		})
	}
}
