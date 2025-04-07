// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package eth implements the Ethereum protocol.
package eth

import (
	"encoding/json"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	// SYSCOIN
	"errors"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/filtermaps"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state/pruner"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/blobpool"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/core/txpool/locals"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/eth/gasprice"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/eth/protocols/snap"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/internal/shutdowncheck"
	"github.com/ethereum/go-ethereum/internal/version"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/dnsdisc"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	// SYSCOIN
	"github.com/ethereum/go-ethereum/crypto"
	gethversion "github.com/ethereum/go-ethereum/version"
)

// Config contains the configuration options of the ETH protocol.
// Deprecated: use ethconfig.Config instead.
type Config = ethconfig.Config
// Ethereum implements the Ethereum full node service.
type Ethereum struct {
	// core protocol objects
	config         *ethconfig.Config
	txPool         *txpool.TxPool
	localTxTracker *locals.TxTracker
	blockchain     *core.BlockChain

	handler *handler
	discmix *enode.FairMix

	// DB interfaces
	chainDb ethdb.Database // Block chain database

	eventMux       *event.TypeMux
	engine         consensus.Engine
	accountManager *accounts.Manager

	filterMaps      *filtermaps.FilterMaps
	closeFilterMaps chan chan struct{}

	APIBackend *EthAPIBackend

	miner    *miner.Miner
	gasPrice *big.Int

	networkID     uint64
	netRPCService *ethapi.NetAPI

	p2pServer *p2p.Server

	lock sync.RWMutex // Protects the variadic fields (e.g. gas price and etherbase)

	shutdownTracker *shutdowncheck.ShutdownTracker // Tracks if and when the node has shutdown ungracefully
	// SYSCOIN
	wgNEVM            sync.WaitGroup
	wg     			  sync.WaitGroup
	zmqRep            *ZMQRep
	timeLastBlock     int64
	stack             *node.Node
	closeHandler chan struct{}
	blockConnectBuffer []*types.NEVMBlockConnect
	bufferLock         sync.Mutex
}
var batchSize = 100
// New creates a new Ethereum object (including the initialisation of the common Ethereum object),
// whose lifecycle will be managed by the provided node.
func New(stack *node.Node, config *ethconfig.Config) (*Ethereum, error) {
	// Ensure configuration values are compatible and sane
	if !config.SyncMode.IsValid() {
		return nil, fmt.Errorf("invalid sync mode %d", config.SyncMode)
	}
	if !config.HistoryMode.IsValid() {
		return nil, fmt.Errorf("invalid history mode %d", config.HistoryMode)
	}
	if config.Miner.GasPrice == nil || config.Miner.GasPrice.Sign() <= 0 {
		log.Warn("Sanitizing invalid miner gas price", "provided", config.Miner.GasPrice, "updated", ethconfig.Defaults.Miner.GasPrice)
		config.Miner.GasPrice = new(big.Int).Set(ethconfig.Defaults.Miner.GasPrice)
	}
	if config.NoPruning && config.TrieDirtyCache > 0 {
		if config.SnapshotCache > 0 {
			config.TrieCleanCache += config.TrieDirtyCache * 3 / 5
			config.SnapshotCache += config.TrieDirtyCache * 2 / 5
		} else {
			config.TrieCleanCache += config.TrieDirtyCache
		}
		config.TrieDirtyCache = 0
	}
	log.Info("Allocated trie memory caches", "clean", common.StorageSize(config.TrieCleanCache)*1024*1024, "dirty", common.StorageSize(config.TrieDirtyCache)*1024*1024)

	chainDb, err := stack.OpenDatabaseWithFreezer("chaindata", config.DatabaseCache, config.DatabaseHandles, config.DatabaseFreezer, "eth/db/chaindata/", false)
	if err != nil {
		return nil, err
	}
	scheme, err := rawdb.ParseStateScheme(config.StateScheme, chainDb)
	if err != nil {
		return nil, err
	}
	// Try to recover offline state pruning only in hash-based.
	if scheme == rawdb.HashScheme {
		if err := pruner.RecoverPruning(stack.ResolvePath(""), chainDb); err != nil {
			log.Error("Failed to recover state", "error", err)
		}
	}

	// Here we determine genesis hash and active ChainConfig.
	// We need these to figure out the consensus parameters and to set up history pruning.
	chainConfig, genesisHash, err := core.LoadChainConfig(chainDb, config.Genesis)
	if err != nil {
		return nil, err
	}
	engine, err := ethconfig.CreateConsensusEngine(chainConfig, chainDb)
	if err != nil {
		return nil, err
	}

	// Validate history pruning configuration.
	var (
		cutoffNumber uint64
		cutoffHash   common.Hash
	)
	if config.HistoryMode == ethconfig.PostMergeHistory {
		prunecfg, ok := ethconfig.HistoryPrunePoints[genesisHash]
		if !ok {
			return nil, fmt.Errorf("no history pruning point is defined for genesis %x", genesisHash)
		}
		cutoffNumber = prunecfg.BlockNumber
		cutoffHash = prunecfg.BlockHash
		log.Info("Chain cutoff configured", "number", cutoffNumber, "hash", cutoffHash)
	}

	// Set networkID to chainID by default.
	networkID := config.NetworkId
	if networkID == 0 {
		networkID = chainConfig.ChainID.Uint64()
	}

	// Assemble the Ethereum object.
	eth := &Ethereum{
		config:          config,
		chainDb:         chainDb,
		eventMux:        stack.EventMux(),
		accountManager:  stack.AccountManager(),
		engine:          engine,
		networkID:       networkID,
		gasPrice:        config.Miner.GasPrice,
		p2pServer:       stack.Server(),
		discmix:         enode.NewFairMix(0),
		shutdownTracker: shutdowncheck.NewShutdownTracker(chainDb),
		// SYSCOIN
		closeHandler:        make(chan struct{}),
		stack:               stack,
		blockConnectBuffer:  make([]*types.NEVMBlockConnect, 0, batchSize),
	}
	bcVersion := rawdb.ReadDatabaseVersion(chainDb)
	var dbVer = "<nil>"
	if bcVersion != nil {
		dbVer = fmt.Sprintf("%d", *bcVersion)
	}
	log.Info("Initialising Ethereum protocol", "network", networkID, "dbversion", dbVer)

	if !config.SkipBcVersionCheck {
		if bcVersion != nil && *bcVersion > core.BlockChainVersion {
			return nil, fmt.Errorf("database version is v%d, Geth %s only supports v%d", *bcVersion, version.WithMeta, core.BlockChainVersion)
		} else if bcVersion == nil || *bcVersion < core.BlockChainVersion {
			if bcVersion != nil { // only print warning on upgrade, not on init
				log.Warn("Upgrade blockchain database version", "from", dbVer, "to", core.BlockChainVersion)
			}
			rawdb.WriteDatabaseVersion(chainDb, core.BlockChainVersion)
		}
	}
	var (
		vmConfig = vm.Config{
			EnablePreimageRecording: config.EnablePreimageRecording,
		}
		cacheConfig = &core.CacheConfig{
			TrieCleanLimit:             config.TrieCleanCache,
			TrieCleanNoPrefetch:        config.NoPrefetch,
			TrieDirtyLimit:             config.TrieDirtyCache,
			TrieDirtyDisabled:          config.NoPruning,
			TrieTimeLimit:              config.TrieTimeout,
			SnapshotLimit:              config.SnapshotCache,
			Preimages:                  config.Preimages,
			StateHistory:               config.StateHistory,
			StateScheme:                scheme,
			HistoryPruningCutoffNumber: cutoffNumber,
			HistoryPruningCutoffHash:   cutoffHash,
		}
	)
	if config.VMTrace != "" {
		traceConfig := json.RawMessage("{}")
		if config.VMTraceJsonConfig != "" {
			traceConfig = json.RawMessage(config.VMTraceJsonConfig)
		}
		t, err := tracers.LiveDirectory.New(config.VMTrace, traceConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create tracer %s: %v", config.VMTrace, err)
		}
		vmConfig.Tracer = t
	}
	// Override the chain config with provided settings.
	var overrides core.ChainOverrides
	if config.OverridePrague != nil {
		overrides.OverridePrague = config.OverridePrague
	}
	if config.OverrideVerkle != nil {
		overrides.OverrideVerkle = config.OverrideVerkle
	}
	eth.blockchain, err = core.NewBlockChain(chainDb, cacheConfig, config.Genesis, &overrides, eth.engine, vmConfig, &config.TransactionHistory)
	if err != nil {
		return nil, err
	}
	fmConfig := filtermaps.Config{
		History:        config.LogHistory,
		Disabled:       config.LogNoHistory,
		ExportFileName: config.LogExportCheckpoints,
		HashScheme:     scheme == rawdb.HashScheme,
	}
	chainView := eth.newChainView(eth.blockchain.CurrentBlock())
	historyCutoff, _ := eth.blockchain.HistoryPruningCutoff()
	var finalBlock uint64
	if fb := eth.blockchain.CurrentFinalBlock(); fb != nil {
		finalBlock = fb.Number.Uint64()
	}
	eth.filterMaps = filtermaps.NewFilterMaps(chainDb, chainView, historyCutoff, finalBlock, filtermaps.DefaultParams, fmConfig)
	eth.closeFilterMaps = make(chan chan struct{})

	if config.BlobPool.Datadir != "" {
		config.BlobPool.Datadir = stack.ResolvePath(config.BlobPool.Datadir)
	}
	blobPool := blobpool.New(config.BlobPool, eth.blockchain)

	if config.TxPool.Journal != "" {
		config.TxPool.Journal = stack.ResolvePath(config.TxPool.Journal)
	}
	legacyPool := legacypool.New(config.TxPool, eth.blockchain)

	eth.txPool, err = txpool.New(config.TxPool.PriceLimit, eth.blockchain, []txpool.SubPool{legacyPool, blobPool})
	if err != nil {
		return nil, err
	}

	if !config.TxPool.NoLocals {
		rejournal := config.TxPool.Rejournal
		if rejournal < time.Second {
			log.Warn("Sanitizing invalid txpool journal time", "provided", rejournal, "updated", time.Second)
			rejournal = time.Second
		}
		eth.localTxTracker = locals.New(config.TxPool.Journal, rejournal, eth.blockchain.Config(), eth.txPool)
		stack.RegisterLifecycle(eth.localTxTracker)
	}
	// Permit the downloader to use the trie cache allowance during fast sync
	cacheLimit := cacheConfig.TrieCleanLimit + cacheConfig.TrieDirtyLimit + cacheConfig.SnapshotLimit
	if eth.handler, err = newHandler(&handlerConfig{
		NodeID:         eth.p2pServer.Self().ID(),
		Database:       chainDb,
		Chain:          eth.blockchain,
		TxPool:         eth.txPool,
		Network:        networkID,
		Sync:           config.SyncMode,
		BloomCache:     uint64(cacheLimit),
		EventMux:       eth.eventMux,
		RequiredBlocks: config.RequiredBlocks,
	}); err != nil {
		return nil, err
	}

	eth.miner = miner.New(eth, config.Miner, eth.engine)
	eth.miner.SetExtra(makeExtraData(config.Miner.ExtraData))
	eth.miner.SetPrioAddresses(config.TxPool.Locals)

	eth.APIBackend = &EthAPIBackend{stack.Config().ExtRPCEnabled(), stack.Config().AllowUnprotectedTxs, eth, nil}
	if eth.APIBackend.allowUnprotectedTxs {
		log.Info("Unprotected transactions allowed")
	}
	eth.APIBackend.gpo = gasprice.NewOracle(eth.APIBackend, config.GPO, config.Miner.GasPrice)

	// Start the RPC service
	eth.netRPCService = ethapi.NewNetAPI(eth.p2pServer, networkID)

	// Register the backend on the node
	stack.RegisterAPIs(eth.APIs())
	stack.RegisterProtocols(eth.Protocols())
	stack.RegisterLifecycle(eth)

	// Successful startup; push a marker and check previous unclean shutdowns.
	eth.shutdownTracker.MarkStartup()
	// SYSCOIN	
	if eth.blockchain.GetChainConfig().SyscoinBlock != nil {
		eth.zmqRep = NewZMQRep(stack, eth, config.NEVMPubEP)
		eth.wg.Add(1)
		go eth.networkingLoop()
	}
	return eth, nil
}

func makeExtraData(extra []byte) []byte {
	if len(extra) == 0 {
		// create default extradata
		extra, _ = rlp.EncodeToBytes([]interface{}{
			uint(gethversion.Major<<16 | gethversion.Minor<<8 | gethversion.Patch),
			"geth",
			runtime.Version(),
			runtime.GOOS,
		})
	}
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		log.Warn("Miner extra data exceed limit", "extra", hexutil.Bytes(extra), "limit", params.MaximumExtraDataSize)
		extra = nil
	}
	return extra
}
// SYSCOIN
func (eth *Ethereum) CreateBlock() *types.Block {
	eth.wgNEVM.Add(1)
	defer eth.wgNEVM.Done()

	if err := eth.flushBufferedBlocks(); err != nil {
		log.Crit("Failed flushing buffer before createBlock", "err", err)
		return nil
	}

	return eth.miner.GenerateWorkSyscoin(
		eth.config.Miner.Etherbase,
		crypto.Keccak256Hash([]byte{123}),
	)
}

func (eth *Ethereum) AddBlock(nevmBlockConnectIn *types.NEVMBlockConnect) error {
    if nevmBlockConnectIn == nil || nevmBlockConnectIn.Block == nil {
        return errors.New("addBlock: Empty block")
    }

    incomingBlockNumber := nevmBlockConnectIn.Block.NumberU64()
    incomingBlockHash := nevmBlockConnectIn.Block.Hash()

    // Check persisted blockchain first to avoid duplicates or collisions
    existingBlock := eth.blockchain.GetBlockByNumber(incomingBlockNumber)
    if existingBlock != nil {
        if existingBlock.Hash() == incomingBlockHash {
            log.Info("Block already exists in chain, skipping insert", "number", incomingBlockNumber, "hash", existingBlock.Hash())
            return nil
        }
        log.Warn("Block height collision in chain",
            "number", incomingBlockNumber,
            "existingHash", existingBlock.Hash(),
            "incomingHash", incomingBlockHash)
        return fmt.Errorf("block collision at height %d: existing [%x..], incoming [%x..]",
            incomingBlockNumber, existingBlock.Hash().Bytes()[:4], incomingBlockHash.Bytes()[:4])
    }

    // Determine last block for continuity check
    var lastBlockNumber uint64
    var lastBlockHash common.Hash

    eth.bufferLock.Lock()
    bufferLen := len(eth.blockConnectBuffer)
    if bufferLen == 0 {
        currentHead := eth.blockchain.CurrentBlock()
        lastBlockNumber = currentHead.Number.Uint64()
        lastBlockHash = currentHead.Hash()
    } else {
        lastInBatch := eth.blockConnectBuffer[bufferLen-1].Block
        lastBlockNumber = lastInBatch.NumberU64()
        lastBlockHash = lastInBatch.Hash()

        // Check last buffered block directly for duplicate
        if incomingBlockNumber == lastBlockNumber && incomingBlockHash == lastBlockHash {
            eth.bufferLock.Unlock()
            log.Info("Block already buffered as last, skipping insert", "number", incomingBlockNumber, "hash", incomingBlockHash)
            return nil
        }
    }
    eth.bufferLock.Unlock()

    incomingParentHash := nevmBlockConnectIn.Block.ParentHash()

    if incomingBlockNumber != lastBlockNumber+1 || incomingParentHash != lastBlockHash {
        log.Error("Non contiguous block insert",
            "number", incomingBlockNumber,
            "hash", incomingBlockHash,
            "parent", incomingParentHash,
            "prevnumber", lastBlockNumber,
            "prevhash", lastBlockHash,
        )
        return fmt.Errorf("non contiguous insert: last block #%d [%x..], new block #%d [%x..] (parent [%x..])",
            lastBlockNumber, lastBlockHash.Bytes()[:4],
            incomingBlockNumber, incomingBlockHash.Bytes()[:4],
            incomingParentHash.Bytes()[:4],
        )
    }

    sysBlockHash := common.BytesToHash([]byte(nevmBlockConnectIn.Sysblockhash))
    if sysBlockHash == (common.Hash{}) {
        if err := eth.engine.VerifyHeader(eth.blockchain, nevmBlockConnectIn.Block.Header()); err != nil {
            return err
        }
        return nil
    }

    // Add to buffer
    eth.bufferLock.Lock()
    eth.blockConnectBuffer = append(eth.blockConnectBuffer, nevmBlockConnectIn)
    bufferLen = len(eth.blockConnectBuffer)
    eth.bufferLock.Unlock()

    // Update timestamp
    eth.lock.Lock()
    eth.timeLastBlock = time.Now().Unix()
    eth.lock.Unlock()

    if eth.handler.peers.closed && bufferLen < batchSize {
        return nil
    }

    return eth.flushBufferedBlocks()
}


func (eth *Ethereum) flushBufferedBlocks() error {
    eth.bufferLock.Lock()
    defer eth.bufferLock.Unlock()

    if len(eth.blockConnectBuffer) == 0 {
        return nil
    }

    blockBuffer := make([]*types.Block, 0, len(eth.blockConnectBuffer))
    for _, nevmBlockConnect := range eth.blockConnectBuffer {
        nevmBlockConnect.Block.NevmBlockConnect = nevmBlockConnect
        blockBuffer = append(blockBuffer, nevmBlockConnect.Block)
    }

    if _, err := eth.blockchain.InsertChain(blockBuffer); err != nil {
        return err
    }

    eth.blockConnectBuffer = eth.blockConnectBuffer[:0] // safely clear buffer
    return nil
}

func (eth *Ethereum) disconnectBufferedBlock(blockHash common.Hash) (bool, error) {
    eth.bufferLock.Lock()
    defer eth.bufferLock.Unlock()

    if len(eth.blockConnectBuffer) == 0 {
        // Buffer empty, safely signal caller to proceed with disk rollback
        log.Info("Buffer empty, block must be disconnected from persisted chain", "hash", blockHash)
        return false, nil
    }

    foundIndex := -1
    for i, buffered := range eth.blockConnectBuffer {
        if common.BytesToHash([]byte(buffered.Sysblockhash)) == blockHash {
            foundIndex = i
            break
        }
    }

    if foundIndex == -1 {
        // Critical mismatch: buffer is non-empty but block not found
        errMsg := fmt.Sprintf("Critical: buffer non-empty but block [%x] not found during disconnect", blockHash.Bytes()[:4])
        log.Crit(errMsg)
        return false, errors.New(errMsg)
    }

    // Remove the block and descendants from buffer
    removedBlocks := eth.blockConnectBuffer[foundIndex:]
    eth.blockConnectBuffer = eth.blockConnectBuffer[:foundIndex]

    log.Info("Buffered blocks disconnected",
        "removedCount", len(removedBlocks),
        "disconnectedSysHash", blockHash,
    )

    return true, nil
}

// deleteBlock reverts the blockchain by one NEVM block
func (eth *Ethereum) DeleteBlock(nevmBlockDisconnect *types.NEVMBlockDisconnect) error {
	disconnectHash := common.BytesToHash([]byte(nevmBlockDisconnect.Sysblockhash))
    // Attempt disconnect from buffer first
    buffered, err := eth.disconnectBufferedBlock(disconnectHash)
    if err != nil {
        return err
    }

    if buffered {
        // Block was found and disconnected from the buffer, no further action needed.
        return nil
    }

	current := eth.blockchain.CurrentBlock()
	if current == nil {
		return errors.New("deleteBlock: Current block is nil")
	}
	currentNumber := current.Number.Uint64()
	if currentNumber == 0 {
		log.Warn("Trying to disconnect block 0")
		return nil
	}

	parent := eth.blockchain.GetBlock(current.ParentHash, currentNumber-1)
	if parent == nil {
		return errors.New("deleteBlock: Parent block not found")
	}
	headHash, err := eth.blockchain.SetCanonical(parent)
	if err != nil {
		return err
	}
	if parent.Hash() != headHash {
		return errors.New("deleteBlock: Mismatch after setting canonical head")
	}

	batch := eth.ChainDb().NewBatch()
	if nevmBlockDisconnect.HasDiff() {
		for _, entry := range nevmBlockDisconnect.Diff.AddedMNNEVM {
			addr := common.BytesToAddress(entry.Address)
			eth.blockchain.StoreNEVMAddress(batch, addr, entry.CollateralHeight)
		}
		for _, entry := range nevmBlockDisconnect.Diff.UpdatedMNNEVM {
			oldAddr := common.BytesToAddress(entry.OldAddress)
			newAddr := common.BytesToAddress(entry.NewAddress)
			eth.blockchain.RemoveNEVMAddress(batch, oldAddr)
			eth.blockchain.StoreNEVMAddress(batch, newAddr, entry.CollateralHeight)
		}
		for _, entry := range nevmBlockDisconnect.Diff.RemovedMNNEVM {
			addr := common.BytesToAddress(entry.Address)
			eth.blockchain.RemoveNEVMAddress(batch, addr)
		}
	}

	eth.blockchain.DeleteSYSHash(batch, currentNumber)
	eth.blockchain.DeleteDataHashes(batch, currentNumber)

	if err := batch.Write(); err != nil {
		log.Crit("Failed to write NEVM batch during block disconnect", "err", err)
	}

	return nil
}
// SYSCOIN start networking sync once we start inserting chain meaning we are likely finished with IBD
func (eth *Ethereum) networkingLoop() {
	defer eth.wg.Done()

	sub := eth.eventMux.Subscribe(downloader.StartNetworkEvent{})
	defer sub.Unsubscribe()

	for {
		select {
		case <-eth.closeHandler:
			return

		case event, ok := <-sub.Chan():
			if !ok {
				// Subscription was closed, exit the loop
				return
			}
			if event == nil {
				continue
			}
			switch event.Data.(type) {
			case downloader.StartNetworkEvent:
				log.Info("Received StartNetworkEvent, waiting for block arrival to finish (5 seconds of inactivity)...")
				if eth.waitForSyncCompletion() {
					log.Info("5 seconds passed without new blocks. Starting network...")
					eth.handler.peers.SetOpen()
					if err := eth.p2pServer.Start(); err != nil {
						log.Error("Error starting p2pServer", "err", err)
					}
					eth.handler.Start(eth.p2pServer.MaxPeers)
					eth.Downloader().DoneEvent()
					eth.handler.synced.Store(true)
				}
				return
			}
		}
	}
}

// Waits until no new blocks arrive for 5 consecutive seconds
func (eth *Ethereum) waitForSyncCompletion() bool {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-eth.closeHandler:
			return false
		case <-ticker.C:
			eth.lock.Lock()
			elapsed := time.Now().Unix() - eth.timeLastBlock
			eth.lock.Unlock()

			if elapsed >= 5 {
				return true
			}
		}
	}
}

// APIs return the collection of RPC services the ethereum package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *Ethereum) APIs() []rpc.API {
	apis := ethapi.GetAPIs(s.APIBackend)

	// Append any APIs exposed explicitly by the consensus engine
	apis = append(apis, s.engine.APIs(s.BlockChain())...)

	// Append all the local APIs and return
	return append(apis, []rpc.API{
		{
			Namespace: "miner",
			Service:   NewMinerAPI(s),
		}, {
			Namespace: "eth",
			Service:   downloader.NewDownloaderAPI(s.handler.downloader, s.blockchain, s.eventMux),
		}, {
			Namespace: "admin",
			Service:   NewAdminAPI(s),
		}, {
			Namespace: "debug",
			Service:   NewDebugAPI(s),
		}, {
			Namespace: "net",
			Service:   s.netRPCService,
		},
	}...)
}

func (s *Ethereum) ResetWithGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *Ethereum) Miner() *miner.Miner { return s.miner }

func (s *Ethereum) AccountManager() *accounts.Manager  { return s.accountManager }
func (s *Ethereum) BlockChain() *core.BlockChain       { return s.blockchain }
func (s *Ethereum) TxPool() *txpool.TxPool             { return s.txPool }
func (s *Ethereum) Engine() consensus.Engine           { return s.engine }
func (s *Ethereum) ChainDb() ethdb.Database            { return s.chainDb }
func (s *Ethereum) IsListening() bool                  { return true } // Always listening
func (s *Ethereum) Downloader() *downloader.Downloader { return s.handler.downloader }
func (s *Ethereum) Synced() bool                       { return s.handler.synced.Load() }
func (s *Ethereum) SetSynced()                         { s.handler.enableSyncedFeatures() }
func (s *Ethereum) ArchiveMode() bool                  { return s.config.NoPruning }

// Protocols returns all the currently configured
// network protocols to start.
func (s *Ethereum) Protocols() []p2p.Protocol {
	protos := eth.MakeProtocols((*ethHandler)(s.handler), s.networkID, s.discmix)
	if s.config.SnapshotCache > 0 {
		protos = append(protos, snap.MakeProtocols((*snapHandler)(s.handler))...)
	}
	return protos
}

// Start implements node.Lifecycle, starting all internal goroutines needed by the
// Ethereum protocol implementation.
func (s *Ethereum) Start() error {
	if err := s.setupDiscovery(); err != nil {
		return err
	}

	// Regularly update shutdown marker
	s.shutdownTracker.Start()
	if s.blockchain.GetChainConfig().SyscoinBlock != nil {
		log.Info("SYSCOIN mode active: skipping Ethereum networking and peers")

		// Explicitly mark peers closed BEFORE calling any handler methods:
		s.handler.peers.SetClosed()
		s.p2pServer.Stop()

		// Don't call s.handler.Start(), as it will try to sync peers
		// instead, manually start minimal required handlers:
		go s.zmqRep.InitZMQListener()

	} else {
		// Normal Ethereum networking startup
		s.handler.Start(s.p2pServer.MaxPeers)
	}
	// start log indexer
	s.filterMaps.Start()
	go s.updateFilterMapsHeads()
	return nil
}

func (s *Ethereum) newChainView(head *types.Header) *filtermaps.ChainView {
	if head == nil {
		return nil
	}
	return filtermaps.NewChainView(s.blockchain, head.Number.Uint64(), head.Hash())
}

func (s *Ethereum) updateFilterMapsHeads() {
	headEventCh := make(chan core.ChainEvent, 10)
	blockProcCh := make(chan bool, 10)
	sub := s.blockchain.SubscribeChainEvent(headEventCh)
	sub2 := s.blockchain.SubscribeBlockProcessingEvent(blockProcCh)
	defer func() {
		sub.Unsubscribe()
		sub2.Unsubscribe()
		for {
			select {
			case <-headEventCh:
			case <-blockProcCh:
			default:
				return
			}
		}
	}()

	var head *types.Header
	setHead := func(newHead *types.Header) {
		if newHead == nil {
			return
		}
		if head == nil || newHead.Hash() != head.Hash() {
			head = newHead
			chainView := s.newChainView(head)
			historyCutoff, _ := s.blockchain.HistoryPruningCutoff()
			var finalBlock uint64
			if fb := s.blockchain.CurrentFinalBlock(); fb != nil {
				finalBlock = fb.Number.Uint64()
			}
			s.filterMaps.SetTarget(chainView, historyCutoff, finalBlock)
		}
	}
	setHead(s.blockchain.CurrentBlock())

	for {
		select {
		case ev := <-headEventCh:
			setHead(ev.Header)
		case blockProc := <-blockProcCh:
			s.filterMaps.SetBlockProcessing(blockProc)
		case <-time.After(time.Second * 10):
			setHead(s.blockchain.CurrentBlock())
		case ch := <-s.closeFilterMaps:
			close(ch)
			return
		}
	}
}

func (s *Ethereum) setupDiscovery() error {
	eth.StartENRUpdater(s.blockchain, s.p2pServer.LocalNode())

	// Add eth nodes from DNS.
	dnsclient := dnsdisc.NewClient(dnsdisc.Config{})
	if len(s.config.EthDiscoveryURLs) > 0 {
		iter, err := dnsclient.NewIterator(s.config.EthDiscoveryURLs...)
		if err != nil {
			return err
		}
		s.discmix.AddSource(iter)
	}

	// Add snap nodes from DNS.
	if len(s.config.SnapDiscoveryURLs) > 0 {
		iter, err := dnsclient.NewIterator(s.config.SnapDiscoveryURLs...)
		if err != nil {
			return err
		}
		s.discmix.AddSource(iter)
	}

	// Add DHT nodes from discv5.
	if s.p2pServer.DiscoveryV5() != nil {
		filter := eth.NewNodeFilter(s.blockchain)
		iter := enode.Filter(s.p2pServer.DiscoveryV5().RandomNodes(), filter)
		s.discmix.AddSource(iter)
	}

	return nil
}

// Stop implements node.Lifecycle, terminating all internal goroutines used by the
// Ethereum protocol.
func (s *Ethereum) Stop() error {
	// SYSCOIN
    // Flush buffered blocks first
    if err := s.flushBufferedBlocks(); err != nil {
        log.Error("Failed to flush buffered blocks on shutdown", "err", err)
    }
	// Stop all the peer-related stuff first.
	s.discmix.Close()
	s.handler.Stop()

	// Then stop everything else.
	ch := make(chan struct{})
	s.closeFilterMaps <- ch
	<-ch
	s.filterMaps.Stop()
	s.txPool.Close()
	s.blockchain.Stop()
	s.engine.Close()

	// Clean shutdown marker as the last thing before closing db
	s.shutdownTracker.Stop()

	s.chainDb.Close()
	s.eventMux.Stop()
	// SYSCOIN
	s.wg.Wait()
	s.wgNEVM.Wait()
	if s.zmqRep != nil {
		s.zmqRep.Close()
	}
	if s.closeHandler != nil {
		close(s.closeHandler)
	}
	return nil
}

// SYSCOIN
func (s *Ethereum) Shutdown() {
    log.Info("Ethereum shutdown explicitly requested via ZMQ...")

    go func() {
        if err := s.stack.Close(); err != nil {
            log.Error("Node stack Close error", "err", err)
        } else {
            log.Info("Node stack closed gracefully.")
        }

        s.stack.Wait()
        log.Info("Node stack shutdown completed successfully.")
    }()
}

// SyncMode retrieves the current sync mode, either explicitly set, or derived
// from the chain status.
func (s *Ethereum) SyncMode() ethconfig.SyncMode {
	// If we're in snap sync mode, return that directly
	if s.handler.snapSync.Load() {
		return ethconfig.SnapSync
	}
	// We are probably in full sync, but we might have rewound to before the
	// snap sync pivot, check if we should re-enable snap sync.
	head := s.blockchain.CurrentBlock()
	if pivot := rawdb.ReadLastPivotNumber(s.chainDb); pivot != nil {
		if head.Number.Uint64() < *pivot {
			return ethconfig.SnapSync
		}
	}
	// We are in a full sync, but the associated head state is missing. To complete
	// the head state, forcefully rerun the snap sync. Note it doesn't mean the
	// persistent state is corrupted, just mismatch with the head block.
	if !s.blockchain.HasState(head.Root) {
		log.Info("Reenabled snap sync as chain is stateless")
		return ethconfig.SnapSync
	}
	// Nope, we're really full syncing
	return ethconfig.FullSync
}
