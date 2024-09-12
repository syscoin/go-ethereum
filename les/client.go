// Copyright 2019 The go-ethereum Authors
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

// Package les implements the Light Ethereum Subprotocol.
package les

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/bloombits"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/eth/gasprice"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/internal/shutdowncheck"
	"github.com/ethereum/go-ethereum/les/vflux"
	vfc "github.com/ethereum/go-ethereum/les/vflux/client"
	"github.com/ethereum/go-ethereum/light"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	// SYSCOIN
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/trie"
)

// SYSCOIN
type LightNEVMAddBlockFn func(*types.NEVMBlockConnect, *LightEthereum) error
type LightNEVMDeleteBlockFn func(*types.NEVMBlockDisconnect, *LightEthereum) error

type LightNEVMIndex struct {
	// Callbacks
	AddBlock    LightNEVMAddBlockFn    // Connects a new NEVM block
	DeleteBlock LightNEVMDeleteBlockFn // Disconnects NEVM tip
}
type LightEthereum struct {
	lesCommons

	peers              *serverPeerSet
	reqDist            *requestDistributor
	retriever          *retrieveManager
	odr                *LesOdr
	relay              *lesTxRelay
	handler            *clientHandler
	txPool             *light.TxPool
	blockchain         *light.LightChain
	serverPool         *vfc.ServerPool
	serverPoolIterator enode.Iterator
	merger             *consensus.Merger

	bloomRequests chan chan *bloombits.Retrieval // Channel receiving bloom data retrieval requests
	bloomIndexer  *core.ChainIndexer             // Bloom indexer operating during block imports

	ApiBackend     *LesApiBackend
	eventMux       *event.TypeMux
	engine         consensus.Engine
	accountManager *accounts.Manager
	netRPCService  *ethapi.NetAPI

	p2pServer  *p2p.Server
	p2pConfig  *p2p.Config
	udpEnabled bool
	// SYSCOIN
	zmqRep        *ZMQRep
	timeLastBlock int64
	lock          sync.RWMutex

	shutdownTracker *shutdowncheck.ShutdownTracker // Tracks if and when the node has shutdown ungracefully
}
// New creates an instance of the light client.
func New(stack *node.Node, config *ethconfig.Config) (*LightEthereum, error) {
	chainDb, err := stack.OpenDatabase("lightchaindata", config.DatabaseCache, config.DatabaseHandles, "eth/db/chaindata/", false)
	if err != nil {
		return nil, err
	}
	lesDb, err := stack.OpenDatabase("les.client", 0, 0, "eth/db/lesclient/", false)
	if err != nil {
		return nil, err
	}
	var overrides core.ChainOverrides
	if config.OverrideCancun != nil {
		overrides.OverrideCancun = config.OverrideCancun
	}
	if config.OverrideVerkle != nil {
		overrides.OverrideVerkle = config.OverrideVerkle
	}
	triedb := trie.NewDatabase(chainDb, trie.HashDefaults)
	chainConfig, genesisHash, genesisErr := core.SetupGenesisBlockWithOverride(chainDb, triedb, config.Genesis, &overrides)
	if _, isCompat := genesisErr.(*params.ConfigCompatError); genesisErr != nil && !isCompat {
		return nil, genesisErr
	}
	log.Info("")
	log.Info(strings.Repeat("-", 153))
	for _, line := range strings.Split(chainConfig.Description(), "\n") {
		log.Info(line)
	}
	log.Info(strings.Repeat("-", 153))
	log.Info("")

	peers := newServerPeerSet()
	merger := consensus.NewMerger(chainDb)
	leth := &LightEthereum{
		lesCommons: lesCommons{
			genesis:     genesisHash,
			config:      config,
			chainConfig: chainConfig,
			iConfig:     light.DefaultClientIndexerConfig,
			chainDb:     chainDb,
			lesDb:       lesDb,
			closeCh:     make(chan struct{}),
		},
		peers:           peers,
		eventMux:        stack.EventMux(),
		reqDist:         newRequestDistributor(peers, &mclock.System{}),
		accountManager:  stack.AccountManager(),
		merger:          merger,
		// SYSCOIN
		engine:          ethconfig.CreateConsensusEngine(stack, &config.Ethash, chainConfig.ChainID, chainConfig.Clique, nil, false, chainDb),
		bloomRequests:   make(chan chan *bloombits.Retrieval),
		bloomIndexer:    core.NewBloomIndexer(chainDb, params.BloomBitsBlocksClient, params.HelperTrieConfirmations),
		p2pServer:       stack.Server(),
		p2pConfig:       &stack.Config().P2P,
		udpEnabled:      stack.Config().P2P.DiscoveryV5,
		shutdownTracker: shutdowncheck.NewShutdownTracker(chainDb),
	}

	var prenegQuery vfc.QueryFunc
	if leth.udpEnabled {
		prenegQuery = leth.prenegQuery
	}
	leth.serverPool, leth.serverPoolIterator = vfc.NewServerPool(lesDb, []byte("serverpool:"), time.Second, prenegQuery, &mclock.System{}, nil, requestList)
	leth.serverPool.AddMetrics(suggestedTimeoutGauge, totalValueGauge, serverSelectableGauge, serverConnectedGauge, sessionValueMeter, serverDialedMeter)

	leth.retriever = newRetrieveManager(peers, leth.reqDist, leth.serverPool.GetTimeout)
	leth.relay = newLesTxRelay(peers, leth.retriever)

	leth.odr = NewLesOdr(chainDb, light.DefaultClientIndexerConfig, leth.peers, leth.retriever)
	leth.chtIndexer = light.NewChtIndexer(chainDb, leth.odr, params.CHTFrequency, params.HelperTrieConfirmations, config.LightNoPrune)
	leth.bloomTrieIndexer = light.NewBloomTrieIndexer(chainDb, leth.odr, params.BloomBitsBlocksClient, params.BloomTrieFrequency, config.LightNoPrune)
	leth.odr.SetIndexers(leth.chtIndexer, leth.bloomTrieIndexer, leth.bloomIndexer)

	// Note: NewLightChain adds the trusted checkpoint so it needs an ODR with
	// indexers already set but not started yet
	if leth.blockchain, err = light.NewLightChain(leth.odr, leth.chainConfig, leth.engine); err != nil {
		return nil, err
	}
	leth.chainReader = leth.blockchain
	leth.txPool = light.NewTxPool(leth.chainConfig, leth.blockchain, leth.relay)

	// Note: AddChildIndexer starts the update process for the child
	leth.bloomIndexer.AddChildIndexer(leth.bloomTrieIndexer)
	leth.chtIndexer.Start(leth.blockchain)
	leth.bloomIndexer.Start(leth.blockchain)

	// Rewind the chain in case of an incompatible config upgrade.
	if compat, ok := genesisErr.(*params.ConfigCompatError); ok {
		log.Warn("Rewinding chain to upgrade configuration", "err", compat)
		if compat.RewindToTime > 0 {
			leth.blockchain.SetHeadWithTimestamp(compat.RewindToTime)
		} else {
			leth.blockchain.SetHead(compat.RewindToBlock)
		}
		rawdb.WriteChainConfig(chainDb, genesisHash, chainConfig)
	}

	leth.ApiBackend = &LesApiBackend{stack.Config().ExtRPCEnabled(), stack.Config().AllowUnprotectedTxs, leth, nil}
	gpoParams := config.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = config.Miner.GasPrice
	}
	leth.ApiBackend.gpo = gasprice.NewOracle(leth.ApiBackend, gpoParams)

	leth.handler = newClientHandler(leth)
	leth.netRPCService = ethapi.NewNetAPI(leth.p2pServer, leth.config.NetworkId)

	// Register the backend on the node
	stack.RegisterAPIs(leth.APIs())
	stack.RegisterProtocols(leth.Protocols())
	stack.RegisterLifecycle(leth)

	// Successful startup; push a marker and check previous unclean shutdowns.
	leth.shutdownTracker.MarkStartup()
	// SYSCOIN
	addBlock := func(nevmBlockConnect *types.NEVMBlockConnect, eth *LightEthereum) error {
		if nevmBlockConnect == nil {
			return errors.New("addBlock: Empty block")
		}
		currentHeader := eth.blockchain.CurrentHeader()
		currentNumber := currentHeader.Number.Uint64()
		currentHash := currentHeader.Hash()
		proposedBlockNumber := nevmBlockConnect.Block.NumberU64()
		proposedBlockParentHash := nevmBlockConnect.Block.ParentHash()
		proposedBlockHash := nevmBlockConnect.Block.Hash()
		if nevmBlockConnect.Block == nil {
			return errors.New("addBlock: empty block")
		}
		if currentNumber > 0 {
			if (proposedBlockNumber != (currentNumber + 1)) || (proposedBlockParentHash != currentHash) {
				log.Error("Non contiguous block insert", "number", proposedBlockNumber, "hash", proposedBlockHash,
					"parent", proposedBlockParentHash, "prevnumber", currentNumber, "prevhash", currentHash)
				return errors.New("addBlock: Non contiguous block insert")
			}
		}
		eth.blockchain.NevmBlockConnect = nevmBlockConnect
		_, err = eth.blockchain.InsertHeaderChain([]*types.Header{nevmBlockConnect.Block.Header()}, 0)
		if err != nil {
			return err
		}
		if eth.peers.closed {
			eth.lock.Lock()
			eth.timeLastBlock = time.Now().Unix()
			eth.lock.Unlock()
		}
		return nil
	}
	go func(eth *LightEthereum) {
		sub := eth.eventMux.Subscribe(StartNetworkEvent{})
		defer sub.Unsubscribe()
		for {
			event := <-sub.Chan()
			if event == nil {
				continue
			}
			switch event.Data.(type) {
			case StartNetworkEvent:
				eth.lock.Lock()
				eth.timeLastBlock = time.Now().Unix()
				eth.lock.Unlock()
				log.Info("Attempt to start networking/peering...")
				for {
					time.Sleep(100 * time.Millisecond)
					eth.lock.Lock()
					// ensure 5 seconds has passed between blocks before we start peering so we are sure sync has finished
					if time.Now().Unix()-eth.timeLastBlock >= 5 {
						log.Info("Networking and peering start...")
						eth.udpEnabled = true
						eth.peers.open()
						eth.p2pServer.Start()
						eth.DoneEvent()
						eth.lock.Unlock()
						return
					}
					eth.lock.Unlock()
				}
			}
		}
	}(leth)

	deleteBlock := func(nevmBlockDisconnect *types.NEVMBlockDisconnect, eth *LightEthereum) error {
		current := eth.blockchain.CurrentHeader()
		currentNumber := current.Number.Uint64()
		if currentNumber == 0 {
			log.Warn("Trying to disconnect block 0")
			return nil
		}
		if current.ParentHash == (common.Hash{}) {
			return errors.New("deleteBlock: NEVM tip parent block not found")
		}
		err := leth.blockchain.SetHead(currentNumber - 1)
		if err != nil {
			return err
		}
		if eth.blockchain.CurrentHeader().Number.Uint64() != (currentNumber - 1) {
			return errors.New("deleteBlock: Block number post-write does not match")
		}
		batch := eth.chainDb.NewBatch()
		// Update the NEVM address mappings based on the block's diff
		hasDiff := nevmBlockDisconnect.HasDiff()
		if hasDiff {
			// Retrieve the current NEVM address mappings from the database
			mapping := eth.blockchain.ReadNEVMAddressMapping()
			for _, entry := range nevmBlockDisconnect.Diff.AddedMNNEVM {
				mapping.AddNEVMAddress(common.BytesToAddress(entry.Address), entry.CollateralHeight)
			}
			for _, entry := range nevmBlockDisconnect.Diff.UpdatedMNNEVM {
				mapping.UpdateNEVMAddress(common.BytesToAddress(entry.OldAddress), common.BytesToAddress(entry.NewAddress))
			}
			for _, entry := range nevmBlockDisconnect.Diff.RemovedMNNEVM {
				mapping.RemoveNEVMAddress(common.BytesToAddress(entry.Address))
			}
		
			// Persist the updated NEVM address mappings to the database
			eth.blockchain.WriteNEVMAddressMapping(batch, mapping)
		}
		eth.blockchain.DeleteNEVMMapping(batch, current.Hash())
		eth.blockchain.DeleteSYSHash(batch, currentNumber)
		eth.blockchain.DeleteDataHashes(batch, currentNumber)
		return nil
	}
	if config.Ethash.PowMode == ethash.ModeNEVM {
		leth.zmqRep = NewZMQRep(stack, leth, config.NEVMPubEP, LightNEVMIndex{addBlock, deleteBlock})
	}
	return leth, nil
}
// SYSCOIN
type DoneEvent struct {
	Latest *types.Header
}
type StartNetworkEvent struct{}
func (s *LightEthereum) DoneEvent() {
	latest := s.blockchain.CurrentHeader()
	s.eventMux.Post(DoneEvent{latest})
}
func (s *LightEthereum) StartNetworkEvent() {
	s.eventMux.Post(StartNetworkEvent{})
}
// VfluxRequest sends a batch of requests to the given node through discv5 UDP TalkRequest and returns the responses
func (s *LightEthereum) VfluxRequest(n *enode.Node, reqs vflux.Requests) vflux.Replies {
	if !s.udpEnabled {
		return nil
	}
	reqsEnc, _ := rlp.EncodeToBytes(&reqs)
	repliesEnc, _ := s.p2pServer.DiscV5.TalkRequest(s.serverPool.DialNode(n), "vfx", reqsEnc)
	var replies vflux.Replies
	if len(repliesEnc) == 0 || rlp.DecodeBytes(repliesEnc, &replies) != nil {
		return nil
	}
	return replies
}

// vfxVersion returns the version number of the "les" service subdomain of the vflux UDP
// service, as advertised in the ENR record
func (s *LightEthereum) vfxVersion(n *enode.Node) uint {
	if n.Seq() == 0 {
		var err error
		if !s.udpEnabled {
			return 0
		}
		if n, err = s.p2pServer.DiscV5.RequestENR(n); n != nil && err == nil && n.Seq() != 0 {
			s.serverPool.Persist(n)
		} else {
			return 0
		}
	}

	var les []rlp.RawValue
	if err := n.Load(enr.WithEntry("les", &les)); err != nil || len(les) < 1 {
		return 0
	}
	var version uint
	rlp.DecodeBytes(les[0], &version) // Ignore additional fields (for forward compatibility).
	return version
}

// prenegQuery sends a capacity query to the given server node to determine whether
// a connection slot is immediately available
func (s *LightEthereum) prenegQuery(n *enode.Node) int {
	if s.vfxVersion(n) < 1 {
		// UDP query not supported, always try TCP connection
		return 1
	}

	var requests vflux.Requests
	requests.Add("les", vflux.CapacityQueryName, vflux.CapacityQueryReq{
		Bias:      180,
		AddTokens: []vflux.IntOrInf{{}},
	})
	replies := s.VfluxRequest(n, requests)
	var cqr vflux.CapacityQueryReply
	if replies.Get(0, &cqr) != nil || len(cqr) != 1 { // Note: Get returns an error if replies is nil
		return -1
	}
	if cqr[0] > 0 {
		return 1
	}
	return 0
}

type LightDummyAPI struct{}

// Etherbase is the address that mining rewards will be sent to
func (s *LightDummyAPI) Etherbase() (common.Address, error) {
	return common.Address{}, errors.New("mining is not supported in light mode")
}

// Coinbase is the address that mining rewards will be sent to (alias for Etherbase)
func (s *LightDummyAPI) Coinbase() (common.Address, error) {
	return common.Address{}, errors.New("mining is not supported in light mode")
}

// Hashrate returns the POW hashrate
func (s *LightDummyAPI) Hashrate() hexutil.Uint {
	return 0
}

// Mining returns an indication if this node is currently mining.
func (s *LightDummyAPI) Mining() bool {
	return false
}

// APIs returns the collection of RPC services the ethereum package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *LightEthereum) APIs() []rpc.API {
	apis := ethapi.GetAPIs(s.ApiBackend)
	apis = append(apis, s.engine.APIs(s.BlockChain().HeaderChain())...)
	return append(apis, []rpc.API{
		{
			Namespace: "eth",
			Service:   &LightDummyAPI{},
		}, {
			Namespace: "net",
			Service:   s.netRPCService,
		}, {
			Namespace: "vflux",
			Service:   s.serverPool.API(),
		},
	}...)
}

func (s *LightEthereum) ResetWithGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *LightEthereum) BlockChain() *light.LightChain { return s.blockchain }
func (s *LightEthereum) TxPool() *light.TxPool         { return s.txPool }
func (s *LightEthereum) Engine() consensus.Engine      { return s.engine }
func (s *LightEthereum) LesVersion() int               { return int(ClientProtocolVersions[0]) }
func (s *LightEthereum) EventMux() *event.TypeMux      { return s.eventMux }
func (s *LightEthereum) Merger() *consensus.Merger     { return s.merger }

// Protocols returns all the currently configured network protocols to start.
func (s *LightEthereum) Protocols() []p2p.Protocol {
	return s.makeProtocols(ClientProtocolVersions, s.handler.runPeer, func(id enode.ID) interface{} {
		if p := s.peers.peer(id.String()); p != nil {
			return p.Info()
		}
		return nil
	}, s.serverPoolIterator)
}

// Start implements node.Lifecycle, starting all internal goroutines needed by the
// light ethereum protocol implementation.
func (s *LightEthereum) Start() error {
	log.Warn("Light client mode is an experimental feature")

	// Regularly update shutdown marker
	s.shutdownTracker.Start()

	if s.udpEnabled && s.p2pServer.DiscV5 == nil {
		s.udpEnabled = false
		log.Error("Discovery v5 is not initialized")
	}
	discovery, err := s.setupDiscovery()
	if err != nil {
		return err
	}
	s.serverPool.AddSource(discovery)
	s.serverPool.Start()
	// Start bloom request workers.
	s.wg.Add(bloomServiceThreads)
	s.startBloomHandlers(params.BloomBitsBlocksClient)
	// SYSCOIN
	if s.lesCommons.config.Ethash.PowMode == ethash.ModeNEVM {
		log.Info("Skip networking start...")
		s.udpEnabled = false
		s.p2pServer.Stop()
		s.peers.close()
	}

	return nil
}

// Stop implements node.Lifecycle, terminating all internal goroutines used by the
// Ethereum protocol.
func (s *LightEthereum) Stop() error {
	close(s.closeCh)
	s.serverPool.Stop()
	s.peers.close()
	s.reqDist.close()
	s.odr.Stop()
	s.relay.Stop()
	s.bloomIndexer.Close()
	s.chtIndexer.Close()
	s.blockchain.Stop()
	s.handler.stop()
	s.txPool.Stop()
	s.engine.Close()
	s.eventMux.Stop()
	// Clean shutdown marker as the last thing before closing db
	s.shutdownTracker.Stop()

	s.chainDb.Close()
	s.lesDb.Close()
	s.wg.Wait()
	// SYSCOIN
	if s.zmqRep != nil {
		s.zmqRep.Close()
	}
	log.Info("Light ethereum stopped")
	return nil
}
