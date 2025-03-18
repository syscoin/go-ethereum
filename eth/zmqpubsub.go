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

// Package core implements the Ethereum consensus protocol.
package eth

import (
	"context"
	"strconv"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/go-zeromq/zmq4"
)

type ZMQRep struct {
	stack       *node.Node
	eth         *Ethereum
	rep         zmq4.Socket
	nevmIndexer NEVMIndex
	inited      bool
	ctx         context.Context
	cancel      context.CancelFunc
}
// Close is idempotent
func (zmq *ZMQRep) Close() {
	if !zmq.inited {
		return
	}

	zmq.cancel()

	if err := zmq.rep.Close(); err != nil {
		log.Error("ZMQ socket close error", "err", err)
	} else {
		log.Info("ZMQ socket closed successfully")
	}

	zmq.inited = false
}


func (zmq *ZMQRep) Init(nevmEP string) error {
	err := zmq.rep.Listen(nevmEP)
	if err != nil {
		log.Error("could not listen on NEVM REP point", "endpoint", nevmEP, "err", err)
		return err
	}
	go func(zmq *ZMQRep) {
		for {
			select {
			case <-zmq.ctx.Done():
				log.Info("ZMQ listener stopped due to context cancellation")
				return
			default:
				msg, err := zmq.rep.Recv()
				if err != nil {
					if zmq.ctx.Err() != nil {
						log.Info("ZMQ context cancelled, exiting loop")
						return
					}
					log.Error("ZMQ receive error", "err", err)
					continue
				}
				if len(msg.Frames) != 2 {
					log.Error("Invalid number of message frames", "len", len(msg.Frames))
					continue
				}
				strTopic := string(msg.Frames[0])
				if strTopic == "nevmcomms" {
					if string(msg.Frames[1]) == "\ndisconnect" {
						log.Info("ZMQ: exiting...")
						if zmq.stack != nil {
							go func() {
								if err := zmq.stack.Close(); err != nil {
									log.Error("Stack close error", "err", err)
								} else {
									log.Info("Stack closed gracefully")
								}
								zmq.stack.Wait()
								log.Info("Stack shutdown completed successfully")
							}()
						} else {
							log.Error("ZMQ: STACK EMPTY...")
						}
						zmq.Close()
						return
					}
					if string(msg.Frames[1]) == "\fstartnetwork" {
						zmq.eth.Downloader().StartNetworkEvent()
					}
					msgSend := zmq4.NewMsgFrom([]byte("nevmcomms"), []byte("ack"))
					if err := zmq.rep.SendMulti(msgSend); err != nil {
						log.Error("ZMQ send error", "topic", strTopic, "err", err)
					}					
				} else if strTopic == "nevmconnect" {
					result := "connected"
					var nevmBlockConnect types.NEVMBlockConnect
					err = nevmBlockConnect.Deserialize(msg.Frames[1])
					if err != nil {
						log.Error("addBlockSub Deserialize", "err", err)
						result = err.Error()
					} else {
						err = zmq.nevmIndexer.AddBlock(&nevmBlockConnect, zmq.eth)
						if err != nil {
							log.Error("addBlockSub AddBlock", "err", err)
							result = err.Error()
						}
					}
					msgSend := zmq4.NewMsgFrom([]byte("nevmconnect"), []byte(result))
					if err := zmq.rep.SendMulti(msgSend); err != nil {
						log.Error("ZMQ send error", "topic", strTopic, "err", err)
					}					
				} else if strTopic == "nevmdisconnect" {
					result := "disconnected"
					var nevmBlockDisconnect types.NEVMBlockDisconnect
					err = nevmBlockDisconnect.Deserialize(msg.Frames[1])
					if err != nil {
						log.Error("deleteBlockSub Deserialize", "err", err)
						result = err.Error()
					} else {
						err = zmq.nevmIndexer.DeleteBlock(&nevmBlockDisconnect, zmq.eth)
						if err != nil {
							log.Error("deleteBlockSub DeleteBlock", "err", err)
							result = err.Error()
						}
					}
					msgSend := zmq4.NewMsgFrom([]byte("nevmdisconnect"), []byte(result))
					if err := zmq.rep.SendMulti(msgSend); err != nil {
						log.Error("ZMQ send error", "topic", strTopic, "err", err)
					}	
				} else if strTopic == "nevmblock" {
					var nevmBlockConnectBytes []byte
					block := zmq.nevmIndexer.CreateBlock(zmq.eth)
					if block != nil {
						var NEVMBlockConnect types.NEVMBlockConnect
						nevmBlockConnectBytes, err = NEVMBlockConnect.Serialize(block)
						if err != nil {
							log.Error("createBlockSub", "err", err)
							nevmBlockConnectBytes = make([]byte, 0)
						}
					}
					msgSend := zmq4.NewMsgFrom([]byte("nevmblock"), nevmBlockConnectBytes)
					if err := zmq.rep.SendMulti(msgSend); err != nil {
						log.Error("ZMQ send error", "topic", strTopic, "err", err)
					}	
					nevmBlockConnectBytes = nil
				} else if strTopic == "nevmblockinfo" {
					str := strconv.FormatUint(zmq.eth.blockchain.CurrentBlock().Number.Uint64(), 10)
					msgSend := zmq4.NewMsgFrom([]byte("nevmblockinfo"), []byte(str))
					if err := zmq.rep.SendMulti(msgSend); err != nil {
						log.Error("ZMQ send error", "topic", strTopic, "err", err)
					}	
				}
			}
		}
	}(zmq)
	zmq.inited = true
	return nil
}

func NewZMQRep(stackIn *node.Node, ethIn *Ethereum, NEVMPubEP string, nevmIndexerIn NEVMIndex) *ZMQRep {
	ctx, cancel := context.WithCancel(context.Background())
	zmq := &ZMQRep{
		stack:       stackIn,
		eth:         ethIn,
		rep:         zmq4.NewRep(ctx),
		nevmIndexer: nevmIndexerIn,
		ctx:         ctx,
		cancel:      cancel,
	}
	log.Info("zmq Init")
	zmq.Init(NEVMPubEP)
	return zmq
}

