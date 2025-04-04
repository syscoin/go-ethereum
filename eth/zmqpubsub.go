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
	NEVMPubEP   string
	eth         *Ethereum
	rep         zmq4.Socket
	inited      bool
	ctx         context.Context
	cancel      context.CancelFunc
}

func (zmq *ZMQRep) Close() {
    if !zmq.inited {
        return
    }
    zmq.inited = false

    zmq.cancel()

    if err := zmq.rep.Close(); err != nil {
        log.Error("ZMQ socket close error", "err", err)
    } else {
        log.Info("ZMQ socket closed successfully")
    }
}


func (zmq *ZMQRep) InitZMQListener() error {
	err := zmq.rep.Listen(zmq.NEVMPubEP)
	if err != nil {
		log.Error("could not listen on NEVM REP point", "endpoint", zmq.NEVMPubEP, "err", err)
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
						go zmq.eth.Shutdown()
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
						err = zmq.eth.AddBlock(&nevmBlockConnect)
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
						err = zmq.eth.DeleteBlock(&nevmBlockDisconnect)
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
				
					block := zmq.eth.CreateBlock()
					if block == nil {
						log.Error("createBlockSub", "err", "block is nil")
						nevmBlockConnectBytes = []byte{} // Explicitly empty to signal error clearly
					} else {
						var nevmBlockConnect types.NEVMBlockConnect
						var err error
						nevmBlockConnectBytes, err = nevmBlockConnect.Serialize(block)
						if err != nil {
							log.Error("createBlockSub Serialize failed", "err", err)
							nevmBlockConnectBytes = []byte{} // explicitly empty if serialization fails
						}
					}
				
					msgSend := zmq4.NewMsgFrom([]byte("nevmblock"), nevmBlockConnectBytes)
					if err := zmq.rep.SendMulti(msgSend); err != nil {
						log.Error("ZMQ send error", "topic", strTopic, "err", err)
					}
				
					// explicitly clear bytes after send (optional, helps GC)
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

func NewZMQRep(stackIn *node.Node, ethIn *Ethereum, NEVMPubEPIn string) *ZMQRep {
	ctx, cancel := context.WithCancel(context.Background())
	zmq := &ZMQRep{
		NEVMPubEP:       NEVMPubEPIn,
		eth:         ethIn,
		rep:         zmq4.NewRep(ctx),
		ctx:         ctx,
		cancel:      cancel,
	}
	log.Info("zmq Init")
	return zmq
}

