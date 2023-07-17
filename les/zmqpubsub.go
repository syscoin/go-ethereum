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
package les

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
	eth         *LightEthereum
	rep         zmq4.Socket
	nevmIndexer LightNEVMIndex
	inited      bool
}

func (zmq *ZMQRep) Close() {
	if !zmq.inited {
		return
	}
	zmq.rep.Close()
	log.Error("ZMQ socket closed")
}

func (zmq *ZMQRep) Init(nevmEP string) error {
	err := zmq.rep.Listen(nevmEP)
	if err != nil {
		log.Error("could not listen on NEVM REP point", "endpoint", nevmEP, "err", err)
		return err
	}
	go func(zmq *ZMQRep) {
		for {
			msg, err := zmq.rep.Recv()
			if err != nil {
				if err.Error() == "context canceled" {
					return
				}
				log.Error("ZMQ: could not receive message", "err", err)
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
					zmq.stack.Close()
					return
				}
				if string(msg.Frames[1]) == "\fstartnetwork" {
					zmq.eth.StartNetworkEvent()
				}
				msgSend := zmq4.NewMsgFrom([]byte("nevmcomms"), []byte("ack"))
				zmq.rep.SendMulti(msgSend)
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
				zmq.rep.SendMulti(msgSend)
			} else if strTopic == "nevmdisconnect" {
				result := "disconnected"
				err := zmq.nevmIndexer.DeleteBlock(string(msg.Frames[1]), zmq.eth)
				if err != nil {
					log.Error("deleteBlockSub", "err", err)
					result = err.Error()
				}
				msgSend := zmq4.NewMsgFrom([]byte("nevmdisconnect"), []byte(result))
				zmq.rep.SendMulti(msgSend)
			} else if strTopic == "nevmblock" {
				nevmBlockConnectBytes := make([]byte, 0)
				msgSend := zmq4.NewMsgFrom([]byte("nevmblock"), nevmBlockConnectBytes)
				zmq.rep.SendMulti(msgSend)
				nevmBlockConnectBytes = nil
			} else if strTopic == "nevmblockinfo" {
				str := strconv.FormatUint(zmq.eth.blockchain.CurrentHeader().Number.Uint64(), 10)
				msgSend := zmq4.NewMsgFrom([]byte("nevmblockinfo"), []byte(str))
				zmq.rep.SendMulti(msgSend)
			}
		}
	}(zmq)
	zmq.inited = true
	return nil
}

func NewZMQRep(stackIn *node.Node, ethIn *LightEthereum, NEVMPubEP string, nevmIndexerIn LightNEVMIndex) *ZMQRep {
	ctx := context.Background()
	zmq := &ZMQRep{
		stack:       stackIn,
		eth:         ethIn,
		rep:         zmq4.NewRep(ctx),
		nevmIndexer: nevmIndexerIn,
	}
	log.Info("zmq Init")
	zmq.Init(NEVMPubEP)
	return zmq
}
