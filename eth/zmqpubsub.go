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
	"encoding/hex"
	"strconv"
	"strings" // SYSCOIN: exact recovery durability command.

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/go-zeromq/zmq4"
)

func encodeSyscoinDisplayHash(serializedHash []byte) string {
	// SYSCOIN: The pairing DB stores uint256's 32 serialized little-endian
	// bytes. Status uses the conventional display order consumed by SetHex.
	display := make([]byte, 32)
	if len(serializedHash) == len(display) {
		for i := range serializedHash {
			display[len(display)-1-i] = serializedHash[i]
		}
	}
	return hex.EncodeToString(display)
}

func (zmq *ZMQRep) currentNEVMBlockInfo() (uint64, string, bool) {
	count, sysHash, ok := zmq.eth.blockchain.CurrentSyscoinPair()
	return count, encodeSyscoinDisplayHash(sysHash), ok
}

// handleNEVMComms receives Core's serialized string, including its length byte.
// The generic ack is not proof of a flush. Core must require flushed and then
// query blockinfo to verify the exact committed pair before completing replay.
func (zmq *ZMQRep) handleNEVMComms(command string) string {
	// SYSCOIN: generic legacy ack is never proof of this storage barrier.
	if len(command) > 1 && strings.HasPrefix(command[1:], nevmDurablePairPrefix) {
		text, number, hash, err := parseNEVMDurablePair(command)
		if err == nil {
			err = zmq.eth.syncNEVMPair(number, hash)
		}
		if err != nil {
			log.Error("NEVM durability fence failed", "err", err)
			return "durable-pair-error"
		}
		return text
	}
	switch command {
	case "\x0aconnect-v1":
		return "connect-v1"
	case "\x0apayload-v1":
		return "payload-v1"
	case "\x05flush":
		err := zmq.eth.flushBufferedBlocks()
		if err != nil {
			log.Error("NEVM buffer flush failed", "err", err)
		}
		return nevmFlushResult(err)
	case "\fstartnetwork":
		zmq.eth.Downloader().StartNetworkEvent()
	}
	return "ack"
}

type ZMQRep struct {
	NEVMPubEP string
	eth       *Ethereum
	rep       zmq4.Socket
	inited    bool
	ctx       context.Context
	cancel    context.CancelFunc
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
					msgSend := zmq4.NewMsgFrom([]byte("error"), []byte("invalid-message-frames"))
					if err := zmq.rep.SendMulti(msgSend); err != nil {
						log.Error("ZMQ send error", "topic", "error", "err", err)
					}
					continue
				}
				strTopic := string(msg.Frames[0])
				if strTopic == "nevmcomms" {
					if string(msg.Frames[1]) == "\ndisconnect" {
						log.Info("ZMQ: exiting...")
						go zmq.eth.Shutdown()
						return
					}
					result := zmq.handleNEVMComms(string(msg.Frames[1]))
					msgSend := zmq4.NewMsgFrom([]byte("nevmcomms"), []byte(result))
					if err := zmq.rep.SendMulti(msgSend); err != nil {
						log.Error("ZMQ send error", "topic", strTopic, "err", err)
					}
				} else if strTopic == "nevmconnect" {
					result := zmq.handleNEVMConnect(msg.Frames[1])
					msgSend := zmq4.NewMsgFrom([]byte("nevmconnect"), []byte(result))
					if err := zmq.rep.SendMulti(msgSend); err != nil {
						log.Error("ZMQ send error", "topic", strTopic, "err", err)
					}
				} else if strTopic == "nevmvalidate" {
					result := zmq.handleNEVMValidate(msg.Frames[1])
					msgSend := zmq4.NewMsgFrom([]byte("nevmvalidate"), []byte(result))
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
					current, lastSysHash, ok := zmq.currentNEVMBlockInfo()
					count := strconv.FormatUint(current, 10)
					if !ok {
						// A non-numeric count makes the Core side fail closed instead
						// of accepting a torn or unpaired status snapshot.
						count = "unavailable"
					}
					// SYSCOIN: Count alone cannot distinguish equal-height Syscoin
					// forks after a crash. Return the exact paired branch tip atomically.
					msgSend := zmq4.NewMsgFrom([]byte("nevmblockinfo"), []byte(count), []byte(lastSysHash))
					if err := zmq.rep.SendMulti(msgSend); err != nil {
						log.Error("ZMQ send error", "topic", strTopic, "err", err)
					}
				} else {
					log.Error("Unknown ZMQ request topic", "topic", strTopic)
					msgSend := zmq4.NewMsgFrom([]byte(strTopic), []byte("unknown-topic"))
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
		NEVMPubEP: NEVMPubEPIn,
		eth:       ethIn,
		rep:       zmq4.NewRep(ctx),
		ctx:       ctx,
		cancel:    cancel,
	}
	log.Info("zmq Init")
	return zmq
}
