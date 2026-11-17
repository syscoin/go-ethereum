// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package eth

import (
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/go-zeromq/zmq4"
)

// SYSCOIN: successful templates retain their two-frame binary reply. Errors use
// three frames so no prefix in a serialized block can be mistaken for a failure.
// In particular, a template request can flush a previously buffered invalid pair;
// Core needs that pair's identity to reconcile, not a template or a process exit.
func (zmq *ZMQRep) handleNEVMBlock() zmq4.Msg {
	block, err := zmq.eth.CreateBlock()
	var payload []byte
	if err == nil {
		var connect types.NEVMBlockConnect
		payload, err = connect.Serialize(block)
	}
	if err != nil {
		log.Error("createBlockSub", "err", err)
		return zmq4.NewMsgFrom([]byte("nevmblock"), []byte("error"),
			[]byte(nevmBlockResult(err, "", "template-failed: ")))
	}
	return zmq4.NewMsgFrom([]byte("nevmblock"), payload)
}
