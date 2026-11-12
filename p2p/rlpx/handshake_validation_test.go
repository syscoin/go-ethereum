// Copyright 2017 The go-ethereum Authors
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

// SYSCOIN: Security regression coverage.
package rlpx

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

func TestHandshakePublicKeyValidation(t *testing.T) {
	initiatorKey, recipientKey := newkey(), newkey()
	init := handshakeState{initiator: true, remote: ecies.ImportECDSAPublic(&recipientKey.PublicKey)}
	auth, err := init.makeAuthMsg(initiatorKey)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := init.sealEIP8(auth)
	if err != nil {
		t.Fatal(err)
	}
	var recipient handshakeState
	if _, err := recipient.readMsg(new(authMsgV4), recipientKey, bytes.NewReader(packet)); err != nil {
		t.Fatalf("valid handshake rejected: %v", err)
	}
	badPoint := append([]byte(nil), packet...)
	clear(badPoint[3 : 2+65])
	if _, err := recipient.readMsg(new(authMsgV4), recipientKey, bytes.NewReader(badPoint)); err != ecies.ErrInvalidPublicKey {
		t.Fatalf("invalid point returned %v, want %v", err, ecies.ErrInvalidPublicKey)
	}
	badMAC := append([]byte(nil), packet...)
	badMAC[len(badMAC)-1] ^= 1
	if _, err := recipient.readMsg(new(authMsgV4), recipientKey, bytes.NewReader(badMAC)); err != ecies.ErrInvalidMessage {
		t.Fatalf("invalid MAC returned %v, want %v", err, ecies.ErrInvalidMessage)
	}
}
