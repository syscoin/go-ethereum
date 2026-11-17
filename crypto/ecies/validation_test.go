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
package ecies

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestDecryptPayloadLength(t *testing.T) {
	prv, err := GenerateKey(rand.Reader, crypto.S256(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := GenerateKey(rand.Reader, crypto.S256(), nil)
	if err != nil {
		t.Fatal(err)
	}
	params := prv.Params
	shared1, shared2 := []byte("key context"), []byte("message context")
	z, err := ephemeral.GenerateShared(&prv.PublicKey, params.KeyLen, params.KeyLen)
	if err != nil {
		t.Fatal(err)
	}
	_, macKey := deriveKeys(params.Hash(), z, shared1, params.KeyLen)
	point := crypto.S256().Marshal(ephemeral.X, ephemeral.Y)

	for size := 0; size <= params.BlockSize+1; size++ {
		for _, validMAC := range []bool{true, false} {
			t.Run(fmt.Sprintf("size=%d/validMAC=%t", size, validMAC), func(t *testing.T) {
				payload := make([]byte, size)
				tag := messageTag(params.Hash, macKey, payload, shared2)
				if !validMAC {
					tag[0] ^= 1
				}
				ciphertext := append(append(append([]byte{}, point...), payload...), tag...)
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Errorf("Decrypt panicked: %v", recovered)
					}
				}()
				plaintext, err := prv.Decrypt(ciphertext, shared1, shared2)
				if size < params.BlockSize || !validMAC {
					if err != ErrInvalidMessage {
						t.Fatalf("got %v, want %v", err, ErrInvalidMessage)
					}
					if plaintext != nil {
						t.Fatalf("unexpected plaintext %x", plaintext)
					}
				} else if err != nil || len(plaintext) != size-params.BlockSize {
					t.Fatalf("got plaintext %x, error %v", plaintext, err)
				}
			})
		}
	}
}

func TestGenerateSharedPublicKeyValidation(t *testing.T) {
	prv, err := GenerateKey(rand.Reader, crypto.S256(), nil)
	if err != nil {
		t.Fatal(err)
	}
	curve := crypto.S256()
	p := curve.Params()
	tests := []struct {
		name string
		x, y *big.Int
	}{
		{"nil x", nil, p.Gy},
		{"nil y", p.Gx, nil},
		{"zero point", new(big.Int), new(big.Int)},
		{"x at prime", p.P, p.Gy},
		{"y at prime", p.Gx, p.P},
		{"negative x", new(big.Int).Neg(p.Gx), p.Gy},
		{"negative y", p.Gx, new(big.Int).Neg(p.Gy)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pub := &PublicKey{Curve: curve, X: test.x, Y: test.y}
			shared, err := prv.GenerateShared(pub, 16, 16)
			if err != ErrInvalidPublicKey || shared != nil {
				t.Fatalf("got shared %x, error %v; want %v", shared, err, ErrInvalidPublicKey)
			}
			if ciphertext, err := Encrypt(rand.Reader, pub, []byte("message"), nil, nil); err != ErrInvalidPublicKey || ciphertext != nil {
				t.Fatalf("Encrypt returned %x, %v; want %v", ciphertext, err, ErrInvalidPublicKey)
			}
		})
	}
	peer, err := GenerateKey(rand.Reader, curve, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, err := peer.GenerateShared(&prv.PublicKey, 16, 16)
	if err != nil {
		t.Fatal(err)
	}
	got, err := prv.GenerateShared(&peer.PublicKey, 16, 16)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("valid shared key mismatch: %x, %v", got, err)
	}
}
