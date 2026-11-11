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

package crypto

import (
	"math/big"
	"testing"
)

func TestS256CoordinateRange(t *testing.T) {
	curve := S256()
	p := curve.Params()
	one := big.NewInt(1)
	y := new(big.Int).ModSqrt(big.NewInt(8), p.P)
	if y == nil || !curve.IsOnCurve(one, y) || !curve.IsOnCurve(p.Gx, p.Gy) {
		t.Fatal("valid points rejected")
	}
	tests := []struct {
		name string
		x, y *big.Int
	}{
		{"nil x", nil, p.Gy},
		{"nil y", p.Gx, nil},
		{"zero point", new(big.Int), new(big.Int)},
		{"negative x", new(big.Int).Neg(p.Gx), p.Gy},
		{"negative y", p.Gx, new(big.Int).Neg(p.Gy)},
		{"x at prime", p.P, p.Gy},
		{"y at prime", p.Gx, p.P},
		{"x above prime", new(big.Int).Add(p.P, one), y},
		{"x plus prime", new(big.Int).Add(p.P, p.Gx), p.Gy},
		{"y plus prime", p.Gx, new(big.Int).Add(p.P, p.Gy)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if curve.IsOnCurve(test.x, test.y) {
				t.Fatal("invalid point accepted")
			}
		})
	}
	encoded := curve.Marshal(new(big.Int).Add(p.P, one), y)
	if key, err := UnmarshalPubkey(encoded); err == nil || key != nil {
		t.Fatalf("out-of-range public key accepted: %v, %v", key, err)
	}
	if key, err := UnmarshalPubkey(curve.Marshal(one, y)); err != nil || key == nil {
		t.Fatalf("valid public key rejected: %v", err)
	}
}
