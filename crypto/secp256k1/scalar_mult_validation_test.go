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

//go:build !gofuzz && cgo

package secp256k1

import (
	"math/big"
	"testing"
)

func TestScalarMultCoordinateRange(t *testing.T) {
	curve := S256()
	one := big.NewInt(1)
	y := new(big.Int).ModSqrt(big.NewInt(8), curve.P)
	if y == nil {
		t.Fatal("missing test point")
	}
	for _, point := range [][2]*big.Int{{curve.Gx, curve.Gy}, {one, y}} {
		x, gotY := curve.ScalarMult(point[0], point[1], []byte{1})
		if x == nil || gotY == nil || x.Cmp(point[0]) != 0 || gotY.Cmp(point[1]) != 0 {
			t.Fatalf("valid point changed: %v, %v", x, gotY)
		}
	}
	tests := []struct {
		name string
		x, y *big.Int
	}{
		{"x at prime", curve.P, y},
		{"y at prime", one, curve.P},
		{"x above prime", new(big.Int).Add(curve.P, one), y},
		{"y above prime", one, new(big.Int).Add(curve.P, one)},
		{"maximum x", new(big.Int).Sub(new(big.Int).Lsh(one, 256), one), y},
		{"maximum y", one, new(big.Int).Sub(new(big.Int).Lsh(one, 256), one)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			x, y := curve.ScalarMult(test.x, test.y, []byte{1})
			if x != nil || y != nil {
				t.Fatalf("invalid coordinates returned (%v, %v)", x, y)
			}
		})
	}
}
