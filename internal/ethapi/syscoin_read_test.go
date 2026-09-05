// Copyright 2026 The go-ethereum Authors
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

package ethapi

import (
	"errors"
	"testing"
)

type metadataReadBackend struct {
	check func() error
}

func (b metadataReadBackend) BeginSyscoinMetadataRead() func() error { return b.check }

func TestBeginSyscoinMetadataRead(t *testing.T) {
	for _, backend := range []interface{}{nil, struct{}{}, metadataReadBackend{}} {
		if err := BeginSyscoinMetadataRead(backend)(); err != nil {
			t.Fatalf("backend without SYSCOIN metadata returned %v", err)
		}
	}
	want := errors.New("generation changed")
	checks := 0
	check := BeginSyscoinMetadataRead(metadataReadBackend{check: func() error {
		checks++
		return want
	}})
	if checks != 0 {
		t.Fatal("validation ran before execution")
	}
	if err := check(); err != want || checks != 1 {
		t.Fatalf("check returned %v after %d calls, want %v once", err, checks, want)
	}
}
