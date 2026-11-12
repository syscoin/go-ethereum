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

package main

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/eth/ethconfig"
)

// SYSCOIN: Generated TOML codecs must preserve the NEVM listener endpoint.
func TestConfigNEVMPubEPRoundTrip(t *testing.T) {
	for _, endpoint := range []string{"", "tcp://127.0.0.1:8370"} {
		t.Run(endpoint, func(t *testing.T) {
			config := ethconfig.Defaults
			config.NEVMPubEP = endpoint
			encoded, err := tomlSettings.Marshal(&config)
			if err != nil {
				t.Fatal(err)
			}
			if got := bytes.Contains(encoded, []byte("NEVMPubEP")); got != (endpoint != "") {
				t.Fatalf("NEVMPubEP field presence = %t, want %t", got, endpoint != "")
			}
			var decoded ethconfig.Config
			if err := tomlSettings.Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.NEVMPubEP != endpoint {
				t.Fatalf("NEVMPubEP = %q, want %q", decoded.NEVMPubEP, endpoint)
			}
		})
	}
}
