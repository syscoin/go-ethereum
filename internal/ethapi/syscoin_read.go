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

// BeginSyscoinMetadataRead starts a SYSCOIN optimistic read before selecting any
// header or state. Call the returned checker after all execution/reexecution and
// discard both results and execution errors if it reports a metadata change.
// Unlike holding a read lock for the RPC's lifetime, this lets imports proceed
// while potentially expensive calls and traces are running.
// Backends without SYSCOIN metadata support need no validation.
func BeginSyscoinMetadataRead(backend interface{}) func() error {
	if reader, ok := backend.(interface{ BeginSyscoinMetadataRead() func() error }); ok {
		if check := reader.BeginSyscoinMetadataRead(); check != nil {
			return check
		}
	}
	return func() error { return nil }
}
