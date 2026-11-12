// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package snap

import (
	"fmt"

	"github.com/ethereum/go-ethereum/rlp"
)

// newTrieNodePathIterator checks the wire shape without allocating pathsets or
// paths. The returned content can be consumed under the service's existing
// lookup and time limits, even when the request contains millions of paths.
func newTrieNodePathIterator(raw rlp.RawValue) ([]byte, error) {
	content, rest, err := rlp.SplitList(raw)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing path list data")
	}
	for sets := content; len(sets) != 0; {
		paths, rest, err := rlp.SplitList(sets)
		if err != nil {
			return nil, err
		}
		sets = rest
		for len(paths) != 0 {
			_, rest, err := rlp.SplitString(paths)
			if err != nil {
				return nil, err
			}
			paths = rest
		}
	}
	return content, nil
}
