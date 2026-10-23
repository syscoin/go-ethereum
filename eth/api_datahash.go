// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package eth

import (
	"context"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
)

type dataHashInclusionSource interface {
	GetDataHashInclusions(context.Context, []common.Hash, *uint64, uint64) (*core.DataHashInclusionPage, error)
}

// DataHashAPI exposes bounded candidate discovery, not a finality oracle.
type DataHashAPI struct{ chain dataHashInclusionSource }

func (api *DataHashAPI) GetDataHashInclusions(ctx context.Context, hashes []common.Hash, beforeHeight *hexutil.Uint64, maxBlocks *hexutil.Uint64) (*core.DataHashInclusionPage, error) {
	limit := uint64(core.DefaultDataHashLookupBlocks)
	if maxBlocks != nil {
		limit = uint64(*maxBlocks)
	}
	var before *uint64
	if beforeHeight != nil {
		value := uint64(*beforeHeight)
		before = &value
	}
	return api.chain.GetDataHashInclusions(ctx, hashes, before, limit)
}
