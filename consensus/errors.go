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

package consensus

import "errors"

// InvalidBlockError identifies a deterministic failure of committed block data.
// Local availability, storage and transport errors must never use this marker.
// Unwrap preserves the original consensus error for errors.Is callers.
type InvalidBlockError struct {
	Err error
}

func (e *InvalidBlockError) Error() string { return e.Err.Error() }
func (e *InvalidBlockError) Unwrap() error { return e.Err }

// MarkInvalidBlock is only for validation origins that have ruled out local
// failures and, for execution errors, verified the body's header commitments.
func MarkInvalidBlock(err error) error {
	if err == nil {
		return nil
	}
	var invalid *InvalidBlockError
	if errors.As(err, &invalid) {
		return err
	}
	return &InvalidBlockError{Err: err}
}

var (
	// ErrUnknownAncestor is returned when validating a block requires an ancestor
	// that is unknown.
	ErrUnknownAncestor = errors.New("unknown ancestor")

	// ErrPrunedAncestor is returned when validating a block requires an ancestor
	// that is known, but the state of which is not available.
	ErrPrunedAncestor = errors.New("pruned ancestor")

	// ErrFutureBlock is returned when a block's timestamp is in the future according
	// to the current node.
	ErrFutureBlock = errors.New("block in the future")

	// ErrInvalidNumber is returned if a block's number doesn't equal its parent's
	// plus one.
	ErrInvalidNumber = errors.New("invalid block number")

	// ErrInvalidTerminalBlock is returned if a block is invalid wrt. the terminal
	// total difficulty.
	ErrInvalidTerminalBlock = errors.New("invalid terminal block")
)
