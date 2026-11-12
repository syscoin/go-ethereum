// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// SYSCOIN: Bounded peer-response decoding and validation.
package tracker

import (
	"container/list"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/rlp"
)

var (
	ErrUnrequestedResponse = errors.New("response has no active request")
	ErrResponseCancelled   = errors.New("response request was cancelled")
	ErrResponseType        = errors.New("unexpected response type")
	ErrResponseLimit       = errors.New("response exceeds request limit")
	ErrRequestLimit        = errors.New("too many active requests")
	ErrRequestID           = errors.New("request ID already active")
)

// ResponseLimits bounds the encoded payload and its top-level item count.
// A negative Items value permits any count within the byte limit.
type ResponseLimits struct {
	Items      int
	Bytes      uint64
	ProofItems int
}

type activeRequest struct {
	id        uint64
	code      uint64
	limits    ResponseLimits
	expiry    time.Time
	cancelled bool
}

// ResponseTracker tracks a single peer's requests independently of metrics.
// Expiration is lazy, so it never leaves a timer behind after a peer disconnects.
type ResponseTracker struct {
	mu      sync.Mutex
	timeout time.Duration
	pending map[uint64]*list.Element
	order   *list.List
}

func NewResponseTracker(timeout time.Duration) *ResponseTracker {
	return &ResponseTracker{timeout: timeout, pending: make(map[uint64]*list.Element), order: list.New()}
}

func (t *ResponseTracker) expire(now time.Time) {
	for head := t.order.Front(); head != nil; head = t.order.Front() {
		req := head.Value.(activeRequest)
		if now.Before(req.expiry) {
			break
		}
		delete(t.pending, req.id)
		t.order.Remove(head)
	}
}

func (t *ResponseTracker) Track(id, code uint64, limits ResponseLimits) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.expire(now)
	if _, ok := t.pending[id]; ok {
		return ErrRequestID
	}
	if len(t.pending) >= 10000 {
		return ErrRequestLimit
	}
	t.pending[id] = t.order.PushBack(activeRequest{id: id, code: code, limits: limits, expiry: now.Add(t.timeout)})
	return nil
}

func (t *ResponseTracker) Cancel(id uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if elem := t.pending[id]; elem != nil {
		req := elem.Value.(activeRequest)
		req.cancelled = true
		elem.Value = req
	}
}

// Forget removes a request which was not sent successfully.
func (t *ResponseTracker) Forget(id uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if elem := t.pending[id]; elem != nil {
		delete(t.pending, id)
		t.order.Remove(elem)
	}
}

func (t *ResponseTracker) match(id, code uint64) (ResponseLimits, error) {
	t.expire(time.Now())
	elem := t.pending[id]
	if elem == nil {
		return ResponseLimits{}, ErrUnrequestedResponse
	}
	req := elem.Value.(activeRequest)
	if req.code != code {
		return ResponseLimits{}, ErrResponseType
	}
	if req.cancelled {
		return ResponseLimits{}, ErrResponseCancelled
	}
	return req.limits, nil
}

func (t *ResponseTracker) limits(id, code uint64) (ResponseLimits, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.match(id, code)
}

func (t *ResponseTracker) take(id, code uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, err := t.match(id, code); err != nil {
		return err
	}
	elem := t.pending[id]
	delete(t.pending, id)
	t.order.Remove(elem)
	return nil
}

// ResponseDecoder checks the request envelope before reading raw payload lists,
// and checks their limits before allocating decoded items. Values contains the
// response's main list followed by its optional proof list.
type ResponseDecoder struct {
	Tracker   *ResponseTracker
	Code      uint64
	ID        *uint64
	Values    []interface{}
	Cancelled bool
}

// ListDecoder bounds a list before allocating any of its decoded elements.
// It is also used for unsolicited messages, which have no request envelope.
type ListDecoder struct {
	Items int
	Bytes uint64
	Value interface{}
}

func (d *ListDecoder) DecodeRLP(s *rlp.Stream) error {
	_, size, err := s.Kind()
	if err != nil {
		return err
	}
	if size > d.Bytes {
		return ErrResponseLimit
	}
	raw, err := s.Raw()
	if err != nil {
		return err
	}
	content, rest, err := rlp.SplitList(raw)
	if err != nil || len(rest) != 0 {
		return fmt.Errorf("invalid message list: %v", err)
	}
	count, err := rlp.CountValues(content)
	if err != nil {
		return err
	}
	if d.Items >= 0 && count > d.Items {
		return ErrResponseLimit
	}
	return rlp.DecodeBytes(raw, d.Value)
}

func (d *ResponseDecoder) DecodeRLP(s *rlp.Stream) error {
	if d.Tracker == nil {
		return ErrUnrequestedResponse
	}
	size, err := s.List()
	if err != nil {
		return err
	}
	id, err := s.Uint64()
	if err != nil {
		return err
	}
	limits, err := d.Tracker.limits(id, d.Code)
	if err != nil {
		d.Cancelled = errors.Is(err, ErrResponseCancelled)
		return err
	}
	// Proofs are independent of the requested range size. Bound their envelope
	// as well as their item count, allowing the usual trie path proofs.
	envelopeLimit := limits.Bytes + 64
	if len(d.Values) == 2 {
		envelopeLimit += 128 * 1024
	}
	if size > envelopeLimit {
		return ErrResponseLimit
	}
	raw := make([][]byte, len(d.Values))
	for i := range raw {
		if raw[i], err = s.Raw(); err != nil {
			return err
		}
		content, rest, err := rlp.SplitList(raw[i])
		if err != nil || len(rest) != 0 {
			return fmt.Errorf("invalid response list: %v", err)
		}
		count, err := rlp.CountValues(content)
		if err != nil {
			return err
		}
		if i == 0 && ((limits.Items >= 0 && count > limits.Items) || uint64(len(content)) > limits.Bytes) {
			return ErrResponseLimit
		}
		if i == 1 && count > limits.ProofItems {
			return ErrResponseLimit
		}
	}
	if err := s.ListEnd(); err != nil {
		return err
	}
	if err := d.Tracker.take(id, d.Code); err != nil {
		d.Cancelled = errors.Is(err, ErrResponseCancelled)
		return err
	}
	for i := range raw {
		if err := rlp.DecodeBytes(raw[i], d.Values[i]); err != nil {
			return err
		}
	}
	*d.ID = id
	return nil
}
