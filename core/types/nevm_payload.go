// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package types

import (
	"crypto/sha256"
	"errors"
	"hash"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// nevmPayloadContext records only provenance on successful deserialization. Raw
// payload bytes and their digest are neither retained nor hashed on that path.
type nevmPayloadContext struct {
	nevmHash, txRoot, receiptRoot, sysHash common.Hash
	block                                  *Block
}

func (p *nevmPayloadContext) hasPair() bool {
	return p.nevmHash != (common.Hash{}) && p.sysHash != (common.Hash{})
}

func (p *nevmPayloadContext) hasher() hash.Hash {
	h := sha256.New()
	h.Write([]byte("syscoin-nevm-payload-v1\x00"))
	h.Write(p.nevmHash[:])
	h.Write(p.txRoot[:])
	h.Write(p.receiptRoot[:])
	h.Write(p.sysHash[:])
	return h
}

// NEVMPayloadError identifies a rejected representation, not a consensus-invalid
// header. Its private provenance must still match a deserialized connect pair.
type NEVMPayloadError struct {
	err     error
	block   *Block
	context *nevmPayloadContext
	digest  common.Hash
}

func (e *NEVMPayloadError) Error() string { return e.err.Error() }
func (e *NEVMPayloadError) Unwrap() error { return e.err }

// MarkNEVMPayloadError marks an existing body commitment failure at its source.
// It performs no encoding or hashing; the checked block is retained for reply
// correlation. It must not be used for header, execution or operational errors.
func MarkNEVMPayloadError(err error, block *Block) error {
	if err == nil || block == nil {
		return err
	}
	return &NEVMPayloadError{err: err, block: block}
}

func (n *NEVMBlockConnect) rejectPayload(err error, raw []byte) error {
	if !n.payload.hasPair() {
		return err
	}
	h := n.payload.hasher()
	h.Write(raw)
	return &NEVMPayloadError{err: err, context: n.payload, digest: common.BytesToHash(h.Sum(nil))}
}

// PayloadRejection returns a fingerprint only for a source-marked rejection of
// this exact wire context. For decoded body failures canonical RLP reconstructs
// the original payload, including optional fields and blob sidecar wrappers.
// Re-encoding happens only here, on rejection, never on successful imports.
func (n *NEVMBlockConnect) PayloadRejection(err error) (nevmHash, sysHash, digest common.Hash, ok bool) {
	var rejected *NEVMPayloadError
	if n == nil || n.payload == nil || !errors.As(err, &rejected) {
		return
	}
	p := n.payload
	if !p.hasPair() || n.Blockhash != p.nevmHash || len(n.Sysblockhash) != common.HashLength ||
		common.BytesToHash([]byte(n.Sysblockhash)) != p.sysHash {
		return
	}
	if rejected.context != nil {
		if rejected.context != p {
			return
		}
		digest = rejected.digest
	} else {
		if p.block == nil || rejected.block != p.block || n.Block != p.block ||
			p.block.Hash() != p.nevmHash || p.block.TxHash() != p.txRoot || p.block.ReceiptHash() != p.receiptRoot {
			return
		}
		h := p.hasher()
		if rlp.Encode(h, p.block) != nil {
			return
		}
		digest = common.BytesToHash(h.Sum(nil))
	}
	return p.nevmHash, p.sysHash, digest, true
}
