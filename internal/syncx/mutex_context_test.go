package syncx

import (
	"context"
	"errors"
	"testing"
)

func TestTryLockContextCancellation(t *testing.T) {
	mutex := NewClosableMutex()
	mutex.MustLock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if locked, err := mutex.TryLockContext(ctx); locked || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled lock = %v, %v", locked, err)
	}
	mutex.Unlock()
	if locked, err := mutex.TryLockContext(context.Background()); !locked || err != nil {
		t.Fatalf("available lock = %v, %v", locked, err)
	}
	mutex.Unlock()
	mutex.Close()
	if locked, err := mutex.TryLockContext(context.Background()); locked || err != nil {
		t.Fatalf("closed lock = %v, %v", locked, err)
	}
}
