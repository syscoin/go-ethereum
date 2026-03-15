package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofrs/flock"
)

func TestEnsureChaindataNotLockedWithoutLockFile(t *testing.T) {
	chaindataPath := t.TempDir()

	if err := ensureChaindataNotLocked(chaindataPath); err != nil {
		t.Fatalf("ensureChaindataNotLocked error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(chaindataPath, "LOCK")); !os.IsNotExist(err) {
		t.Fatalf("expected no LOCK file to be created, stat err=%v", err)
	}
}

func TestEnsureChaindataNotLockedWithStaleLockFile(t *testing.T) {
	chaindataPath := t.TempDir()
	lockPath := filepath.Join(chaindataPath, "LOCK")
	if err := os.WriteFile(lockPath, []byte{}, 0o644); err != nil {
		t.Fatalf("write stale LOCK file: %v", err)
	}

	if err := ensureChaindataNotLocked(chaindataPath); err != nil {
		t.Fatalf("ensureChaindataNotLocked error: %v", err)
	}
}

func TestEnsureChaindataNotLockedWithHeldLock(t *testing.T) {
	chaindataPath := t.TempDir()
	lockPath := filepath.Join(chaindataPath, "LOCK")
	lock := flock.New(lockPath)
	locked, err := lock.TryLock()
	if err != nil {
		t.Fatalf("acquire test lock: %v", err)
	}
	if !locked {
		t.Fatal("expected test lock acquisition to succeed")
	}
	t.Cleanup(func() {
		_ = lock.Unlock()
	})

	err = ensureChaindataNotLocked(chaindataPath)
	if err == nil {
		t.Fatal("expected lock-held error")
	}
	if !strings.Contains(err.Error(), "locked by another process") {
		t.Fatalf("unexpected error: %v", err)
	}
}
