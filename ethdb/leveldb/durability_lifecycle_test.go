// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package leveldb

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/storage"
)

func openDurabilityLifecycleDB(t *testing.T, path string, customize func(*opt.Options)) *Database {
	t.Helper()
	db, err := NewCustom(path, t.Name()+"/", customize)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil && !errors.Is(err, leveldb.ErrClosed) {
			t.Error(err)
		}
	})
	return db
}

func requireDurabilityLifecycleValue(t *testing.T, db *Database, key string, want []byte) {
	t.Helper()
	got, err := db.Get([]byte(key))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Get(%q) = %q, %v; want %q", key, got, err, want)
	}
}

func TestSyncKeyValueFileLifecycle(t *testing.T) {
	path := t.TempDir()
	db := openDurabilityLifecycleDB(t, path, nil)
	batch := db.NewBatch()
	for _, key := range []string{"pair", "head", "canonical"} {
		if err := batch.Put([]byte(key), []byte("P")); err != nil {
			t.Fatal(err)
		}
	}
	if err := batch.Write(); err != nil {
		t.Fatal(err)
	}
	if err := db.SyncKeyValue(); err != nil {
		t.Fatal(err)
	}
	if extra, err := NewCustom(path, "", nil); err == nil {
		extra.Close()
		t.Fatal("second writer acquired the live database lock")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openDurabilityLifecycleDB(t, path, nil)
	for _, key := range []string{"pair", "head", "canonical"} {
		requireDurabilityLifecycleValue(t, reopened, key, []byte("P"))
	}
	// SYSCOIN: the storage fence must not insert an application-visible marker.
	iter := reopened.NewIterator(nil, nil)
	defer iter.Release()
	var keys []string
	for iter.Next() {
		keys = append(keys, string(iter.Key()))
	}
	if err := iter.Error(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(keys, ","); got != "canonical,head,pair" {
		t.Fatalf("unexpected keys after a durability fence: %s", got)
	}
	if err := reopened.SyncKeyValue(); err != nil {
		t.Fatal(err)
	}
}

func TestSyncKeyValueOpenFailureCleanup(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing=%t", existing), func(t *testing.T) {
			path := t.TempDir()
			if existing {
				db := openDurabilityLifecycleDB(t, path, nil)
				if err := db.Put([]byte("pair"), []byte("P")); err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			failed, err := NewCustom(path, "", func(options *opt.Options) {
				options.ErrorIfExist = existing
				options.ErrorIfMissing = !existing
			})
			if err == nil {
				failed.Close()
				t.Fatal("requested open failure did not occur")
			}
			// The failed leveldb.Open must release the underlying file lock too.
			reopened := openDurabilityLifecycleDB(t, path, nil)
			if existing {
				requireDurabilityLifecycleValue(t, reopened, "pair", []byte("P"))
			}
			if err := reopened.SyncKeyValue(); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("recovery", func(t *testing.T) {
		path := t.TempDir()
		db := openDurabilityLifecycleDB(t, path, nil)
		if err := db.Put([]byte("pair"), []byte("P")); err != nil {
			t.Fatal(err)
		}
		// Recovery rebuilds the manifest from tables, so materialize the row
		// before deliberately removing all manifest entry-point files.
		if err := db.Compact(nil, nil); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			t.Fatal(err)
		}
		removed := false
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "CURRENT") {
				if err := os.Remove(filepath.Join(path, entry.Name())); err != nil {
					t.Fatal(err)
				}
				removed = true
			}
		}
		if !removed {
			t.Fatal("fixture had no manifest entry point to remove")
		}
		recovered := openDurabilityLifecycleDB(t, path, nil)
		requireDurabilityLifecycleValue(t, recovered, "pair", []byte("P"))
		if err := recovered.SyncKeyValue(); err != nil {
			t.Fatal(err)
		}
		if err := recovered.Close(); err != nil {
			t.Fatal(err)
		}
		reopened := openDurabilityLifecycleDB(t, path, nil)
		requireDurabilityLifecycleValue(t, reopened, "pair", []byte("P"))
	})
}

func TestSyncKeyValueUnsupportedLifecycle(t *testing.T) {
	for _, mode := range []string{"readonly", "no-sync", "closed"} {
		t.Run(mode, func(t *testing.T) {
			path := t.TempDir()
			db := openDurabilityLifecycleDB(t, path, nil)
			if err := db.Put([]byte("pair"), []byte("P")); err != nil {
				t.Fatal(err)
			}
			if err := db.SyncKeyValue(); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if mode != "closed" {
				db = openDurabilityLifecycleDB(t, path, func(options *opt.Options) {
					options.ReadOnly = mode == "readonly"
					options.NoSync = mode == "no-sync"
				})
				requireDurabilityLifecycleValue(t, db, "pair", []byte("P"))
			}
			if err := db.SyncKeyValue(); err == nil {
				t.Fatalf("%s database acknowledged a durability fence", mode)
			}
		})
	}
}

func TestSyncKeyValueConcurrentOperations(t *testing.T) {
	path := t.TempDir()
	db := openDurabilityLifecycleDB(t, path, func(options *opt.Options) {
		options.WriteBuffer = 4096
	})
	const workers, writes = 4, 32
	value := bytes.Repeat([]byte{0x51}, 128)
	start := make(chan struct{})
	errs := make(chan error, workers+1)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			<-start
			for i := 0; i < writes; i++ {
				key := []byte(fmt.Sprintf("%d/%d", worker, i))
				temporary := append(bytes.Clone(key), '/', 'x')
				if err := db.Put(temporary, value); err != nil {
					errs <- err
					return
				}
				if err := db.Delete(temporary); err != nil {
					errs <- err
					return
				}
				batch := db.NewBatch()
				batch.Put(key, value)
				batch.Put(temporary, value)
				batch.Delete(temporary)
				if err := batch.Write(); err != nil {
					errs <- err
					return
				}
			}
		}(worker)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < writes; i++ {
			if err := db.SyncKeyValue(); err != nil {
				errs <- err
				return
			}
		}
	}()
	close(start)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent database operations did not finish")
	}
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if err := db.SyncKeyValue(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openDurabilityLifecycleDB(t, path, nil)
	for worker := 0; worker < workers; worker++ {
		for i := 0; i < writes; i++ {
			key := fmt.Sprintf("%d/%d", worker, i)
			requireDurabilityLifecycleValue(t, reopened, key, value)
			if has, err := reopened.Has([]byte(key + "/x")); err != nil || has {
				t.Fatalf("deleted key %q reappeared: %t, %v", key, has, err)
			}
		}
	}
}

func TestSyncKeyValueConcurrentClose(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var enterOnce, releaseOnce sync.Once
	releaseFence := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseFence()
	wrapped := newDurabilityStorage(storage.NewMemStorage(), func() error {
		enterOnce.Do(func() { close(entered) })
		<-release
		return nil
	})
	engine, err := leveldb.Open(wrapped, nil)
	if err != nil {
		t.Fatal(err)
	}
	db := &Database{db: engine, storage: wrapped}
	t.Cleanup(func() { db.Close() })
	if err := db.Put([]byte("pair"), []byte("P")); err != nil {
		t.Fatal(err)
	}
	fenced := make(chan error, 1)
	go func() { fenced <- db.SyncKeyValue() }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("durability fence did not reach the directory barrier")
	}
	batch := db.NewBatch()
	batch.Put([]byte("batch"), []byte("P"))
	batch.Delete([]byte("pair"))
	operations := []func() error{
		func() error { return db.Put([]byte("put"), []byte("P")) },
		func() error { return db.Delete([]byte("delete")) },
		batch.Write,
		db.Close,
	}
	started := make(chan struct{}, len(operations))
	finished := make(chan error, len(operations))
	for _, operation := range operations {
		go func(operation func() error) {
			started <- struct{}{}
			finished <- operation()
		}(operation)
	}
	for range operations {
		<-started
	}
	// All callers now contend with a fence already inside its storage barrier.
	releaseFence()
	select {
	case err := <-fenced:
		if err != nil {
			t.Fatalf("in-flight fence failed during concurrent close: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("in-flight fence did not finish")
	}
	for range operations {
		select {
		case err := <-finished:
			if err != nil && !errors.Is(err, leveldb.ErrClosed) {
				t.Fatalf("unexpected error racing Close: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("database operation deadlocked with Close")
		}
	}
	if err := db.SyncKeyValue(); err == nil {
		t.Fatal("closed database acknowledged a durability fence")
	}
}

type retirementFailureStorage struct {
	storage.Storage
	removeErr error
	opened    int
	closed    int
	syncs     int
}

type retirementFailureWriter struct {
	storage.Writer
	store  *retirementFailureStorage
	closed bool
}

func (s *retirementFailureStorage) Create(fd storage.FileDesc) (storage.Writer, error) {
	w, err := s.Storage.Create(fd)
	if err != nil {
		return nil, err
	}
	s.opened++
	return &retirementFailureWriter{Writer: w, store: s}, nil
}

func (s *retirementFailureStorage) Remove(storage.FileDesc) error {
	return s.removeErr
}

func (w *retirementFailureWriter) Sync() error {
	if w.closed {
		return storage.ErrClosed
	}
	w.store.syncs++
	return w.Writer.Sync()
}

func (w *retirementFailureWriter) Close() error {
	if w.closed {
		return storage.ErrClosed
	}
	w.closed = true
	w.store.closed++
	return w.Writer.Close()
}

func TestSyncKeyValueRetirementRemoveFailure(t *testing.T) {
	store := &retirementFailureStorage{
		Storage:   storage.NewMemStorage(),
		removeErr: errors.New("injected journal removal failure"),
	}
	wrapped := newDurabilityStorage(store, func() error { return nil })
	defer wrapped.Close()
	// SYSCOIN: LevelDB's retirement request follows durable publication. Even
	// when unlink fails and obsolete files remain, their handles must not build
	// up across later rotations or be included in a subsequent recovery fence.
	for i := int64(1); i <= 64; i++ {
		fd := storage.FileDesc{Type: storage.TypeJournal, Num: i}
		w, err := wrapped.Create(fd)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("retired")); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if got := store.opened - store.closed; got != 1 {
			t.Fatalf("logical close retained %d physical writers; want 1", got)
		}
		if err := wrapped.Remove(fd); !errors.Is(err, store.removeErr) {
			t.Fatalf("Remove returned %v; want injected failure", err)
		}
		if got := store.opened - store.closed; got != 0 {
			t.Fatalf("failed removal left %d physical writers open", got)
		}
	}
	current, err := wrapped.Create(storage.FileDesc{Type: storage.TypeJournal, Num: 65})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := current.Write([]byte("current")); err != nil {
		t.Fatal(err)
	}
	if err := wrapped.syncJournals(); err != nil {
		t.Fatal(err)
	}
	if store.syncs != 1 {
		t.Fatalf("fence synced %d writers; want only the current journal", store.syncs)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	if store.opened != store.closed {
		t.Fatalf("Close leaked %d physical writers", store.opened-store.closed)
	}
}
