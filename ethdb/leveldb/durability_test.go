// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package leveldb

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/storage"
)

type durabilityStorage struct {
	storage.Storage
	syncs atomic.Int32
	fail  atomic.Bool
}

type durabilityWriter struct {
	storage.Writer
	store *durabilityStorage
}

func (s *durabilityStorage) Create(fd storage.FileDesc) (storage.Writer, error) {
	w, err := s.Storage.Create(fd)
	if err == nil && fd.Type == storage.TypeJournal {
		return &durabilityWriter{Writer: w, store: s}, nil
	}
	return w, err
}

func (w *durabilityWriter) Sync() error {
	w.store.syncs.Add(1)
	if w.store.fail.Load() {
		return errors.New("injected WAL sync failure")
	}
	return w.Writer.Sync()
}

// SYSCOIN: the real LevelDB writer must issue a WAL sync, including failures.
func TestSyncKeyValueWAL(t *testing.T) {
	for _, fail := range []bool{false, true} {
		store := &durabilityStorage{Storage: storage.NewMemStorage()}
		engine, err := leveldb.Open(store, nil)
		if err != nil {
			t.Fatal(err)
		}
		db := &Database{db: engine}
		if err := db.Put([]byte("pair"), []byte("P")); err != nil {
			t.Fatal(err)
		}
		before := store.syncs.Load()
		store.fail.Store(fail)
		if err := db.SyncKeyValue(); (err != nil) != fail {
			t.Fatalf("sync error %v, fail=%v", err, fail)
		}
		if store.syncs.Load() <= before {
			t.Fatal("durability barrier did not sync the WAL")
		}
		store.fail.Store(false)
		if err := engine.Close(); err != nil {
			t.Fatal(err)
		}
	}
	unsafe, err := NewCustom(t.TempDir(), "", func(options *opt.Options) { options.NoSync = true })
	if err != nil {
		t.Fatal(err)
	}
	defer unsafe.Close()
	if err := unsafe.SyncKeyValue(); err == nil {
		t.Fatal("NoSync backend acknowledged durability")
	}
}
