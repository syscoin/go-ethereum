// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package leveldb

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cockroachdb/pebble/vfs"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/storage"
)

// SYSCOIN: a synchronous marker only fences LevelDB's current WAL. Rotation
// closes the previous WAL without syncing it, before its memtable is durably
// compacted. Retain those writers so an exceptional recovery barrier covers
// every outstanding generation without changing normal asynchronous writes.
func (db *Database) SyncKeyValue() error {
	db.quitLock.Lock()
	defer db.quitLock.Unlock()
	if db.noSync {
		return fmt.Errorf("key-value durability disabled by LevelDB NoSync")
	}
	if db.readOnly {
		return leveldb.ErrReadOnly
	}
	if db.storage == nil {
		return fmt.Errorf("key-value durability requires tracked LevelDB storage")
	}
	return db.storage.syncJournals()
}

// SYSCOIN: unlike OpenFile/RecoverFile, Open/Recover leave storage ownership
// with the caller. Both failed opens and Database.Close must release it.
func openDurableLevelDB(path string, options *opt.Options, recover bool) (*leveldb.DB, *durabilityStorage, error) {
	files, err := storage.OpenFile(path, options.GetReadOnly())
	if err != nil {
		return nil, nil, err
	}
	store := newDurabilityStorage(files, func() error {
		dir, err := vfs.Default.OpenDir(path)
		if err != nil {
			return err
		}
		return errors.Join(dir.Sync(), dir.Close())
	})
	var engine *leveldb.DB
	if recover {
		engine, err = leveldb.Recover(store, options)
	} else {
		engine, err = leveldb.Open(store, options)
	}
	if err != nil {
		if closeErr := store.Close(); closeErr != nil {
			return nil, nil, errors.Join(err, closeErr)
		}
		return nil, nil, err
	}
	return engine, store, nil
}

// SYSCOIN: LevelDB has a current and a frozen memtable. Keep their WAL handles
// until LevelDB retires them after durable table/manifest publication (or until
// shutdown). Its next rotation waits for the frozen memtable, bounding retention.
// Only journal operations use mu: a stalled table compaction must not prevent
// this WAL barrier. Never call back into leveldb.DB while holding mu.
type durabilityStorage struct {
	storage.Storage
	mu       sync.Mutex
	journals map[storage.FileDesc]*durabilityWriter
	syncDir  func() error
	closed   bool
}

type durabilityWriter struct {
	storage.Writer
	store  *durabilityStorage
	closed bool // Logical close; the physical handle remains available to the barrier.
}

func newDurabilityStorage(files storage.Storage, syncDir func() error) *durabilityStorage {
	return &durabilityStorage{Storage: files, journals: make(map[storage.FileDesc]*durabilityWriter), syncDir: syncDir}
}

func (s *durabilityStorage) Create(fd storage.FileDesc) (storage.Writer, error) {
	if fd.Type != storage.TypeJournal {
		return s.Storage.Create(fd)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, storage.ErrClosed
	}
	if _, exists := s.journals[fd]; exists {
		return nil, fmt.Errorf("LevelDB journal already tracked: %s", fd)
	}
	w, err := s.Storage.Create(fd)
	if err != nil {
		return nil, err
	}
	tracked := &durabilityWriter{Writer: w, store: s}
	s.journals[fd] = tracked
	return tracked, nil
}

func (s *durabilityStorage) Remove(fd storage.FileDesc) error {
	if fd.Type != storage.TypeJournal {
		return s.Storage.Remove(fd)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return storage.ErrClosed
	}
	var closeErr error
	if w, ok := s.journals[fd]; ok {
		// LevelDB requests retirement only after durable publication, or for
		// an empty/obsolete journal. Release even if unlink fails: the engine
		// can ignore that error and continue rotating; no live data relies on it.
		w.closed = true
		closeErr = w.Writer.Close()
		delete(s.journals, fd)
	}
	return errors.Join(closeErr, s.Storage.Remove(fd))
}

func (w *durabilityWriter) Write(p []byte) (int, error) {
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	if w.closed || w.store.closed {
		return 0, storage.ErrClosed
	}
	return w.Writer.Write(p)
}

func (w *durabilityWriter) Sync() error {
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	if w.closed || w.store.closed {
		return storage.ErrClosed
	}
	return w.Writer.Sync()
}

func (w *durabilityWriter) Close() error {
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	if w.closed || w.store.closed {
		return storage.ErrClosed
	}
	w.closed = true
	return nil
}

func (s *durabilityStorage) syncJournals() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return storage.ErrClosed
	}
	if s.syncDir == nil {
		return fmt.Errorf("LevelDB directory durability barrier unavailable")
	}
	for fd, w := range s.journals {
		if err := w.Writer.Sync(); err != nil {
			return fmt.Errorf("sync LevelDB journal %s: %w", fd, err)
		}
	}
	// Persist directory entries for new journals too. Use the same platform
	// directory-sync semantics as Pebble; propagate any supported I/O failure.
	if err := s.syncDir(); err != nil {
		return fmt.Errorf("sync LevelDB directory: %w", err)
	}
	return nil
}

func (s *durabilityStorage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	for fd, w := range s.journals {
		w.closed = true
		err = errors.Join(err, w.Writer.Close())
		delete(s.journals, fd)
	}
	return errors.Join(err, s.Storage.Close())
}
