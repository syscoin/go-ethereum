// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package leveldb

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/storage"
)

// generationStorage models loss of unsynchronized file bytes, independently
// for every journal/table/manifest generation. Closing a writer does not
// persist it. A crash image is copied before closing the live LevelDB engine.
type generationStorage struct {
	storage.Storage
	mu           sync.Mutex
	files        map[storage.FileDesc]*generationFile
	meta         storage.FileDesc
	journals     []storage.FileDesc
	tableStarted chan struct{}
	tableRelease chan struct{}
	tableOnce    sync.Once
}

type generationFile struct {
	live, durable []byte
	closed        bool
	syncs         int
	failSync      bool
}

type generationWriter struct {
	storage.Writer
	store *generationStorage
	fd    storage.FileDesc
}

func newGenerationStorage() *generationStorage {
	return &generationStorage{Storage: storage.NewMemStorage(), files: make(map[storage.FileDesc]*generationFile)}
}

func (s *generationStorage) Create(fd storage.FileDesc) (storage.Writer, error) {
	if fd.Type == storage.TypeTable && s.tableStarted != nil {
		s.tableOnce.Do(func() { close(s.tableStarted) })
		<-s.tableRelease
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w, err := s.Storage.Create(fd)
	if err != nil {
		return nil, err
	}
	s.files[fd] = new(generationFile)
	if fd.Type == storage.TypeJournal {
		s.journals = append(s.journals, fd)
	}
	return &generationWriter{Writer: w, store: s, fd: fd}, nil
}

func (s *generationStorage) SetMeta(fd storage.FileDesc) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.Storage.SetMeta(fd); err != nil {
		return err
	}
	// Model the atomic manifest pointer as durable. This deliberately does not
	// grant durability to any unsynchronized contents of the referenced files.
	s.meta = fd
	return nil
}

func (s *generationStorage) Remove(fd storage.FileDesc) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.Storage.Remove(fd); err != nil {
		return err
	}
	delete(s.files, fd)
	return nil
}

func (s *generationStorage) Rename(from, to storage.FileDesc) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.Storage.Rename(from, to); err != nil {
		return err
	}
	s.files[to] = s.files[from]
	delete(s.files, from)
	return nil
}

func (w *generationWriter) Write(p []byte) (int, error) {
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	n, err := w.Writer.Write(p)
	w.store.files[w.fd].live = append(w.store.files[w.fd].live, p[:n]...)
	return n, err
}

func (w *generationWriter) Sync() error {
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	if w.store.files[w.fd].failSync {
		return errors.New("injected generation sync failure")
	}
	if err := w.Writer.Sync(); err != nil {
		return err
	}
	f := w.store.files[w.fd]
	f.durable = bytes.Clone(f.live)
	f.syncs++
	return nil
}

func (w *generationWriter) Close() error {
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	w.store.files[w.fd].closed = true
	return w.Writer.Close()
}

func (s *generationStorage) crashImage(t *testing.T) storage.Storage {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	image := storage.NewMemStorage()
	for fd, f := range s.files {
		w, err := image.Create(fd)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(f.durable); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := image.SetMeta(s.meta); err != nil {
		t.Fatal(err)
	}
	return image
}

func checkRecoveredMetadata(t *testing.T, image storage.Storage, want string) {
	t.Helper()
	reopened, err := leveldb.Open(image, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	for _, key := range []string{"pair", "head", "canonical"} {
		got, err := reopened.Get([]byte(key), nil)
		if err != nil || string(got) != want {
			t.Errorf("crash-recovered %s = %q, %v; want %q", key, got, err, want)
		}
	}
}

// A fence must cover the previous WAL while its frozen memtable has
// not yet published a table. Syncing only a marker in the new WAL loses P.
func TestSyncKeyValueRotatedWAL(t *testing.T) {
	for _, mode := range []string{"success", "empty-current", "old-sync-error", "current-sync-error", "directory-error", "missing-directory"} {
		t.Run(mode, func(t *testing.T) { testSyncRotatedWAL(t, mode) })
	}
}

func testSyncRotatedWAL(t *testing.T, mode string) {
	store := newGenerationStorage()
	store.tableStarted = make(chan struct{})
	store.tableRelease = make(chan struct{})
	directoryCalls := 0
	failDirectory := mode == "directory-error"
	var syncDirectory func() error
	if mode != "missing-directory" {
		syncDirectory = func() error {
			directoryCalls++
			if failDirectory {
				return errors.New("injected directory sync failure")
			}
			return nil
		}
	}
	wrapped := newDurabilityStorage(store, syncDirectory)
	engine, err := leveldb.Open(wrapped, &opt.Options{WriteBuffer: 256, NoWriteMerge: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		close(store.tableRelease)
		if err := engine.Close(); err != nil {
			t.Error(err)
		}
		if err := wrapped.Close(); err != nil {
			t.Error(err)
		}
	}()
	db := &Database{db: engine, storage: wrapped}
	batch := new(leveldb.Batch)
	for _, key := range []string{"pair", "head", "canonical"} {
		batch.Put([]byte(key), []byte("C"))
	}
	if err := engine.Write(batch, &opt.WriteOptions{Sync: true}); err != nil {
		t.Fatal(err)
	}
	checkRecoveredMetadata(t, store.crashImage(t), "C")
	batch.Reset()
	for _, key := range []string{"pair", "head", "canonical"} {
		batch.Put([]byte(key), []byte("P"))
	}
	if err := engine.Write(batch, nil); err != nil {
		t.Fatal(err)
	}
	// The first size rotates before writing. The second exactly fills the
	// old memtable (88 metadata bytes + 15 key/type bytes + 153 value bytes),
	// so normal post-write rotation leaves the current WAL completely empty.
	padding := 160
	if mode == "empty-current" {
		padding = 153
	}
	if err := db.Put([]byte("padding"), bytes.Repeat([]byte{0x61}, padding)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-store.tableStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("normal writes did not rotate a memtable")
	}
	store.mu.Lock()
	generations := len(store.journals)
	if generations != 2 {
		store.mu.Unlock()
		t.Fatalf("journal generations = %d, want 2", generations)
	}
	oldFD, currentFD := store.journals[0], store.journals[1]
	old, current := store.files[oldFD], store.files[currentFD]
	closed, unsynced := old.closed, len(old.live) > len(old.durable)
	oldSyncs, currentSyncs, currentBytes := old.syncs, current.syncs, len(current.live)
	store.mu.Unlock()
	if closed || !unsynced {
		t.Fatal("wrapper did not retain the older unsynchronized WAL writer")
	}
	if oldSyncs != 1 || currentSyncs != 0 || directoryCalls != 0 {
		t.Fatalf("ordinary asynchronous writes added durability work: old=%d current=%d directory=%d", oldSyncs, currentSyncs, directoryCalls)
	}
	if mode == "empty-current" && currentBytes != 0 {
		t.Fatalf("current WAL has %d bytes, want empty", currentBytes)
	}
	if value, err := db.Get([]byte("pair")); err != nil || string(value) != "P" {
		t.Fatalf("live pair = %q, %v; want P", value, err)
	}
	checkRecoveredMetadata(t, store.crashImage(t), "C")
	if mode == "old-sync-error" || mode == "current-sync-error" {
		store.mu.Lock()
		fd := oldFD
		if mode == "current-sync-error" {
			fd = currentFD
		}
		store.files[fd].failSync = true
		store.mu.Unlock()
	}
	if mode != "success" && mode != "empty-current" {
		if err := db.SyncKeyValue(); err == nil {
			t.Fatal("failed durability component produced a successful acknowledgement")
		}
		if mode == "missing-directory" {
			return
		}
		if mode != "directory-error" && directoryCalls != 0 {
			t.Fatal("directory barrier ran after a failed WAL sync")
		}
		failDirectory = false
		store.mu.Lock()
		store.files[oldFD].failSync = false
		store.files[currentFD].failSync = false
		store.mu.Unlock()
	}
	if err := db.SyncKeyValue(); err != nil {
		t.Fatal(err)
	}
	wantDirectoryCalls := 1
	if mode == "directory-error" {
		wantDirectoryCalls = 2
	}
	if directoryCalls != wantDirectoryCalls {
		t.Fatalf("directory barriers = %d, want %d", directoryCalls, wantDirectoryCalls)
	}
	// The snapshot is taken with compaction still blocked and before the live
	// engine's clean Close, so neither can conceal a false acknowledgement.
	checkRecoveredMetadata(t, store.crashImage(t), "P")
}

type syncCountingStorage struct {
	storage.Storage
	syncs atomic.Int32
	fail  atomic.Bool
}

type syncCountingWriter struct {
	storage.Writer
	store *syncCountingStorage
}

func (s *syncCountingStorage) Create(fd storage.FileDesc) (storage.Writer, error) {
	w, err := s.Storage.Create(fd)
	if err == nil && fd.Type == storage.TypeJournal {
		return &syncCountingWriter{Writer: w, store: s}, nil
	}
	return w, err
}

func (w *syncCountingWriter) Sync() error {
	w.store.syncs.Add(1)
	if w.store.fail.Load() {
		return errors.New("injected WAL sync failure")
	}
	return w.Writer.Sync()
}

// SYSCOIN: the real LevelDB writer must issue a WAL sync, including failures.
func TestSyncKeyValueWAL(t *testing.T) {
	for _, fail := range []bool{false, true} {
		store := &syncCountingStorage{Storage: storage.NewMemStorage()}
		wrapped := newDurabilityStorage(store, func() error { return nil })
		engine, err := leveldb.Open(wrapped, nil)
		if err != nil {
			t.Fatal(err)
		}
		db := &Database{db: engine, storage: wrapped}
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
		if err := wrapped.Close(); err != nil {
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
