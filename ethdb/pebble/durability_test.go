// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package pebble

import (
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
)

// SYSCOIN: discard unsynced WAL bytes before reopening the real Pebble engine.
func TestSyncKeyValueCrash(t *testing.T) {
	for _, fence := range []bool{false, true} {
		name := "without-fence"
		if fence {
			name = "with-fence"
		}
		t.Run(name, func(t *testing.T) {
			fs := vfs.NewStrictMem()
			// The database directory already exists before recovery. Use the
			// strict FS root, as Pebble's own crash/WAL tests do, so this test
			// discards database writes rather than an unsynced parent mkdir.
			engine, err := pebble.Open("", &pebble.Options{FS: fs})
			if err != nil {
				t.Fatal(err)
			}
			db := &Database{db: engine, writeOptions: pebble.NoSync}
			if err := db.Put([]byte("pair"), []byte("C")); err != nil {
				t.Fatal(err)
			}
			if err := db.SyncKeyValue(); err != nil {
				t.Fatal(err)
			}
			if err := db.Put([]byte("pair"), []byte("P")); err != nil {
				t.Fatal(err)
			}
			if fence {
				if err := db.SyncKeyValue(); err != nil {
					t.Fatal(err)
				}
			}
			fs.SetIgnoreSyncs(true)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			fs.ResetToSyncedState()
			fs.SetIgnoreSyncs(false)
			reopened, err := pebble.Open("", &pebble.Options{FS: fs})
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			value, closer, err := reopened.Get([]byte("pair"))
			if err != nil {
				t.Fatal(err)
			}
			defer closer.Close()
			want := "C"
			if fence {
				want = "P"
			}
			if string(value) != want {
				t.Fatalf("crash pair %q, want %q", value, want)
			}
			if err := db.SyncKeyValue(); err == nil {
				t.Fatal("closed backend acknowledged durability")
			}
		})
	}
}
