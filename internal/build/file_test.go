// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package build

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// SYSCOIN: The generation gate must hash sources after dotfiles and excluded
// files, while keeping directory exclusions separate from similarly named paths.
func TestHashFolderExclusions(t *testing.T) {
	for _, absolute := range []bool{false, true} {
		name := "relative"
		if absolute {
			name = "absolute"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			files := map[string]string{
				".gitattributes":                "attributes",
				".gitignore":                    "ignored patterns",
				".github/workflows/test.yml":    "workflow",
				".git/config":                   "excluded git metadata",
				"build/cache/tool":              "excluded tool",
				"build/cache-extra/source.go":   "source next to cache",
				"build/cache-file":              "another cache sibling",
				"skip.txt":                      "excluded file",
				"zz-after-excluded-file/source": "source after excluded file",
			}
			for path, content := range files {
				full := filepath.Join(root, filepath.FromSlash(path))
				if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if !absolute {
				cwd, err := os.Getwd()
				if err != nil {
					t.Fatal(err)
				}
				root, err = filepath.Rel(cwd, root)
				if err != nil {
					t.Fatal(err)
				}
			}
			excluded := []string{".git", "build/cache/", "skip.txt"}
			before, err := HashFolder(root, excluded)
			if err != nil {
				t.Fatal(err)
			}
			want := make(map[string][32]byte)
			for path, content := range files {
				if path == ".git/config" || path == "build/cache/tool" || path == "skip.txt" {
					continue
				}
				want[filepath.Join(root, filepath.FromSlash(path))] = sha256.Sum256([]byte(content))
			}
			if !reflect.DeepEqual(before, want) {
				t.Fatalf("wrong hashed files or contents:\ngot %v\nwant %v", before, want)
			}
			var changed []string
			for _, path := range []string{".github/workflows/test.yml", "zz-after-excluded-file/source"} {
				full := filepath.Join(root, filepath.FromSlash(path))
				if err := os.WriteFile(full, []byte("changed"), 0o600); err != nil {
					t.Fatal(err)
				}
				changed = append(changed, full)
			}
			after, err := HashFolder(root, excluded)
			if err != nil {
				t.Fatal(err)
			}
			sort.Strings(changed)
			if got := DiffHashes(before, after); !reflect.DeepEqual(got, changed) {
				t.Fatalf("source edits were not detected: got %v, want %v", got, changed)
			}
		})
	}
}

// SYSCOIN: A failed walk must return its cause before examining a nil entry.
func TestHashFolderWalkError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	hashes, err := HashFolder(missing, nil)
	if !errors.Is(err, os.ErrNotExist) || hashes != nil {
		t.Fatalf("got hashes %v, error %v; want no hashes and a missing-path error", hashes, err)
	}
}
