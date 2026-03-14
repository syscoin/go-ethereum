// Copyright 2026 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/internal/build"
	"github.com/ethereum/go-ethereum/node"
	"github.com/urfave/cli/v2"
)

type errCloser struct {
	err error
}

func (e errCloser) Close() error {
	return e.err
}

func TestFindChaindataRoot(t *testing.T) {
	t.Run("direct", func(t *testing.T) {
		stage := t.TempDir()
		want := filepath.Join(stage, "chaindata")
		if err := os.MkdirAll(want, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		got, err := findChaindataRoot(stage)
		if err != nil {
			t.Fatalf("findChaindataRoot error: %v", err)
		}
		if got != want {
			t.Fatalf("wrong chaindata root: got %s want %s", got, want)
		}
	})

	t.Run("nested", func(t *testing.T) {
		stage := t.TempDir()
		want := filepath.Join(stage, "bootstrap-v1", "chaindata")
		if err := os.MkdirAll(want, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		got, err := findChaindataRoot(stage)
		if err != nil {
			t.Fatalf("findChaindataRoot error: %v", err)
		}
		if got != want {
			t.Fatalf("wrong chaindata root: got %s want %s", got, want)
		}
	})

	t.Run("missing", func(t *testing.T) {
		stage := t.TempDir()
		if _, err := findChaindataRoot(stage); err == nil {
			t.Fatal("expected error for missing chaindata")
		}
	})
}

func TestShouldInstallBootstrap(t *testing.T) {
	t.Run("force", func(t *testing.T) {
		install, err := shouldInstallBootstrap(filepath.Join(t.TempDir(), "missing"), true)
		if err != nil {
			t.Fatalf("shouldInstallBootstrap error: %v", err)
		}
		if !install {
			t.Fatal("expected install=true in force mode")
		}
	})

	t.Run("missing", func(t *testing.T) {
		install, err := shouldInstallBootstrap(filepath.Join(t.TempDir(), "missing"), false)
		if err != nil {
			t.Fatalf("shouldInstallBootstrap error: %v", err)
		}
		if !install {
			t.Fatal("expected install=true for missing chaindata")
		}
	})

	t.Run("non-empty", func(t *testing.T) {
		chaindata := filepath.Join(t.TempDir(), "chaindata")
		if err := os.MkdirAll(chaindata, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(chaindata, "CURRENT"), []byte("x"), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}
		install, err := shouldInstallBootstrap(chaindata, false)
		if err != nil {
			t.Fatalf("shouldInstallBootstrap error: %v", err)
		}
		if install {
			t.Fatal("expected install=false for non-empty chaindata")
		}
	})
}

func TestCreateBootstrapArchive(t *testing.T) {
	testCases := []struct {
		name string
		ext  string
	}{
		{name: "tar.gz", ext: ".tar.gz"},
		{name: "zip", ext: ".zip"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			chaindata := filepath.Join(root, "chaindata")
			if err := os.MkdirAll(filepath.Join(chaindata, "nested"), 0o755); err != nil {
				t.Fatalf("mkdir chaindata: %v", err)
			}
			dataA := []byte("alpha")
			dataB := []byte("beta")
			if err := os.WriteFile(filepath.Join(chaindata, "CURRENT"), dataA, 0o644); err != nil {
				t.Fatalf("write CURRENT: %v", err)
			}
			if err := os.WriteFile(filepath.Join(chaindata, "nested", "000001.sst"), dataB, 0o644); err != nil {
				t.Fatalf("write nested file: %v", err)
			}
			if err := os.WriteFile(filepath.Join(root, "unrelated.txt"), []byte("skip-me"), 0o644); err != nil {
				t.Fatalf("write unrelated file: %v", err)
			}

			archivePath := filepath.Join(t.TempDir(), "state-bootstrap"+tc.ext)
			manifest, err := createBootstrapArchive(chaindata, archivePath)
			if err != nil {
				t.Fatalf("createBootstrapArchive error: %v", err)
			}
			if manifest.FileCount != 2 {
				t.Fatalf("unexpected file count: got %d want 2", manifest.FileCount)
			}
			wantSize := int64(len(dataA) + len(dataB))
			if manifest.TotalBytes != wantSize {
				t.Fatalf("unexpected total bytes: got %d want %d", manifest.TotalBytes, wantSize)
			}
			if len(manifest.ArchiveSHA256) != 64 {
				t.Fatalf("unexpected sha256 length: got %d", len(manifest.ArchiveSHA256))
			}

			stage := t.TempDir()
			if err := build.ExtractArchive(archivePath, stage); err != nil {
				t.Fatalf("extract archive: %v", err)
			}
			gotChaindata, err := findChaindataRoot(stage)
			if err != nil {
				t.Fatalf("find extracted chaindata: %v", err)
			}
			gotA, err := os.ReadFile(filepath.Join(gotChaindata, "CURRENT"))
			if err != nil {
				t.Fatalf("read extracted CURRENT: %v", err)
			}
			if string(gotA) != string(dataA) {
				t.Fatalf("wrong CURRENT data: got %q want %q", string(gotA), string(dataA))
			}
			gotB, err := os.ReadFile(filepath.Join(gotChaindata, "nested", "000001.sst"))
			if err != nil {
				t.Fatalf("read extracted nested file: %v", err)
			}
			if string(gotB) != string(dataB) {
				t.Fatalf("wrong nested data: got %q want %q", string(gotB), string(dataB))
			}
			if _, err := os.Stat(filepath.Join(stage, stateBootstrapArchiveRoot, "unrelated.txt")); !os.IsNotExist(err) {
				t.Fatalf("unexpected unrelated file present in archive: %v", err)
			}

			manifestPath := filepath.Join(t.TempDir(), "bootstrap.manifest.json")
			if err := writeBootstrapManifest(manifestPath, manifest); err != nil {
				t.Fatalf("write manifest: %v", err)
			}
			manifestData, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatalf("read manifest: %v", err)
			}
			var decoded stateBootstrapManifest
			if err := json.Unmarshal(manifestData, &decoded); err != nil {
				t.Fatalf("decode manifest: %v", err)
			}
			if decoded.ArchiveSHA256 != manifest.ArchiveSHA256 {
				t.Fatalf("manifest sha mismatch: got %s want %s", decoded.ArchiveSHA256, manifest.ArchiveSHA256)
			}
		})
	}
}

func TestRecordCloseErrorSetsErrorOnSuccessfulWrite(t *testing.T) {
	closeErr := errors.New("close failed")
	var err error

	recordCloseError(&err, "finalize archive", errCloser{err: closeErr}.Close)

	if !errors.Is(err, closeErr) {
		t.Fatalf("expected close error to be returned, got %v", err)
	}
	if !strings.Contains(err.Error(), "finalize archive") {
		t.Fatalf("expected action context in error, got %v", err)
	}
}

func TestRecordCloseErrorPreservesExistingError(t *testing.T) {
	writeErr := errors.New("write failed")
	closeErr := errors.New("close failed")
	err := writeErr

	recordCloseError(&err, "finalize archive", errCloser{err: closeErr}.Close)

	if !errors.Is(err, writeErr) {
		t.Fatalf("expected original write error to be preserved, got %v", err)
	}
	if errors.Is(err, closeErr) {
		t.Fatalf("unexpected close error replacing original error: %v", err)
	}
}

func TestResolveBootstrapArchivePath(t *testing.T) {
	t.Run("explicit relative file path", func(t *testing.T) {
		want, err := filepath.Abs("custom-bootstrap.zip")
		if err != nil {
			t.Fatalf("resolve expected path: %v", err)
		}
		got, err := resolveBootstrapArchivePath(t.TempDir(), "custom-bootstrap.zip", "https://example.invalid/bootstrap.tar.gz")
		if err != nil {
			t.Fatalf("resolveBootstrapArchivePath error: %v", err)
		}
		if got != want {
			t.Fatalf("unexpected archive path: got %s want %s", got, want)
		}
	})

	t.Run("infer zip from url", func(t *testing.T) {
		instanceDir := t.TempDir()
		got, err := resolveBootstrapArchivePath(instanceDir, "", "https://example.invalid/releases/bootstrap.zip")
		if err != nil {
			t.Fatalf("resolveBootstrapArchivePath error: %v", err)
		}
		want := filepath.Join(instanceDir, "state-bootstrap.zip")
		if got != want {
			t.Fatalf("unexpected archive path: got %s want %s", got, want)
		}
	})

	t.Run("infer tar gz from url with query string", func(t *testing.T) {
		instanceDir := t.TempDir()
		got, err := resolveBootstrapArchivePath(instanceDir, "", "https://example.invalid/releases/bootstrap.tar.gz?download=1")
		if err != nil {
			t.Fatalf("resolveBootstrapArchivePath error: %v", err)
		}
		want := filepath.Join(instanceDir, "state-bootstrap.tar.gz")
		if got != want {
			t.Fatalf("unexpected archive path: got %s want %s", got, want)
		}
	})

	t.Run("reject url without supported extension", func(t *testing.T) {
		_, err := resolveBootstrapArchivePath(t.TempDir(), "", "https://example.invalid/releases/bootstrap")
		if err == nil {
			t.Fatal("expected error for unsupported bootstrap URL extension")
		}
		if !strings.Contains(err.Error(), utils.StateBootstrapFileFlag.Name) {
			t.Fatalf("expected error to mention explicit file flag, got %v", err)
		}
	})
}

func TestInstallBootstrapArchiveReplacesExistingChaindata(t *testing.T) {
	root := t.TempDir()
	instanceDir := filepath.Join(root, "instance")
	if err := os.MkdirAll(instanceDir, 0o755); err != nil {
		t.Fatalf("mkdir instance: %v", err)
	}

	chaindataPath := filepath.Join(instanceDir, "chaindata")
	if err := os.MkdirAll(chaindataPath, 0o755); err != nil {
		t.Fatalf("mkdir existing chaindata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(chaindataPath, "CURRENT"), []byte("old-state"), 0o644); err != nil {
		t.Fatalf("write existing CURRENT: %v", err)
	}

	sourceChaindata := filepath.Join(root, "source-chaindata")
	if err := os.MkdirAll(filepath.Join(sourceChaindata, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir source chaindata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceChaindata, "CURRENT"), []byte("new-state"), 0o644); err != nil {
		t.Fatalf("write source CURRENT: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceChaindata, "nested", "000001.sst"), []byte("snapshot"), 0o644); err != nil {
		t.Fatalf("write source nested file: %v", err)
	}

	archivePath := filepath.Join(root, "state-bootstrap.tar.gz")
	if _, err := createBootstrapArchive(sourceChaindata, archivePath); err != nil {
		t.Fatalf("createBootstrapArchive error: %v", err)
	}

	if err := installBootstrapArchive(instanceDir, chaindataPath, archivePath); err != nil {
		t.Fatalf("installBootstrapArchive error: %v", err)
	}

	gotCurrent, err := os.ReadFile(filepath.Join(chaindataPath, "CURRENT"))
	if err != nil {
		t.Fatalf("read installed CURRENT: %v", err)
	}
	if string(gotCurrent) != "new-state" {
		t.Fatalf("unexpected CURRENT content: got %q want %q", string(gotCurrent), "new-state")
	}
	gotNested, err := os.ReadFile(filepath.Join(chaindataPath, "nested", "000001.sst"))
	if err != nil {
		t.Fatalf("read installed nested file: %v", err)
	}
	if string(gotNested) != "snapshot" {
		t.Fatalf("unexpected nested content: got %q want %q", string(gotNested), "snapshot")
	}
}

func TestInstallBootstrapArchivePreservesExistingChaindataOnInstallFailure(t *testing.T) {
	root := t.TempDir()
	instanceDir := filepath.Join(root, "instance")
	if err := os.MkdirAll(instanceDir, 0o755); err != nil {
		t.Fatalf("mkdir instance: %v", err)
	}

	chaindataPath := filepath.Join(instanceDir, "chaindata")
	if err := os.MkdirAll(chaindataPath, 0o755); err != nil {
		t.Fatalf("mkdir existing chaindata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(chaindataPath, "CURRENT"), []byte("old-state"), 0o644); err != nil {
		t.Fatalf("write existing CURRENT: %v", err)
	}

	sourceChaindata := filepath.Join(root, "source-chaindata")
	if err := os.MkdirAll(sourceChaindata, 0o755); err != nil {
		t.Fatalf("mkdir source chaindata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceChaindata, "CURRENT"), []byte("new-state"), 0o644); err != nil {
		t.Fatalf("write source CURRENT: %v", err)
	}

	archivePath := filepath.Join(root, "state-bootstrap.tar.gz")
	if _, err := createBootstrapArchive(sourceChaindata, archivePath); err != nil {
		t.Fatalf("createBootstrapArchive error: %v", err)
	}

	sentinel := errors.New("injected install failure")
	prevMoveOrCopyDirFn := moveOrCopyDirFn
	moveOrCopyDirFn = func(_, _ string) error {
		return sentinel
	}
	t.Cleanup(func() {
		moveOrCopyDirFn = prevMoveOrCopyDirFn
	})

	err := installBootstrapArchive(instanceDir, chaindataPath, archivePath)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected injected install failure, got %v", err)
	}

	gotCurrent, readErr := os.ReadFile(filepath.Join(chaindataPath, "CURRENT"))
	if readErr != nil {
		t.Fatalf("read preserved CURRENT: %v", readErr)
	}
	if string(gotCurrent) != "old-state" {
		t.Fatalf("existing CURRENT was not preserved: got %q want %q", string(gotCurrent), "old-state")
	}
}

func TestCreateBootstrapArchiveUnsupportedExtension(t *testing.T) {
	chaindata := filepath.Join(t.TempDir(), "chaindata")
	if err := os.MkdirAll(chaindata, 0o755); err != nil {
		t.Fatalf("mkdir chaindata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(chaindata, "CURRENT"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write CURRENT: %v", err)
	}

	_, err := createBootstrapArchive(chaindata, filepath.Join(t.TempDir(), "bootstrap.tgz"))
	if err == nil {
		t.Fatal("expected unsupported extension error")
	}
	if !strings.Contains(err.Error(), "unsupported bootstrap archive extension") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEnsureArchiveAvailable(t *testing.T) {
	t.Run("existing file", func(t *testing.T) {
		archivePath := filepath.Join(t.TempDir(), "state-bootstrap.tar.gz")
		if err := os.WriteFile(archivePath, []byte("existing"), 0o644); err != nil {
			t.Fatalf("write archive: %v", err)
		}
		downloaded, err := ensureArchiveAvailable(archivePath, "https://example.invalid/bootstrap.tar.gz")
		if err != nil {
			t.Fatalf("ensureArchiveAvailable error: %v", err)
		}
		if downloaded {
			t.Fatal("expected downloaded=false for existing archive")
		}
	})

	t.Run("missing without url", func(t *testing.T) {
		archivePath := filepath.Join(t.TempDir(), "state-bootstrap.tar.gz")
		downloaded, err := ensureArchiveAvailable(archivePath, "")
		if err == nil {
			t.Fatal("expected error for missing archive without URL")
		}
		if downloaded {
			t.Fatal("expected downloaded=false when download did not happen")
		}
	})

	t.Run("download missing file", func(t *testing.T) {
		payload := []byte("bootstrap-download")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(payload)
		}))
		defer server.Close()

		archivePath := filepath.Join(t.TempDir(), "state-bootstrap.tar.gz")
		downloaded, err := ensureArchiveAvailable(archivePath, server.URL)
		if err != nil {
			t.Fatalf("ensureArchiveAvailable error: %v", err)
		}
		if !downloaded {
			t.Fatal("expected downloaded=true for URL fetch")
		}
		got, err := os.ReadFile(archivePath)
		if err != nil {
			t.Fatalf("read downloaded archive: %v", err)
		}
		if string(got) != string(payload) {
			t.Fatalf("unexpected downloaded content: got %q want %q", string(got), string(payload))
		}
	})

	t.Run("retry on transient server errors", func(t *testing.T) {
		payload := []byte("bootstrap-download-after-retry")
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attempts++
			if attempts < stateBootstrapDownloadMaxRetries {
				http.Error(w, "temporary upstream failure", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write(payload)
		}))
		defer server.Close()

		archivePath := filepath.Join(t.TempDir(), "state-bootstrap.tar.gz")
		downloaded, err := ensureArchiveAvailable(archivePath, server.URL)
		if err != nil {
			t.Fatalf("ensureArchiveAvailable error: %v", err)
		}
		if !downloaded {
			t.Fatal("expected downloaded=true after retries")
		}
		if attempts != stateBootstrapDownloadMaxRetries {
			t.Fatalf("unexpected retry attempts: got %d want %d", attempts, stateBootstrapDownloadMaxRetries)
		}
		got, err := os.ReadFile(archivePath)
		if err != nil {
			t.Fatalf("read downloaded archive: %v", err)
		}
		if string(got) != string(payload) {
			t.Fatalf("unexpected downloaded content: got %q want %q", string(got), string(payload))
		}
	})
}

func TestCleanupDownloadedBootstrapArchive(t *testing.T) {
	t.Run("keep local archive", func(t *testing.T) {
		archivePath := filepath.Join(t.TempDir(), "state-bootstrap.tar.gz")
		if err := os.WriteFile(archivePath, []byte("local"), 0o644); err != nil {
			t.Fatalf("write archive: %v", err)
		}
		cleanupDownloadedBootstrapArchive(archivePath, false)
		if _, err := os.Stat(archivePath); err != nil {
			t.Fatalf("expected archive to remain: %v", err)
		}
	})

	t.Run("remove downloaded archive", func(t *testing.T) {
		archivePath := filepath.Join(t.TempDir(), "state-bootstrap.tar.gz")
		if err := os.WriteFile(archivePath, []byte("downloaded"), 0o644); err != nil {
			t.Fatalf("write archive: %v", err)
		}
		cleanupDownloadedBootstrapArchive(archivePath, true)
		if _, err := os.Stat(archivePath); !os.IsNotExist(err) {
			t.Fatalf("expected archive to be removed, stat err=%v", err)
		}
	})
}

func TestMaybeBootstrapStateRemovesDownloadedArchive(t *testing.T) {
	root := t.TempDir()

	sourceChaindata := filepath.Join(root, "source-chaindata")
	if err := os.MkdirAll(sourceChaindata, 0o755); err != nil {
		t.Fatalf("mkdir source chaindata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceChaindata, "CURRENT"), []byte("snapshot"), 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}
	sourceArchive := filepath.Join(root, "source-bootstrap.tar.gz")
	if _, err := createBootstrapArchive(sourceChaindata, sourceArchive); err != nil {
		t.Fatalf("create source archive: %v", err)
	}
	payload, err := os.ReadFile(sourceArchive)
	if err != nil {
		t.Fatalf("read source archive: %v", err)
	}
	sourceArchiveSHA256, err := hashFileSHA256(sourceArchive)
	if err != nil {
		t.Fatalf("hash source archive: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	stack, err := node.New(&node.Config{DataDir: filepath.Join(root, "datadir"), Name: "geth"})
	if err != nil {
		t.Fatalf("create test node: %v", err)
	}
	defer stack.Close()

	downloadPath := filepath.Join(stack.InstanceDir(), "downloaded-bootstrap.tar.gz")

	flagset := flag.NewFlagSet("statebootstrap", flag.ContinueOnError)
	flagset.String(utils.StateBootstrapFileFlag.Name, "", "")
	flagset.String(utils.StateBootstrapURLFlag.Name, "", "")
	flagset.String(utils.StateBootstrapSHA256Flag.Name, "", "")
	flagset.Bool(utils.StateBootstrapForceFlag.Name, false, "")
	flagset.Bool(utils.SepoliaFlag.Name, false, "")
	if err := flagset.Set(utils.StateBootstrapFileFlag.Name, downloadPath); err != nil {
		t.Fatalf("set file flag: %v", err)
	}
	if err := flagset.Set(utils.StateBootstrapURLFlag.Name, server.URL); err != nil {
		t.Fatalf("set url flag: %v", err)
	}
	if err := flagset.Set(utils.StateBootstrapSHA256Flag.Name, sourceArchiveSHA256); err != nil {
		t.Fatalf("set sha256 flag: %v", err)
	}
	// Avoid inheriting the built-in Syscoin default hash in this unit test.
	if err := flagset.Set(utils.SepoliaFlag.Name, "true"); err != nil {
		t.Fatalf("set sepolia flag: %v", err)
	}

	ctx := cli.NewContext(cli.NewApp(), flagset, nil)
	if err := maybeBootstrapState(ctx, stack); err != nil {
		t.Fatalf("maybeBootstrapState error: %v", err)
	}

	if _, err := os.Stat(downloadPath); !os.IsNotExist(err) {
		t.Fatalf("expected downloaded archive to be removed after install, stat err=%v", err)
	}
	installedCurrent := filepath.Join(stack.ResolvePath("chaindata"), "CURRENT")
	currentData, err := os.ReadFile(installedCurrent)
	if err != nil {
		t.Fatalf("read installed chaindata: %v", err)
	}
	if string(currentData) != "snapshot" {
		t.Fatalf("unexpected installed state content: got %q want %q", string(currentData), "snapshot")
	}
}

func TestResolveStateBootstrapSHA256(t *testing.T) {
	makeCtx := func(setters map[string]string) *cli.Context {
		t.Helper()
		fs := flag.NewFlagSet("statebootstrap-sha-resolver", flag.ContinueOnError)
		fs.String(utils.StateBootstrapSHA256Flag.Name, "", "")
		fs.Bool(utils.SyscoinFlag.Name, false, "")
		fs.Bool(utils.TanenbaumFlag.Name, false, "")
		fs.Bool(utils.SepoliaFlag.Name, false, "")
		fs.Bool(utils.HoleskyFlag.Name, false, "")
		fs.Bool(utils.HoodiFlag.Name, false, "")
		fs.Bool(utils.MainnetFlag.Name, false, "")
		for key, value := range setters {
			if err := fs.Set(key, value); err != nil {
				t.Fatalf("set %s: %v", key, err)
			}
		}
		return cli.NewContext(cli.NewApp(), fs, nil)
	}

	t.Run("explicit override takes precedence", func(t *testing.T) {
		ctx := makeCtx(map[string]string{
			utils.SyscoinFlag.Name:              "true",
			utils.StateBootstrapSHA256Flag.Name: strings.Repeat("a", 64),
		})
		gotSHA, gotNetwork, fromDefault := resolveStateBootstrapSHA256(ctx, ctx.String(utils.StateBootstrapSHA256Flag.Name))
		if gotSHA != strings.Repeat("a", 64) {
			t.Fatalf("unexpected override sha: got %s", gotSHA)
		}
		if gotNetwork != "" || fromDefault {
			t.Fatalf("unexpected default metadata: network=%q fromDefault=%v", gotNetwork, fromDefault)
		}
	})

	t.Run("tanenbaum default", func(t *testing.T) {
		ctx := makeCtx(map[string]string{utils.TanenbaumFlag.Name: "true"})
		gotSHA, gotNetwork, fromDefault := resolveStateBootstrapSHA256(ctx, "")
		if gotSHA != stateBootstrapDefaultSHA256Tanenbaum {
			t.Fatalf("wrong tanenbaum default sha: got %s want %s", gotSHA, stateBootstrapDefaultSHA256Tanenbaum)
		}
		if gotNetwork != "tanenbaum" || !fromDefault {
			t.Fatalf("unexpected default metadata: network=%q fromDefault=%v", gotNetwork, fromDefault)
		}
	})

	t.Run("syscoin default", func(t *testing.T) {
		ctx := makeCtx(map[string]string{utils.SyscoinFlag.Name: "true"})
		gotSHA, gotNetwork, fromDefault := resolveStateBootstrapSHA256(ctx, "")
		if gotSHA != stateBootstrapDefaultSHA256SyscoinMain {
			t.Fatalf("wrong syscoin default sha: got %s want %s", gotSHA, stateBootstrapDefaultSHA256SyscoinMain)
		}
		if gotNetwork != "syscoin" || !fromDefault {
			t.Fatalf("unexpected default metadata: network=%q fromDefault=%v", gotNetwork, fromDefault)
		}
	})

	t.Run("no preset has no default", func(t *testing.T) {
		ctx := makeCtx(nil)
		gotSHA, gotNetwork, fromDefault := resolveStateBootstrapSHA256(ctx, "")
		if gotSHA != "" {
			t.Fatalf("expected empty default sha, got %s", gotSHA)
		}
		if gotNetwork != "" || fromDefault {
			t.Fatalf("unexpected default metadata: network=%q fromDefault=%v", gotNetwork, fromDefault)
		}
	})

	t.Run("non-syscoin preset has no default", func(t *testing.T) {
		ctx := makeCtx(map[string]string{utils.SepoliaFlag.Name: "true"})
		gotSHA, gotNetwork, fromDefault := resolveStateBootstrapSHA256(ctx, "")
		if gotSHA != "" {
			t.Fatalf("expected empty default sha, got %s", gotSHA)
		}
		if gotNetwork != "" || fromDefault {
			t.Fatalf("unexpected default metadata: network=%q fromDefault=%v", gotNetwork, fromDefault)
		}
	})
}

func TestMaybeBootstrapStateURLRequiresSHAWhenNoDefault(t *testing.T) {
	root := t.TempDir()
	stack, err := node.New(&node.Config{DataDir: filepath.Join(root, "datadir"), Name: "geth"})
	if err != nil {
		t.Fatalf("create test node: %v", err)
	}
	defer stack.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ignored"))
	}))
	defer server.Close()

	fs := flag.NewFlagSet("statebootstrap-url-no-sha", flag.ContinueOnError)
	fs.String(utils.StateBootstrapFileFlag.Name, "", "")
	fs.String(utils.StateBootstrapURLFlag.Name, "", "")
	fs.String(utils.StateBootstrapSHA256Flag.Name, "", "")
	fs.Bool(utils.StateBootstrapForceFlag.Name, false, "")
	fs.Bool(utils.SepoliaFlag.Name, false, "")
	if err := fs.Set(utils.StateBootstrapFileFlag.Name, filepath.Join(stack.InstanceDir(), "missing.tar.gz")); err != nil {
		t.Fatalf("set file flag: %v", err)
	}
	if err := fs.Set(utils.StateBootstrapURLFlag.Name, server.URL); err != nil {
		t.Fatalf("set url flag: %v", err)
	}
	// Use a non-Syscoin preset to guarantee there is no built-in SHA default.
	if err := fs.Set(utils.SepoliaFlag.Name, "true"); err != nil {
		t.Fatalf("set sepolia flag: %v", err)
	}

	ctx := cli.NewContext(cli.NewApp(), fs, nil)
	err = maybeBootstrapState(ctx, stack)
	if err == nil {
		t.Fatal("expected error for URL bootstrap without effective SHA")
	}
	if !strings.Contains(err.Error(), "requires SHA-256") {
		t.Fatalf("unexpected error: %v", err)
	}
}
