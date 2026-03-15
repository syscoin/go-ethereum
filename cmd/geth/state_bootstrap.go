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
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/internal/build"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/urfave/cli/v2"
)

type stateBootstrapConfig struct {
	filePath string
	url      string
	sha256   string
	force    bool
}

const (
	stateBootstrapArchiveRoot        = "state-bootstrap"
	stateBootstrapDownloadTimeout    = 2 * time.Hour
	stateBootstrapDownloadMaxRetries = 3
	// Release-managed defaults. Update these on each release when bootstrap artifacts rotate.
	stateBootstrapDefaultURLSyscoinMain    = "https://download.syscoin.org/state-bootstrap/syscoin-mainnet-latest.tar.gz"
	stateBootstrapDefaultURLTanenbaum      = "https://download.syscoin.org/state-bootstrap/tanenbaum-latest.tar.gz"
	stateBootstrapDefaultSHA256SyscoinMain = "658639bbc6c9e15495c7dcb5901637e27e6f9090ede0e56b28a9789a3efc2dfa"
	stateBootstrapDefaultSHA256Tanenbaum   = "c41deb5b54f93caaf748eee7f17464d3169b10cf4865181ed085c9cc2cbd2ddd"
)

type stateBootstrapManifest struct {
	FormatVersion   int    `json:"formatVersion"`
	CreatedAt       string `json:"createdAt"`
	ArchiveFile     string `json:"archiveFile"`
	ArchiveSHA256   string `json:"archiveSha256"`
	SourceChaindata string `json:"sourceChaindata"`
	FileCount       int    `json:"fileCount"`
	TotalBytes      int64  `json:"totalBytes"`
}

func maybeBootstrapState(ctx *cli.Context, stack *node.Node) error {
	cfg := stateBootstrapConfig{
		filePath: strings.TrimSpace(ctx.String(utils.StateBootstrapFileFlag.Name)),
		url:      strings.TrimSpace(ctx.String(utils.StateBootstrapURLFlag.Name)),
		sha256:   strings.TrimSpace(ctx.String(utils.StateBootstrapSHA256Flag.Name)),
		force:    ctx.Bool(utils.StateBootstrapForceFlag.Name),
	}
	if stack.InstanceDir() == "" {
		return errors.New("state bootstrap requires persistent --datadir")
	}

	chaindataPath := stack.ResolvePath("chaindata")
	install, err := shouldInstallBootstrap(chaindataPath, cfg.force)
	if err != nil {
		return err
	}
	if !install {
		log.Info("Skipping state bootstrap; existing chaindata detected", "chaindata", chaindataPath)
		return nil
	}

	effectiveURL, defaultURLNetwork, usingDefaultURL := resolveStateBootstrapURL(ctx, cfg.url)
	effectiveSHA256, defaultNetwork, usingDefaultSHA256 := resolveStateBootstrapSHA256(ctx, cfg.sha256)
	if cfg.filePath == "" && effectiveURL == "" {
		return nil
	}
	if usingDefaultURL {
		log.Info("Using built-in state bootstrap URL", "network", defaultURLNetwork, "url", effectiveURL)
	}
	if usingDefaultSHA256 {
		log.Info("Using built-in state bootstrap SHA-256", "network", defaultNetwork, "sha256", effectiveSHA256)
	}
	if effectiveURL != "" && effectiveSHA256 == "" {
		return fmt.Errorf("state bootstrap URL download requires SHA-256 via --%s or a built-in default for the selected network", utils.StateBootstrapSHA256Flag.Name)
	}

	archivePath, err := resolveBootstrapArchivePath(stack.InstanceDir(), cfg.filePath, effectiveURL)
	if err != nil {
		return err
	}
	downloadedArchive, err := ensureArchiveAvailable(archivePath, cfg.url)
	if err != nil {
		return err
	}
	if effectiveSHA256 != "" {
		if err := verifyArchiveSHA256(archivePath, effectiveSHA256); err != nil {
			return err
		}
	}
	if err := installBootstrapArchive(stack.InstanceDir(), chaindataPath, archivePath); err != nil {
		return err
	}
	cleanupDownloadedBootstrapArchive(archivePath, downloadedArchive)
	log.Info("State bootstrap import completed", "chaindata", chaindataPath, "archive", archivePath)
	return nil
}

func resolveStateBootstrapURL(ctx *cli.Context, configuredURL string) (url string, network string, fromDefault bool) {
	configuredURL = strings.TrimSpace(configuredURL)
	if configuredURL != "" {
		return configuredURL, "", false
	}
	switch {
	case ctx.Bool(utils.TanenbaumFlag.Name):
		return stateBootstrapDefaultURLTanenbaum, "tanenbaum", true
	case ctx.Bool(utils.SyscoinFlag.Name):
		return stateBootstrapDefaultURLSyscoinMain, "syscoin", true
	default:
		return "", "", false
	}
}

func resolveBootstrapArchivePath(instanceDir, filePath, sourceURL string) (string, error) {
	archivePath := strings.TrimSpace(filePath)
	if archivePath != "" {
		if !filepath.IsAbs(archivePath) {
			absPath, err := filepath.Abs(archivePath)
			if err != nil {
				return "", fmt.Errorf("resolve bootstrap archive path: %w", err)
			}
			return absPath, nil
		}
		return archivePath, nil
	}

	ext, err := inferBootstrapArchiveExtension(sourceURL)
	if err != nil {
		return "", err
	}
	return filepath.Join(instanceDir, "state-bootstrap"+ext), nil
}

func inferBootstrapArchiveExtension(sourceURL string) (string, error) {
	parsedURL, err := url.Parse(strings.TrimSpace(sourceURL))
	if err != nil {
		return "", fmt.Errorf("parse bootstrap URL: %w", err)
	}
	lowerPath := strings.ToLower(path.Clean(parsedURL.Path))
	switch {
	case strings.HasSuffix(lowerPath, ".tar.gz"):
		return ".tar.gz", nil
	case strings.HasSuffix(lowerPath, ".zip"):
		return ".zip", nil
	default:
		return "", fmt.Errorf("bootstrap URL must end with .tar.gz or .zip, or specify --%s explicitly", utils.StateBootstrapFileFlag.Name)
	}
}

func resolveStateBootstrapSHA256(ctx *cli.Context, configuredSHA256 string) (sha256 string, network string, fromDefault bool) {
	configuredSHA256 = strings.TrimSpace(configuredSHA256)
	if configuredSHA256 != "" {
		return configuredSHA256, "", false
	}
	if network, defaultSHA := defaultBootstrapSHA256ForNetwork(ctx); defaultSHA != "" {
		return defaultSHA, network, true
	}
	return "", "", false
}

func defaultBootstrapSHA256ForNetwork(ctx *cli.Context) (network string, sha256 string) {
	switch {
	case ctx.Bool(utils.TanenbaumFlag.Name):
		return "tanenbaum", stateBootstrapDefaultSHA256Tanenbaum
	case ctx.Bool(utils.SyscoinFlag.Name):
		return "syscoin", stateBootstrapDefaultSHA256SyscoinMain
	default:
		return "", ""
	}
}

func shouldInstallBootstrap(chaindataPath string, force bool) (bool, error) {
	if force {
		return true, nil
	}
	info, err := os.Stat(chaindataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, fmt.Errorf("stat chaindata: %w", err)
	}
	if !info.IsDir() {
		return false, fmt.Errorf("chaindata path is not a directory: %s", chaindataPath)
	}
	entries, err := os.ReadDir(chaindataPath)
	if err != nil {
		return false, fmt.Errorf("read chaindata directory: %w", err)
	}
	return len(entries) == 0, nil
}

func ensureArchiveAvailable(archivePath, url string) (bool, error) {
	if info, err := os.Stat(archivePath); err == nil {
		if info.IsDir() {
			return false, fmt.Errorf("bootstrap archive path points to a directory: %s", archivePath)
		}
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("stat bootstrap archive: %w", err)
	}
	if url == "" {
		return false, fmt.Errorf("bootstrap archive not found at %s and --%s is not set", archivePath, utils.StateBootstrapURLFlag.Name)
	}

	if err := os.MkdirAll(filepath.Dir(archivePath), 0o755); err != nil {
		return false, fmt.Errorf("create bootstrap archive directory: %w", err)
	}

	log.Info("Downloading state bootstrap archive", "url", url, "path", archivePath)
	if err := downloadBootstrapArchiveWithRetry(archivePath, url); err != nil {
		return false, err
	}
	return true, nil
}

func downloadBootstrapArchiveWithRetry(archivePath, url string) error {
	var lastErr error
	for attempt := 1; attempt <= stateBootstrapDownloadMaxRetries; attempt++ {
		if err := downloadBootstrapArchiveOnce(archivePath, url); err != nil {
			lastErr = err
			log.Warn("State bootstrap archive download attempt failed", "attempt", attempt, "maxAttempts", stateBootstrapDownloadMaxRetries, "err", err)
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("state bootstrap archive download failed")
	}
	return lastErr
}

func downloadBootstrapArchiveOnce(archivePath, url string) (err error) {
	tmpPath := archivePath + ".part"
	_ = os.Remove(tmpPath)

	ctx, cancel := context.WithTimeout(context.Background(), stateBootstrapDownloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create bootstrap download request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req) // #nosec G107 -- URL is operator-provided CLI input.
	if err != nil {
		return fmt.Errorf("download state bootstrap archive: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download state bootstrap archive: unexpected HTTP status %s", resp.Status)
	}

	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("create bootstrap temp file: %w", err)
	}
	defer func() {
		file.Close()
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err = io.Copy(file, resp.Body); err != nil {
		return fmt.Errorf("write bootstrap archive: %w", err)
	}
	if err = file.Sync(); err != nil {
		return fmt.Errorf("sync bootstrap archive: %w", err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("close bootstrap archive: %w", err)
	}
	if err = os.Rename(tmpPath, archivePath); err != nil {
		return fmt.Errorf("install bootstrap archive: %w", err)
	}
	return nil
}

func cleanupDownloadedBootstrapArchive(archivePath string, downloaded bool) {
	if !downloaded {
		return
	}
	if err := os.Remove(archivePath); err != nil {
		if !os.IsNotExist(err) {
			log.Warn("Failed to remove downloaded state bootstrap archive", "archive", archivePath, "err", err)
		}
		return
	}
	log.Info("Removed downloaded state bootstrap archive after install", "archive", archivePath)
}

func verifyArchiveSHA256(archivePath, expected string) error {
	want := strings.TrimSpace(strings.ToLower(expected))
	want = strings.TrimPrefix(want, "0x")
	if len(want) != 64 {
		return fmt.Errorf("invalid bootstrap SHA-256 length %d", len(want))
	}
	if _, err := hex.DecodeString(want); err != nil {
		return fmt.Errorf("invalid bootstrap SHA-256: %w", err)
	}

	got, err := hashFileSHA256(archivePath)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("bootstrap SHA-256 mismatch: got %s want %s", got, want)
	}
	log.Info("Verified state bootstrap archive hash", "sha256", got)
	return nil
}

func hashFileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file for hashing: %w", err)
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", fmt.Errorf("hash file: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func installBootstrapArchive(instanceDir, chaindataPath, archivePath string) error {
	stageDir, err := os.MkdirTemp(instanceDir, "state-bootstrap-stage-*")
	if err != nil {
		return fmt.Errorf("create bootstrap staging directory: %w", err)
	}
	defer os.RemoveAll(stageDir)

	log.Info("Extracting state bootstrap archive", "archive", archivePath, "staging", stageDir)
	if err := build.ExtractArchive(archivePath, stageDir); err != nil {
		return fmt.Errorf("extract state bootstrap archive: %w", err)
	}
	srcChaindata, err := findChaindataRoot(stageDir)
	if err != nil {
		return err
	}
	parentDir := filepath.Dir(chaindataPath)
	if err := os.MkdirAll(parentDir, 0o755); err != nil {
		return fmt.Errorf("create chaindata parent directory: %w", err)
	}

	installRoot, err := os.MkdirTemp(parentDir, "state-bootstrap-install-*")
	if err != nil {
		return fmt.Errorf("create bootstrap install directory: %w", err)
	}
	defer os.RemoveAll(installRoot)

	stagedChaindata := filepath.Join(installRoot, "chaindata")
	if err := moveOrCopyDirFn(srcChaindata, stagedChaindata); err != nil {
		return fmt.Errorf("install chaindata: %w", err)
	}
	if err := replaceChaindataWithBackup(stagedChaindata, chaindataPath); err != nil {
		return fmt.Errorf("activate chaindata: %w", err)
	}
	return nil
}

func replaceChaindataWithBackup(stagedChaindata, chaindataPath string) error {
	parentDir := filepath.Dir(chaindataPath)
	backupPath := ""

	if _, err := os.Stat(chaindataPath); err == nil {
		backupPath, err = reserveTempPath(parentDir, "chaindata-backup-*")
		if err != nil {
			return err
		}
		if err := os.Rename(chaindataPath, backupPath); err != nil {
			return fmt.Errorf("backup existing chaindata: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat existing chaindata: %w", err)
	}

	if err := os.Rename(stagedChaindata, chaindataPath); err != nil {
		if backupPath != "" {
			if restoreErr := os.Rename(backupPath, chaindataPath); restoreErr != nil {
				return fmt.Errorf("activate staged chaindata: %w (restore backup failed: %v)", err, restoreErr)
			}
		}
		return fmt.Errorf("activate staged chaindata: %w", err)
	}
	if backupPath != "" {
		if err := os.RemoveAll(backupPath); err != nil {
			return fmt.Errorf("remove backup chaindata: %w", err)
		}
	}
	return nil
}

func reserveTempPath(parentDir, pattern string) (string, error) {
	path, err := os.MkdirTemp(parentDir, pattern)
	if err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil {
		return "", err
	}
	return path, nil
}

func findChaindataRoot(stageDir string) (string, error) {
	direct := filepath.Join(stageDir, "chaindata")
	if isDirectory(direct) {
		return direct, nil
	}
	entries, err := os.ReadDir(stageDir)
	if err != nil {
		return "", fmt.Errorf("read bootstrap staging directory: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidate := filepath.Join(stageDir, entry.Name(), "chaindata")
		if isDirectory(candidate) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("state bootstrap archive does not contain a chaindata directory")
}

func isDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func moveOrCopyDir(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	return copyDirectory(src, dst)
}

var moveOrCopyDirFn = moveOrCopyDir

func copyDirectory(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink entry is not supported in bootstrap archive: %s", path)
		}
		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			return os.MkdirAll(target, info.Mode().Perm())
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}

type archiveEntry struct {
	path string
	rel  string
	info fs.FileInfo
}

func createBootstrapArchive(chaindataPath, archivePath string) (stateBootstrapManifest, error) {
	chaindataPath = strings.TrimSpace(chaindataPath)
	archivePath = strings.TrimSpace(archivePath)
	if chaindataPath == "" {
		return stateBootstrapManifest{}, errors.New("source chaindata path is empty")
	}
	if archivePath == "" {
		return stateBootstrapManifest{}, errors.New("archive path is empty")
	}

	absChaindata, err := filepath.Abs(chaindataPath)
	if err != nil {
		return stateBootstrapManifest{}, fmt.Errorf("resolve source chaindata path: %w", err)
	}
	info, err := os.Stat(absChaindata)
	if err != nil {
		return stateBootstrapManifest{}, fmt.Errorf("stat source chaindata: %w", err)
	}
	if !info.IsDir() {
		return stateBootstrapManifest{}, fmt.Errorf("source chaindata is not a directory: %s", absChaindata)
	}

	absArchive, err := filepath.Abs(archivePath)
	if err != nil {
		return stateBootstrapManifest{}, fmt.Errorf("resolve archive path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absArchive), 0o755); err != nil {
		return stateBootstrapManifest{}, fmt.Errorf("create archive directory: %w", err)
	}
	tmpArchive, err := tempArchivePath(absArchive)
	if err != nil {
		return stateBootstrapManifest{}, err
	}
	_ = os.Remove(tmpArchive)

	fileCount, totalBytes, err := archiveChaindata(absChaindata, tmpArchive)
	if err != nil {
		_ = os.Remove(tmpArchive)
		return stateBootstrapManifest{}, err
	}
	if err := os.Rename(tmpArchive, absArchive); err != nil {
		_ = os.Remove(tmpArchive)
		return stateBootstrapManifest{}, fmt.Errorf("install bootstrap archive: %w", err)
	}
	sha, err := hashFileSHA256(absArchive)
	if err != nil {
		return stateBootstrapManifest{}, err
	}
	return stateBootstrapManifest{
		FormatVersion:   1,
		CreatedAt:       time.Now().UTC().Format(time.RFC3339),
		ArchiveFile:     absArchive,
		ArchiveSHA256:   sha,
		SourceChaindata: absChaindata,
		FileCount:       fileCount,
		TotalBytes:      totalBytes,
	}, nil
}

func tempArchivePath(archivePath string) (string, error) {
	switch {
	case strings.HasSuffix(archivePath, ".tar.gz"):
		return strings.TrimSuffix(archivePath, ".tar.gz") + ".part.tar.gz", nil
	case strings.HasSuffix(archivePath, ".zip"):
		return strings.TrimSuffix(archivePath, ".zip") + ".part.zip", nil
	default:
		return "", fmt.Errorf("unsupported bootstrap archive extension for %s (use .tar.gz or .zip)", archivePath)
	}
}

func writeBootstrapManifest(path string, manifest stateBootstrapManifest) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("manifest path is empty")
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve manifest path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return fmt.Errorf("create manifest directory: %w", err)
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal bootstrap manifest: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(absPath, data, 0o644); err != nil {
		return fmt.Errorf("write bootstrap manifest: %w", err)
	}
	return nil
}

func archiveChaindata(chaindataPath, archivePath string) (int, int64, error) {
	entries, totalBytes, err := collectArchiveEntries(chaindataPath)
	if err != nil {
		return 0, 0, err
	}
	if len(entries) == 0 {
		return 0, 0, errors.New("source chaindata directory is empty")
	}
	switch {
	case strings.HasSuffix(archivePath, ".tar.gz"):
		if err := writeTarGzArchive(archivePath, entries); err != nil {
			return 0, 0, err
		}
	case strings.HasSuffix(archivePath, ".zip"):
		if err := writeZipArchive(archivePath, entries); err != nil {
			return 0, 0, err
		}
	default:
		return 0, 0, fmt.Errorf("unsupported bootstrap archive extension for %s (use .tar.gz or .zip)", archivePath)
	}
	return len(entries), totalBytes, nil
}

func collectArchiveEntries(chaindataPath string) ([]archiveEntry, int64, error) {
	var (
		entries    []archiveEntry
		totalBytes int64
	)
	err := filepath.WalkDir(chaindataPath, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink entry is not supported in chaindata snapshot: %s", path)
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(chaindataPath, path)
		if err != nil {
			return err
		}
		entries = append(entries, archiveEntry{
			path: path,
			rel:  filepath.ToSlash(rel),
			info: info,
		})
		totalBytes += info.Size()
		return nil
	})
	if err != nil {
		return nil, 0, fmt.Errorf("walk source chaindata: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].rel < entries[j].rel
	})
	return entries, totalBytes, nil
}

func recordCloseError(errp *error, action string, closeFn func() error) {
	if *errp != nil {
		_ = closeFn()
		return
	}
	if err := closeFn(); err != nil {
		*errp = fmt.Errorf("%s: %w", action, err)
	}
}

func writeTarGzArchive(archivePath string, entries []archiveEntry) (err error) {
	file, err := os.OpenFile(archivePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("create tar.gz archive: %w", err)
	}
	defer recordCloseError(&err, "close tar.gz archive file", file.Close)

	gz := gzip.NewWriter(file)
	defer recordCloseError(&err, "finalize gzip stream", gz.Close)

	tw := tar.NewWriter(gz)
	defer recordCloseError(&err, "finalize tar archive", tw.Close)

	if err := tw.WriteHeader(&tar.Header{
		Name:     stateBootstrapArchiveRoot + "/",
		Mode:     0o755,
		Typeflag: tar.TypeDir,
		ModTime:  time.Unix(0, 0),
	}); err != nil {
		return fmt.Errorf("write tar root directory: %w", err)
	}
	if err := tw.WriteHeader(&tar.Header{
		Name:     stateBootstrapArchiveRoot + "/chaindata/",
		Mode:     0o755,
		Typeflag: tar.TypeDir,
		ModTime:  time.Unix(0, 0),
	}); err != nil {
		return fmt.Errorf("write tar chaindata directory: %w", err)
	}

	for _, entry := range entries {
		header, err := tar.FileInfoHeader(entry.info, "")
		if err != nil {
			return fmt.Errorf("create tar header for %s: %w", entry.rel, err)
		}
		header.Name = filepath.ToSlash(filepath.Join(stateBootstrapArchiveRoot, "chaindata", entry.rel))
		header.ModTime = time.Unix(0, 0)
		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("write tar header for %s: %w", entry.rel, err)
		}
		in, err := os.Open(entry.path)
		if err != nil {
			return fmt.Errorf("open source file for %s: %w", entry.rel, err)
		}
		if _, err := io.Copy(tw, in); err != nil {
			in.Close()
			return fmt.Errorf("copy source file %s: %w", entry.rel, err)
		}
		in.Close()
	}
	return nil
}

func writeZipArchive(archivePath string, entries []archiveEntry) (err error) {
	file, err := os.OpenFile(archivePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("create zip archive: %w", err)
	}
	defer recordCloseError(&err, "close zip archive file", file.Close)

	zw := zip.NewWriter(file)
	defer recordCloseError(&err, "finalize zip archive", zw.Close)

	for _, entry := range entries {
		header, err := zip.FileInfoHeader(entry.info)
		if err != nil {
			return fmt.Errorf("create zip header for %s: %w", entry.rel, err)
		}
		header.Name = filepath.ToSlash(filepath.Join(stateBootstrapArchiveRoot, "chaindata", entry.rel))
		header.Method = zip.Deflate
		header.Modified = time.Unix(0, 0)
		w, err := zw.CreateHeader(header)
		if err != nil {
			return fmt.Errorf("write zip header for %s: %w", entry.rel, err)
		}
		in, err := os.Open(entry.path)
		if err != nil {
			return fmt.Errorf("open source file for %s: %w", entry.rel, err)
		}
		if _, err := io.Copy(w, in); err != nil {
			in.Close()
			return fmt.Errorf("copy source file %s: %w", entry.rel, err)
		}
		in.Close()
	}
	return nil
}
