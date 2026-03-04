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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/log"
	"github.com/urfave/cli/v2"
)

var (
	stateBootstrapExportChaindataFlag = &cli.StringFlag{
		Name:     "chaindata",
		Usage:    "Path to source chaindata directory",
		Required: true,
	}
	stateBootstrapExportOutputFlag = &cli.StringFlag{
		Name:     "output",
		Usage:    "Path to destination bootstrap archive (.tar.gz or .zip)",
		Required: true,
	}
	stateBootstrapExportManifestFlag = &cli.StringFlag{
		Name:  "manifest",
		Usage: "Path to destination manifest JSON file (default: <output>.manifest.json)",
	}
	stateBootstrapExportAllowLiveFlag = &cli.BoolFlag{
		Name:  "allow-live",
		Usage: "Allow export when chaindata LOCK file exists (unsafe unless the writer is stopped)",
	}
	stateBootstrapCommand = &cli.Command{
		Action:    exportStateBootstrap,
		Name:      "statebootstrap",
		Usage:     "Create a Syscoin state bootstrap archive",
		ArgsUsage: "",
		Flags: []cli.Flag{
			stateBootstrapExportChaindataFlag,
			stateBootstrapExportOutputFlag,
			stateBootstrapExportManifestFlag,
			stateBootstrapExportAllowLiveFlag,
		},
		Description: `Create a bootstrap archive from chaindata only, then write a JSON manifest with SHA-256.
This command is intended for release automation and recurring snapshot creation.`,
	}
)

func exportStateBootstrap(ctx *cli.Context) error {
	chaindataPath := strings.TrimSpace(ctx.String(stateBootstrapExportChaindataFlag.Name))
	outputPath := strings.TrimSpace(ctx.String(stateBootstrapExportOutputFlag.Name))
	if chaindataPath == "" {
		return fmt.Errorf("--%s is required", stateBootstrapExportChaindataFlag.Name)
	}
	if outputPath == "" {
		return fmt.Errorf("--%s is required", stateBootstrapExportOutputFlag.Name)
	}
	if !ctx.Bool(stateBootstrapExportAllowLiveFlag.Name) {
		lockPath := filepath.Join(chaindataPath, "LOCK")
		if _, err := os.Stat(lockPath); err == nil {
			return fmt.Errorf("chaindata lock file exists at %s; stop the writer process or pass --%s", lockPath, stateBootstrapExportAllowLiveFlag.Name)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat chaindata lock file: %w", err)
		}
	}

	manifest, err := createBootstrapArchive(chaindataPath, outputPath)
	if err != nil {
		return err
	}
	manifestPath := strings.TrimSpace(ctx.String(stateBootstrapExportManifestFlag.Name))
	if manifestPath == "" {
		manifestPath = outputPath + ".manifest.json"
	}
	if err := writeBootstrapManifest(manifestPath, manifest); err != nil {
		return err
	}
	log.Info("State bootstrap export completed",
		"archive", manifest.ArchiveFile,
		"manifest", manifestPath,
		"sha256", manifest.ArchiveSHA256,
		"files", manifest.FileCount,
		"bytes", manifest.TotalBytes,
	)
	return nil
}
