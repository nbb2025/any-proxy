package main

import (
	"context"
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"anyproxy.dev/any-proxy/internal/api"
	"golang.org/x/mod/semver"
)

func newAgentVersionLister(logger *log.Logger, installDir string) api.AgentVersionLister {
	installDir = strings.TrimSpace(installDir)
	if installDir == "" {
		return func(context.Context) (api.AgentVersionListing, error) {
			return api.AgentVersionListing{Versions: []string{"latest"}}, nil
		}
	}
	abs := installDir
	if resolved, err := filepath.Abs(installDir); err == nil {
		abs = resolved
	}
	binariesDir := filepath.Join(abs, "binaries")
	return func(context.Context) (api.AgentVersionListing, error) {
		listing, err := readAgentVersions(binariesDir)
		if err != nil {
			logger.Printf("list agent versions failed: %v", err)
			return api.AgentVersionListing{Versions: []string{"latest"}}, nil
		}
		return listing, nil
	}
}

func readAgentVersions(binariesDir string) (api.AgentVersionListing, error) {
	listing := api.AgentVersionListing{
		Versions: []string{"latest"},
	}

	entries, err := os.ReadDir(binariesDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return listing, nil
		}
		return listing, err
	}

	var semverVersions []string
	var otherVersions []string

	for _, entry := range entries {
		name := strings.TrimSpace(entry.Name())
		if name == "" || strings.EqualFold(name, "latest") {
			continue
		}
		if !isDirLike(entry) {
			continue
		}
		if semver.IsValid(name) {
			semverVersions = append(semverVersions, name)
		} else {
			otherVersions = append(otherVersions, name)
		}
	}

	sort.Slice(semverVersions, func(i, j int) bool {
		return semver.Compare(semverVersions[i], semverVersions[j]) > 0
	})
	sort.Slice(otherVersions, func(i, j int) bool {
		return strings.ToLower(otherVersions[i]) > strings.ToLower(otherVersions[j])
	})

	result := make([]string, 0, 1+len(semverVersions)+len(otherVersions))
	seen := make(map[string]struct{})
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}

	add("latest")
	for _, v := range semverVersions {
		add(v)
	}
	for _, v := range otherVersions {
		add(v)
	}
	if len(result) == 0 {
		result = append(result, "latest")
	}

	listing.Versions = result
	listing.LatestResolved = resolveLatestTarget(binariesDir)
	if listing.LatestResolved == "" && len(semverVersions) > 0 {
		listing.LatestResolved = semverVersions[0]
	}
	return listing, nil
}

func isDirLike(entry fs.DirEntry) bool {
	if entry.IsDir() {
		return true
	}
	if entry.Type()&fs.ModeSymlink == 0 {
		return false
	}
	info, err := entry.Info()
	if err != nil {
		return false
	}
	return info.IsDir()
}

func resolveLatestTarget(binariesDir string) string {
	latestPath := filepath.Join(binariesDir, "latest")
	info, err := os.Lstat(latestPath)
	if err != nil {
		return ""
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		target, err := os.Readlink(latestPath)
		if err != nil {
			return ""
		}
		if filepath.IsAbs(target) {
			return filepath.Base(target)
		}
		joined := filepath.Clean(filepath.Join(binariesDir, target))
		return filepath.Base(joined)
	}
	if info.IsDir() {
		return info.Name()
	}
	return ""
}
