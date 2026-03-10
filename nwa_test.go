package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNormalizeCLIArgsExpandsMultiSeedFlag(t *testing.T) {
	args := []string{
		"-f",
		"/tmp/a.xml",
		"/tmp/b.xml",
		"-p",
		"809",
		"-workspace",
		"/tmp/ws",
	}

	got := normalizeCLIArgs(args)
	want := []string{
		"-f", "/tmp/a.xml",
		"-f", "/tmp/b.xml",
		"-p", "809",
		"-workspace", "/tmp/ws",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeCLIArgs() = %#v, want %#v", got, want)
	}
}

func TestResolveWorkspacePathAddsNWAExtension(t *testing.T) {
	root := t.TempDir()
	path, err := resolveWorkspacePath(filepath.Join(root, "engagement-alpha"))
	if err != nil {
		t.Fatalf("resolveWorkspacePath() error = %v", err)
	}
	if filepath.Ext(path) != ".nwa" {
		t.Fatalf("workspace path = %q, want .nwa suffix", path)
	}
}

func TestResolveWorkspacePathPlacesWorkspaceInsideDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "investigation")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	path, err := resolveWorkspacePath(root)
	if err != nil {
		t.Fatalf("resolveWorkspacePath() error = %v", err)
	}
	if filepath.Dir(path) != root {
		t.Fatalf("workspace dir = %q, want %q", filepath.Dir(path), root)
	}
	if filepath.Base(path) != "investigation.nwa" {
		t.Fatalf("workspace file = %q, want investigation.nwa", filepath.Base(path))
	}
}
