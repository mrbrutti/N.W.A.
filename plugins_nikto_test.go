package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNiktoPluginRunWritesArtifactsAndUsesProfile(t *testing.T) {
	workDir := t.TempDir()
	toolDir := t.TempDir()
	scriptPath := filepath.Join(toolDir, "nikto")
	script := "#!/bin/sh\nprintf '%s' \"$*\"\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write nikto stub error = %v", err)
	}
	t.Setenv("PATH", toolDir)

	plugin := &niktoPlugin{}
	result, err := plugin.Run(context.Background(), pluginRunRequest{
		Job:        &pluginJob{ID: "job-1"},
		WorkDir:    workDir,
		RawTargets: []string{"http://example.test"},
		Options: map[string]string{
			"profile": "comprehensive",
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !strings.Contains(result.Summary, "nikto completed across 1 web targets") {
		t.Fatalf("Summary = %q, want completion summary", result.Summary)
	}

	logPayload, err := os.ReadFile(filepath.Join(workDir, "command.log"))
	if err != nil {
		t.Fatalf("ReadFile(command.log) error = %v", err)
	}
	if !strings.Contains(string(logPayload), "-C all") {
		t.Fatalf("command.log = %q, want comprehensive profile flags", string(logPayload))
	}

	resultsPayload, err := os.ReadFile(filepath.Join(workDir, "results.txt"))
	if err != nil {
		t.Fatalf("ReadFile(results.txt) error = %v", err)
	}
	if !strings.Contains(string(resultsPayload), "http://example.test") {
		t.Fatalf("results.txt = %q, want target header", string(resultsPayload))
	}
	if len(result.Artifacts) != 3 {
		t.Fatalf("Artifacts = %#v, want targets/results/log", result.Artifacts)
	}
}
