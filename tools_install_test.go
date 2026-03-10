package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenericCommandPluginRunUsesInstalledProfile(t *testing.T) {
	binDir := t.TempDir()
	binaryPath := filepath.Join(binDir, "batchscan")
	script := "#!/bin/sh\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    -l) shift; targets=\"$1\" ;;\n    -o) shift; output=\"$1\" ;;\n  esac\n  shift\ndone\ncp \"$targets\" \"$output\"\n"
	if err := os.WriteFile(binaryPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	plugin := &genericCommandPlugin{definition: PluginDefinitionView{
		ID:             "batchscan",
		Label:          "Batch Scan",
		Description:    "test plugin",
		Mode:           "Managed command",
		Family:         "Custom managed commands",
		Kind:           "managed-command",
		InstallSource:  toolInstallSourceCustom,
		BinaryName:     binaryPath,
		TargetStrategy: "host",
		Profiles: []ToolCommandProfileView{
			{ID: "baseline", Label: "Baseline", Command: "-l {{targets_file}} -o {{output_file}}", Default: true},
		},
	}}

	workDir := t.TempDir()
	result, err := plugin.Run(context.Background(), pluginRunRequest{
		Job:        &pluginJob{ID: "job-test"},
		WorkDir:    workDir,
		RawTargets: []string{"192.0.2.10", "192.0.2.11"},
		Options:    map[string]string{"profile": "baseline"},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !strings.Contains(result.Summary, "Batch Scan completed") {
		t.Fatalf("Run() summary = %q, want tool completion summary", result.Summary)
	}
	resultsPath := filepath.Join(workDir, "results.txt")
	payload, err := os.ReadFile(resultsPath)
	if err != nil {
		t.Fatalf("read results: %v", err)
	}
	if got := strings.TrimSpace(string(payload)); got != "192.0.2.10\n192.0.2.11" {
		t.Fatalf("results.txt = %q, want targets copied", got)
	}
	if len(result.Artifacts) != 3 {
		t.Fatalf("Run() artifacts = %#v, want targets/results/log", result.Artifacts)
	}
}

func TestAdminToolInstallAPIRegistersCustomTool(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	binDir := t.TempDir()
	installFakeTool(t, binDir, "batchscan")
	t.Setenv("PATH", binDir)
	t.Setenv("NWA_ADMIN_PASSWORD", "adminpass")

	app, err := newApplicationWithConfig(applicationConfig{
		DBDSN:           filepath.Join(t.TempDir(), "service.sqlite"),
		DataDir:         filepath.Join(t.TempDir(), "data"),
		WorkspaceTarget: "engagement-alpha",
	}, logger)
	if err != nil {
		t.Fatalf("newApplicationWithConfig() error = %v", err)
	}

	handler, err := app.routes()
	if err != nil {
		t.Fatalf("routes() error = %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if _, err := client.PostForm(server.URL+"/login", url.Values{
		"login":    {"admin"},
		"password": {"adminpass"},
	}); err != nil {
		t.Fatalf("login request error = %v", err)
	}

	payload, err := json.Marshal(toolInstallRequest{
		Label:          "Batch Scan",
		Description:    "Batch scanner wired in through the install API",
		Family:         "Custom validation",
		BinaryName:     "batchscan",
		TargetStrategy: "web",
		Capabilities:   []string{"http", "validation"},
		Profiles: []ToolCommandProfileView{
			{ID: "baseline", Label: "Baseline", Command: "-l {{targets_file}} -o {{output_file}}", Default: true},
			{ID: "headers", Label: "Headers", Command: "-l {{targets_file}} -o {{output_file}} --headers"},
		},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/admin/tools", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("POST /api/v1/admin/tools error = %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("POST /api/v1/admin/tools status = %d, want %d, body=%s", response.StatusCode, http.StatusCreated, strings.TrimSpace(string(body)))
	}

	var installed PlatformToolView
	if err := json.NewDecoder(response.Body).Decode(&installed); err != nil {
		t.Fatalf("decode install response: %v", err)
	}
	if installed.ID != "batch-scan" {
		t.Fatalf("installed tool id = %q, want batch-scan", installed.ID)
	}
	if installed.InstallSource != toolInstallSourceCustom {
		t.Fatalf("install source = %q, want %q", installed.InstallSource, toolInstallSourceCustom)
	}
	if installed.TargetStrategy != "web" {
		t.Fatalf("target strategy = %q, want web", installed.TargetStrategy)
	}
	if len(installed.Profiles) != 2 {
		t.Fatalf("profiles = %#v, want two command profiles", installed.Profiles)
	}

	workspace, _, err := app.center.defaultWorkspace()
	if err != nil {
		t.Fatalf("defaultWorkspace() error = %v", err)
	}
	catalog := workspace.plugins.catalog()
	found := false
	for _, item := range catalog {
		if item.ID == "batch-scan" {
			found = true
			if len(item.Profiles) != 2 {
				t.Fatalf("catalog profiles = %#v, want two profiles", item.Profiles)
			}
			if item.TargetStrategy != "web" {
				t.Fatalf("catalog target strategy = %q, want web", item.TargetStrategy)
			}
		}
	}
	if !found {
		t.Fatal("custom tool was not loaded into the workspace plugin catalog")
	}
}
