package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type niktoPlugin struct{}

func (p *niktoPlugin) Definition() PluginDefinitionView {
	return PluginDefinitionView{
		ID:             "nikto",
		Label:          "Nikto Web Sweep",
		Description:    "Run Nikto against mapped web targets, retain the output as artifacts, and keep the command in the same managed queue as the rest of the workspace tooling.",
		Mode:           "Managed command",
		Family:         "Web validation",
		BinaryName:     "nikto",
		TargetStrategy: "web",
		Profiles: []ToolCommandProfileView{
			{ID: "basic", Label: "Baseline", Description: "Default Nikto checks across selected targets.", Default: true},
			{ID: "comprehensive", Label: "Comprehensive", Description: "Run the broader Nikto checks with `-C all`."},
			{ID: "robots", Label: "Robots", Description: "Focus on robots.txt and related content."},
			{ID: "shellshock", Label: "Shellshock", Description: "Shellshock-focused checks only."},
			{ID: "ssl", Label: "SSL", Description: "SSL and TLS-focused checks only."},
			{ID: "interesting-files", Label: "Interesting files", Description: "Interesting file checks with tuning set 1."},
		},
		Availability:     "available",
		AvailabilityTone: "accent",
	}
}

func (p *niktoPlugin) Run(ctx context.Context, request pluginRunRequest) (PluginRunResult, error) {
	targets := httpxTargetsForRequest(request)
	if len(targets) == 0 {
		return PluginRunResult{}, errors.New("nikto requires HTTP/HTTPS targets or hosts with mapped HTTP services")
	}

	targetsPath := filepath.Join(request.WorkDir, "targets.txt")
	resultsPath := filepath.Join(request.WorkDir, "results.txt")
	logPath := filepath.Join(request.WorkDir, "command.log")
	if err := writeTargetsFile(targetsPath, targets); err != nil {
		return PluginRunResult{}, err
	}

	var commandLog strings.Builder
	var results strings.Builder
	profile := strings.TrimSpace(request.Options["profile"])
	if profile == "" {
		profile = "basic"
	}

	for index, target := range targets {
		args := []string{"-h", target}
		switch profile {
		case "comprehensive":
			args = append(args, "-C", "all")
		case "robots":
			args = append(args, "-Plugins", "robots")
		case "shellshock":
			args = append(args, "-Plugins", "shellshock")
		case "ssl":
			args = append(args, "-Plugins", "ssl")
		case "interesting-files":
			args = append(args, "-Tuning", "1")
		}
		args = append(args, strings.Fields(strings.TrimSpace(request.Options["extra_args"]))...)

		emitProgress(request, fmt.Sprintf("Nikto scanning %s (%d/%d)", target, index+1, len(targets)))
		output, commandLine, err := runCLICommand(ctx, request, "nikto", args)
		commandLog.WriteString("$ " + commandLine + "\n\n" + string(output) + "\n")
		results.WriteString("## " + target + "\n\n" + string(output) + "\n")
		if err != nil {
			writeCommandLog(logPath, "", []byte(commandLog.String()))
			_ = os.WriteFile(resultsPath, []byte(results.String()), 0o600)
			return PluginRunResult{
				Artifacts: []jobArtifact{
					{Label: "Targets", RelPath: filepath.Join(request.Job.ID, "targets.txt")},
					{Label: "Results", RelPath: filepath.Join(request.Job.ID, "results.txt")},
					{Label: "Command log", RelPath: filepath.Join(request.Job.ID, "command.log")},
				},
			}, err
		}
		if !strings.HasSuffix(commandLog.String(), "\n\n") {
			commandLog.WriteString("\n")
		}
		results.WriteString("\n")
	}

	writeCommandLog(logPath, "", []byte(commandLog.String()))
	if err := os.WriteFile(resultsPath, []byte(results.String()), 0o600); err != nil {
		return PluginRunResult{}, err
	}

	summary := fmt.Sprintf("nikto completed across %d web targets.", len(targets))
	return PluginRunResult{
		Summary: summary,
		Artifacts: []jobArtifact{
			{Label: "Targets", RelPath: filepath.Join(request.Job.ID, "targets.txt")},
			{Label: "Results", RelPath: filepath.Join(request.Job.ID, "results.txt")},
			{Label: "Command log", RelPath: filepath.Join(request.Job.ID, "command.log")},
		},
	}, nil
}
