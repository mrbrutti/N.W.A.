package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type genericCommandPlugin struct {
	definition PluginDefinitionView
}

func (p *genericCommandPlugin) Definition() PluginDefinitionView {
	return normalizedPluginDefinition(p.definition)
}

func (p *genericCommandPlugin) Run(ctx context.Context, request pluginRunRequest) (PluginRunResult, error) {
	definition := normalizedPluginDefinition(p.definition)
	profile, ok := toolProfileByID(definition.Profiles, request.Options["profile"])
	if !ok {
		return PluginRunResult{}, fmt.Errorf("%s requires a valid command profile", definition.Label)
	}

	targets := genericTargetsForRequest(definition, request)
	if len(targets) == 0 {
		return PluginRunResult{}, fmt.Errorf("%s requires at least one matching target", definition.Label)
	}

	targetsPath := filepath.Join(request.WorkDir, "targets.txt")
	resultsPath := filepath.Join(request.WorkDir, "results.txt")
	logPath := filepath.Join(request.WorkDir, "command.log")
	if err := writeTargetsFile(targetsPath, targets); err != nil {
		return PluginRunResult{}, err
	}

	args, err := genericProfileArgs(profile.Command, targetsPath, resultsPath)
	if err != nil {
		return PluginRunResult{}, err
	}
	args = append(args, strings.Fields(strings.TrimSpace(request.Options["extra_args"]))...)

	emitProgress(request, fmt.Sprintf("%s running %s across %d targets", definition.Label, profile.Label, len(targets)))
	output, commandLine, err := runCLICommand(ctx, request, definition.BinaryName, args)
	writeCommandLog(logPath, commandLine, output)
	artifacts := []jobArtifact{
		{Label: "Targets", RelPath: filepath.Join(request.Job.ID, "targets.txt")},
		{Label: "Command log", RelPath: filepath.Join(request.Job.ID, "command.log")},
	}
	if fileExists(resultsPath) {
		artifacts = append(artifacts, jobArtifact{Label: "Results", RelPath: filepath.Join(request.Job.ID, "results.txt")})
	}
	if err != nil {
		return PluginRunResult{Artifacts: artifacts}, err
	}
	if !fileExists(resultsPath) {
		_ = os.WriteFile(resultsPath, output, 0o600)
		artifacts = append(artifacts, jobArtifact{Label: "Results", RelPath: filepath.Join(request.Job.ID, "results.txt")})
	}

	return PluginRunResult{
		Summary:   fmt.Sprintf("%s completed with profile %s across %d targets.", definition.Label, profile.Label, len(targets)),
		Artifacts: uniqueJobArtifacts(artifacts),
	}, nil
}

func genericTargetsForRequest(definition PluginDefinitionView, request pluginRunRequest) []string {
	switch normalizeTargetStrategy(definition.TargetStrategy) {
	case "web":
		return explicitWebTargetsForRequest(request)
	case "domain":
		return subfinderTargetsForRequest(request)
	case "manual":
		return uniqueStrings(request.RawTargets)
	default:
		return uniqueStrings(append(hostIPsFromDetails(request.Hosts), request.RawTargets...))
	}
}

func genericProfileArgs(command string, targetsPath string, resultsPath string) ([]string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil, errors.New("profile command is required")
	}
	fields := strings.Fields(command)
	args := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.ReplaceAll(field, "{{targets_file}}", targetsPath)
		field = strings.ReplaceAll(field, "{{output_file}}", resultsPath)
		args = append(args, field)
	}
	return args, nil
}

func uniqueJobArtifacts(values []jobArtifact) []jobArtifact {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	items := make([]jobArtifact, 0, len(values))
	for _, value := range values {
		key := strings.TrimSpace(value.Label) + "::" + strings.TrimSpace(value.RelPath)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		items = append(items, value)
	}
	return items
}
