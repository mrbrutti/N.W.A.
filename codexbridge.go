package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const defaultDesktopCodexPath = "/Applications/Codex.app/Contents/Resources/codex"

type llmPlanner struct {
	command  string
	authPath string
	workDir  string
}

type llmPlanSuggestion struct {
	Title            string   `json:"title"`
	Detail           string   `json:"detail"`
	Rationale        string   `json:"rationale"`
	Confidence       float64  `json:"confidence"`
	ExpectedValue    string   `json:"expected_value"`
	RequiredApproval string   `json:"required_approval"`
	ToolIDs          []string `json:"tool_ids"`
}

type llmPlanResponse struct {
	Suggestions []llmPlanSuggestion `json:"suggestions"`
}

type execEvent struct {
	Type string    `json:"type"`
	Item *execItem `json:"item"`
}

type execItem struct {
	Type    string        `json:"type"`
	Text    string        `json:"text"`
	Content []execContent `json:"content"`
}

type execContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func newLLMPlanner(workDir string) (*llmPlanner, error) {
	command, err := resolveDesktopCodexCommand()
	if err != nil {
		return nil, err
	}
	authPath, err := resolveCodexAuthPath()
	if err != nil {
		return nil, err
	}
	if err := validateCodexAuth(authPath); err != nil {
		return nil, err
	}
	return &llmPlanner{
		command:  command,
		authPath: authPath,
		workDir:  workDir,
	}, nil
}

func resolveDesktopCodexCommand() (string, error) {
	candidates := []string{
		strings.TrimSpace(os.Getenv("NWA_CODEX_CMD")),
		defaultDesktopCodexPath,
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", errors.New("desktop Codex binary is unavailable")
}

func resolveCodexAuthPath() (string, error) {
	codexHome := strings.TrimSpace(os.Getenv("CODEX_HOME"))
	if codexHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		codexHome = filepath.Join(home, ".codex")
	}
	return filepath.Join(codexHome, "auth.json"), nil
}

func validateCodexAuth(authPath string) error {
	data, err := os.ReadFile(authPath)
	if err != nil {
		return fmt.Errorf("read Codex auth: %w", err)
	}
	var auth struct {
		AuthMode string `json:"auth_mode"`
		Tokens   struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			AccountID    string `json:"account_id"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(data, &auth); err != nil {
		return fmt.Errorf("parse Codex auth: %w", err)
	}
	if strings.TrimSpace(auth.AuthMode) == "" || strings.TrimSpace(auth.Tokens.AccountID) == "" {
		return errors.New("Codex auth is incomplete")
	}
	if strings.TrimSpace(auth.Tokens.AccessToken) == "" && strings.TrimSpace(auth.Tokens.RefreshToken) == "" {
		return errors.New("Codex auth has no usable OAuth tokens")
	}
	return nil
}

func (p *llmPlanner) Available() bool {
	return p != nil && p.command != "" && p.authPath != ""
}

func (p *llmPlanner) RecommendNextSteps(ctx context.Context, workspace *workspace, campaign *campaignRecord) ([]recommendationRecord, error) {
	if p == nil || !p.Available() {
		return nil, errors.New("llm planner is unavailable")
	}
	prompt := buildLLMPlannerPrompt(workspace, campaign)
	message, err := p.runPrompt(ctx, prompt)
	if err != nil {
		return nil, err
	}
	var response llmPlanResponse
	if err := json.Unmarshal([]byte(message), &response); err != nil {
		return nil, fmt.Errorf("parse planner output: %w", err)
	}
	items := make([]recommendationRecord, 0, len(response.Suggestions))
	for _, suggestion := range response.Suggestions {
		if strings.TrimSpace(suggestion.Title) == "" {
			continue
		}
		items = append(items, recommendationRecord{
			ID:               newWorkspaceID("rec"),
			CampaignID:       chooseString(campaign.ID),
			Type:             "llm-plan",
			Status:           recommendationOpen,
			Title:            suggestion.Title,
			Detail:           suggestion.Detail,
			Rationale:        suggestion.Rationale,
			ExpectedValue:    chooseString(suggestion.ExpectedValue, "medium"),
			RequiredApproval: chooseString(suggestion.RequiredApproval, "operator"),
			CreatedAt:        newEventTimestamp(),
			Confidence:       suggestion.Confidence,
			ToolIDs:          uniqueStrings(suggestion.ToolIDs),
		})
	}
	return items, nil
}

func (p *llmPlanner) runPrompt(ctx context.Context, prompt string) (string, error) {
	args := []string{
		"exec",
		"--json",
		"--ephemeral",
		"--skip-git-repo-check",
		"--sandbox", "read-only",
		prompt,
	}
	cmd := exec.CommandContext(ctx, p.command, args...)
	if strings.TrimSpace(p.workDir) != "" {
		cmd.Dir = p.workDir
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	message, scanErr := extractLastAgentMessage(stdout)
	waitErr := cmd.Wait()
	if scanErr != nil {
		return "", scanErr
	}
	if waitErr != nil {
		return "", fmt.Errorf("run codex planner: %w: %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(message), nil
}

func buildLLMPlannerPrompt(workspace *workspace, campaign *campaignRecord) string {
	snapshot := workspace.currentSnapshot()
	targetSummary := "No active campaign selected."
	if campaign != nil {
		targetSummary = fmt.Sprintf("Campaign: %s\nStage: %s\nSummary: %s", campaign.Name, campaign.StageLabel, campaign.Summary)
	}
	return strings.TrimSpace(fmt.Sprintf(`
You are the planning subsystem for NWA, a security command center. Produce strict JSON with this shape:
{"suggestions":[{"title":"","detail":"","rationale":"","confidence":0.0,"expected_value":"low|medium|high","required_approval":"operator|admin","tool_ids":["tool-id"]}]}

Only recommend actions that fit the currently registered tools in NWA:
- naabu
- nmap-enrich
- dnsx
- httpx
- katana
- nuclei
- sqlmap
- zap-connector
- burp-connector
- tenable-connector
- nessus-connector

Constraints:
- No free-form shell commands.
- Prefer 2 to 4 high-value next steps.
- Focus on sequence and expected operator value.
- Recommendations must stay inside the current workspace scope.

Workspace summary:
- %s
- Live hosts: %d
- Findings: %d
- Top ports: %s
- Top services: %s
- High exposure hosts: %d

%s
`, snapshot.summaryLine, snapshot.meta.LiveHosts, snapshot.findingTotals.Total, bucketLabels(snapshot.portBuckets, 5), bucketLabels(snapshot.serviceBuckets, 5), len(snapshot.highExposure), targetSummary))
}

func bucketLabels(items []Bucket, limit int) string {
	if len(items) == 0 {
		return "none"
	}
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	labels := make([]string, 0, len(items))
	for _, item := range items {
		labels = append(labels, fmt.Sprintf("%s (%d)", item.Label, item.Count))
	}
	return strings.Join(labels, ", ")
}

func extractLastAgentMessage(reader io.Reader) (string, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 1024), 1024*1024)

	var lastMessage string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event execEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return "", err
		}
		if event.Type != "item.completed" || event.Item == nil {
			continue
		}
		if event.Item.Type != "agent_message" && event.Item.Type != "agentMessage" {
			continue
		}
		if text := strings.TrimSpace(event.Item.Text); text != "" {
			lastMessage = text
			continue
		}
		parts := make([]string, 0, len(event.Item.Content))
		for _, content := range event.Item.Content {
			if content.Type == "text" && strings.TrimSpace(content.Text) != "" {
				parts = append(parts, strings.TrimSpace(content.Text))
			}
		}
		if len(parts) > 0 {
			lastMessage = strings.Join(parts, "\n")
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if strings.TrimSpace(lastMessage) == "" {
		return "", errors.New("Codex returned no planner output")
	}
	return lastMessage, nil
}
