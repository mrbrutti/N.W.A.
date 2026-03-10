package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
)

type stringListFlag []string

func (f *stringListFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *stringListFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	*f = append(*f, value)
	return nil
}

type installPayload struct {
	ID             string           `json:"id,omitempty"`
	Label          string           `json:"label"`
	Description    string           `json:"description,omitempty"`
	Family         string           `json:"family,omitempty"`
	BinaryName     string           `json:"binary_name"`
	TargetStrategy string           `json:"target_strategy,omitempty"`
	Capabilities   []string         `json:"capabilities,omitempty"`
	SafetyClass    string           `json:"safety_class,omitempty"`
	CostProfile    string           `json:"cost_profile,omitempty"`
	Profiles       []installProfile `json:"profiles"`
}

type installProfile struct {
	ID          string `json:"id,omitempty"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Command     string `json:"command"`
	Default     bool   `json:"default,omitempty"`
}

func main() {
	var (
		baseURL        = flag.String("base-url", "http://127.0.0.1:8080", "Base URL for the N.W.A. server")
		username       = flag.String("username", "admin", "Admin username")
		password       = flag.String("password", "", "Admin password")
		toolID         = flag.String("id", "", "Tool ID override (defaults to a slugified label)")
		label          = flag.String("label", "", "Tool label")
		description    = flag.String("description", "", "Tool description")
		family         = flag.String("family", "Custom managed commands", "Tool family shown in the UI")
		binaryName     = flag.String("binary", "", "Binary name or absolute path")
		targetStrategy = flag.String("target-strategy", "host", "Target strategy: host, web, domain, or manual")
		safetyClass    = flag.String("safety-class", "active", "Safety class: active, passive, or controlled")
		costProfile    = flag.String("cost-profile", "medium", "Cost profile: low, medium, or high")
	)
	var capabilities stringListFlag
	var profileSpecs stringListFlag
	flag.Var(&capabilities, "capability", "Capability tag to attach to the tool (repeatable)")
	flag.Var(&profileSpecs, "profile", "Profile spec in the form id|label|command|description. Command must include {{targets_file}}. Repeatable.")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: go run ./scripts/install_tool.go [flags]\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Example:\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  go run ./scripts/install_tool.go \\\n")
		fmt.Fprintf(flag.CommandLine.Output(), "    -base-url http://127.0.0.1:8080 \\\n")
		fmt.Fprintf(flag.CommandLine.Output(), "    -username admin -password secret \\\n")
		fmt.Fprintf(flag.CommandLine.Output(), "    -label \"DNSX Custom\" -binary dnsx -target-strategy domain \\\n")
		fmt.Fprintf(flag.CommandLine.Output(), "    -capability dns -capability validation \\\n")
		fmt.Fprintf(flag.CommandLine.Output(), "    -profile 'baseline|Baseline|-l {{targets_file}} -json -o {{output_file}}|JSON output'\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if strings.TrimSpace(*label) == "" || strings.TrimSpace(*binaryName) == "" || strings.TrimSpace(*password) == "" {
		flag.Usage()
		os.Exit(2)
	}

	profiles, err := parseProfiles(profileSpecs)
	if err != nil {
		exitErr(err)
	}
	payload := installPayload{
		ID:             strings.TrimSpace(*toolID),
		Label:          strings.TrimSpace(*label),
		Description:    strings.TrimSpace(*description),
		Family:         strings.TrimSpace(*family),
		BinaryName:     strings.TrimSpace(*binaryName),
		TargetStrategy: strings.TrimSpace(*targetStrategy),
		Capabilities:   capabilities,
		SafetyClass:    strings.TrimSpace(*safetyClass),
		CostProfile:    strings.TrimSpace(*costProfile),
		Profiles:       profiles,
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		exitErr(err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if err := login(client, *baseURL, *username, *password); err != nil {
		exitErr(err)
	}
	if err := installTool(client, *baseURL, payload); err != nil {
		exitErr(err)
	}
}

func parseProfiles(values []string) ([]installProfile, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("at least one -profile flag is required")
	}
	profiles := make([]installProfile, 0, len(values))
	for index, value := range values {
		parts := strings.SplitN(value, "|", 4)
		if len(parts) < 3 {
			return nil, fmt.Errorf("invalid profile %q: expected id|label|command|description", value)
		}
		profile := installProfile{
			ID:      strings.TrimSpace(parts[0]),
			Label:   strings.TrimSpace(parts[1]),
			Command: strings.TrimSpace(parts[2]),
			Default: index == 0,
		}
		if len(parts) == 4 {
			profile.Description = strings.TrimSpace(parts[3])
		}
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

func login(client *http.Client, baseURL string, username string, password string) error {
	response, err := client.PostForm(strings.TrimRight(baseURL, "/")+"/login", url.Values{
		"login":    {username},
		"password": {password},
	})
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusSeeOther && response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		return fmt.Errorf("login failed: %s", strings.TrimSpace(string(body)))
	}
	return nil
}

func installTool(client *http.Client, baseURL string, payload installPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, strings.TrimRight(baseURL, "/")+"/api/v1/admin/tools", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return fmt.Errorf("install failed with status %d: %s", response.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	var pretty bytes.Buffer
	if err := json.Indent(&pretty, responseBody, "", "  "); err == nil {
		fmt.Println(pretty.String())
		return nil
	}
	fmt.Println(string(responseBody))
	return nil
}

func exitErr(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
