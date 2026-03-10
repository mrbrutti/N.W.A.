package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type httpxPlugin struct{}

func (p *httpxPlugin) Definition() PluginDefinitionView {
	return PluginDefinitionView{
		ID:               "httpx",
		Label:            "HTTPX Web Census",
		Description:      "Probe mapped web targets, collect status, titles, and technologies, and add the results back to the workspace.",
		Mode:             "Managed command",
		Family:           "Web discovery",
		Availability:     "available",
		AvailabilityTone: "accent",
	}
}

func (p *httpxPlugin) Run(ctx context.Context, request pluginRunRequest) (PluginRunResult, error) {
	targets := httpxTargetsForRequest(request)
	if len(targets) == 0 {
		return PluginRunResult{}, errors.New("httpx requires hostnames, IPs, or URLs")
	}

	targetsPath := filepath.Join(request.WorkDir, "targets.txt")
	resultsPath := filepath.Join(request.WorkDir, "results.jsonl")
	logPath := filepath.Join(request.WorkDir, "command.log")
	if err := writeTargetsFile(targetsPath, targets); err != nil {
		return PluginRunResult{}, err
	}

	args := []string{"-l", targetsPath, "-json", "-silent", "-title", "-tech-detect", "-status-code", "-web-server", "-ip", "-o", resultsPath}
	if concurrency := strings.TrimSpace(request.Options["concurrency"]); concurrency != "" {
		args = append(args, "-threads", concurrency)
	}
	args = append(args, strings.Fields(strings.TrimSpace(request.Options["extra_args"]))...)

	emitProgress(request, fmt.Sprintf("HTTPX probing %d targets", len(targets)))
	output, commandLine, err := runCLICommand(ctx, request, "httpx", args)
	writeCommandLog(logPath, commandLine, output)
	if err != nil {
		return PluginRunResult{Artifacts: baseCommandArtifacts(request.Job.ID, true, fileExists(resultsPath))}, err
	}

	findings, totals, err := parseHTTPXJSONL(resultsPath, buildHostResolutionMap(request))
	if err != nil {
		return PluginRunResult{}, err
	}

	summary := fmt.Sprintf("httpx observed %d responsive web targets and attached %d census findings.", countResponsiveTargets(findings), totals.Total)
	if totals.Total == 0 {
		summary = fmt.Sprintf("httpx completed across %d targets with no responsive web census results.", len(targets))
	}

	return PluginRunResult{
		Summary:        summary,
		Artifacts:      baseCommandArtifacts(request.Job.ID, true, fileExists(resultsPath)),
		Findings:       totals,
		NucleiFindings: findings,
	}, nil
}

type naabuPlugin struct{}

func (p *naabuPlugin) Definition() PluginDefinitionView {
	return PluginDefinitionView{
		ID:               "naabu",
		Label:            "Naabu Port Discovery",
		Description:      "Run fast port discovery and import the resulting port observations back into the workspace.",
		Mode:             "Managed command",
		Family:           "Network discovery",
		Availability:     "available",
		AvailabilityTone: "accent",
	}
}

func (p *naabuPlugin) Run(ctx context.Context, request pluginRunRequest) (PluginRunResult, error) {
	targets := uniqueStrings(append(append([]string(nil), request.RawTargets...), hostIPsFromDetails(request.Hosts)...))
	if len(targets) == 0 {
		return PluginRunResult{}, errors.New("naabu requires at least one host, range, or hostname target")
	}

	targetsPath := filepath.Join(request.WorkDir, "targets.txt")
	resultsPath := filepath.Join(request.WorkDir, "results.jsonl")
	logPath := filepath.Join(request.WorkDir, "command.log")
	if err := writeTargetsFile(targetsPath, targets); err != nil {
		return PluginRunResult{}, err
	}

	args := []string{"-list", targetsPath, "-json", "-o", resultsPath}
	if ports := strings.TrimSpace(request.Options["ports"]); ports != "" {
		args = append(args, "-p", ports)
	}
	if concurrency := strings.TrimSpace(request.Options["concurrency"]); concurrency != "" {
		args = append(args, "-c", concurrency)
	}
	args = append(args, strings.Fields(strings.TrimSpace(request.Options["extra_args"]))...)

	emitProgress(request, fmt.Sprintf("Naabu sweeping %d targets", len(targets)))
	output, commandLine, err := runCLICommand(ctx, request, "naabu", args)
	writeCommandLog(logPath, commandLine, output)
	if err != nil {
		return PluginRunResult{Artifacts: baseCommandArtifacts(request.Job.ID, true, fileExists(resultsPath))}, err
	}

	summary := fmt.Sprintf("naabu completed across %d targets and imported the discovered port surface.", len(targets))
	return PluginRunResult{
		Summary:          summary,
		Artifacts:        append(baseCommandArtifacts(request.Job.ID, true, fileExists(resultsPath)), jobArtifact{Label: "Results", RelPath: filepath.Join(request.Job.ID, "results.jsonl")}),
		ImportedScanPath: resultsPath,
		ImportedScanName: "naabu-" + request.Job.ID,
	}, nil
}

type dnsxPlugin struct{}

func (p *dnsxPlugin) Definition() PluginDefinitionView {
	return PluginDefinitionView{
		ID:               "dnsx",
		Label:            "DNSX Hostname Validation",
		Description:      "Resolve hostnames tied to the current workspace and attach observed DNS records back to the matching inventory members.",
		Mode:             "Managed command",
		Family:           "DNS validation",
		Availability:     "available",
		AvailabilityTone: "accent",
	}
}

func (p *dnsxPlugin) Run(ctx context.Context, request pluginRunRequest) (PluginRunResult, error) {
	targets := dnsTargetsForRequest(request)
	if len(targets) == 0 {
		return PluginRunResult{}, errors.New("dnsx requires hostnames from the current selection or manual hostname targets")
	}

	targetsPath := filepath.Join(request.WorkDir, "targets.txt")
	resultsPath := filepath.Join(request.WorkDir, "results.jsonl")
	logPath := filepath.Join(request.WorkDir, "command.log")
	if err := writeTargetsFile(targetsPath, targets); err != nil {
		return PluginRunResult{}, err
	}

	args := []string{"-l", targetsPath, "-json", "-resp", "-a", "-aaaa", "-cname", "-o", resultsPath}
	if concurrency := strings.TrimSpace(request.Options["concurrency"]); concurrency != "" {
		args = append(args, "-threads", concurrency)
	}
	args = append(args, strings.Fields(strings.TrimSpace(request.Options["extra_args"]))...)

	emitProgress(request, fmt.Sprintf("DNSX resolving %d hostnames", len(targets)))
	output, commandLine, err := runCLICommand(ctx, request, "dnsx", args)
	writeCommandLog(logPath, commandLine, output)
	if err != nil {
		return PluginRunResult{Artifacts: baseCommandArtifacts(request.Job.ID, true, fileExists(resultsPath))}, err
	}

	findings, totals, err := parseDNSXJSONL(resultsPath, buildHostResolutionMap(request))
	if err != nil {
		return PluginRunResult{}, err
	}

	summary := fmt.Sprintf("dnsx resolved %d hostnames and attached %d DNS observations.", len(targets), totals.Total)
	if totals.Total == 0 {
		summary = fmt.Sprintf("dnsx completed across %d hostnames with no matching inventory observations.", len(targets))
	}

	return PluginRunResult{
		Summary:        summary,
		Artifacts:      baseCommandArtifacts(request.Job.ID, true, fileExists(resultsPath)),
		Findings:       totals,
		NucleiFindings: findings,
	}, nil
}

type subfinderPlugin struct{}

func (p *subfinderPlugin) Definition() PluginDefinitionView {
	return PluginDefinitionView{
		ID:               "subfinder",
		Label:            "Subfinder Enumeration",
		Description:      "Query passive sources for subdomains and hand the discovered hostnames back to the command center for follow-up scanning.",
		Mode:             "Managed command",
		Family:           "DNS reconnaissance",
		Availability:     "available",
		AvailabilityTone: "accent",
	}
}

func (p *subfinderPlugin) Run(ctx context.Context, request pluginRunRequest) (PluginRunResult, error) {
	targets := subfinderTargetsForRequest(request)
	if len(targets) == 0 {
		return PluginRunResult{}, errors.New("subfinder requires one or more domain targets")
	}

	targetsPath := filepath.Join(request.WorkDir, "targets.txt")
	resultsPath := filepath.Join(request.WorkDir, "results.txt")
	logPath := filepath.Join(request.WorkDir, "command.log")
	if err := writeTargetsFile(targetsPath, targets); err != nil {
		return PluginRunResult{}, err
	}

	args := []string{"-dL", targetsPath, "-silent", "-all", "-o", resultsPath}
	if concurrency := strings.TrimSpace(request.Options["concurrency"]); concurrency != "" {
		args = append(args, "-t", concurrency)
	}
	args = append(args, strings.Fields(strings.TrimSpace(request.Options["extra_args"]))...)

	emitProgress(request, fmt.Sprintf("Subfinder enumerating %d domains", len(targets)))
	output, commandLine, err := runCLICommand(ctx, request, "subfinder", args)
	writeCommandLog(logPath, commandLine, output)
	if err != nil {
		return PluginRunResult{
			Artifacts: []jobArtifact{
				{Label: "Targets", RelPath: filepath.Join(request.Job.ID, "targets.txt")},
				{Label: "Command log", RelPath: filepath.Join(request.Job.ID, "command.log")},
			},
		}, err
	}

	discovered, err := parseLineTargets(resultsPath)
	if err != nil {
		return PluginRunResult{}, err
	}

	summary := fmt.Sprintf("subfinder discovered %d subdomains across %d domains.", len(discovered), len(targets))
	if len(discovered) == 0 {
		summary = fmt.Sprintf("subfinder completed across %d domains with no retained subdomains.", len(targets))
	}

	return PluginRunResult{
		Summary: summary,
		Artifacts: []jobArtifact{
			{Label: "Targets", RelPath: filepath.Join(request.Job.ID, "targets.txt")},
			{Label: "Results", RelPath: filepath.Join(request.Job.ID, "results.txt")},
			{Label: "Command log", RelPath: filepath.Join(request.Job.ID, "command.log")},
		},
		DerivedTargets: discovered,
	}, nil
}

type katanaPlugin struct{}

func (p *katanaPlugin) Definition() PluginDefinitionView {
	return PluginDefinitionView{
		ID:               "katana",
		Label:            "Katana Crawl Discovery",
		Description:      "Crawl mapped web applications, discover reachable paths, and fold the path inventory back into the workspace.",
		Mode:             "Managed command",
		Family:           "Web discovery",
		Availability:     "available",
		AvailabilityTone: "accent",
	}
}

func (p *katanaPlugin) Run(ctx context.Context, request pluginRunRequest) (PluginRunResult, error) {
	targets := explicitWebTargetsForRequest(request)
	if len(targets) == 0 {
		return PluginRunResult{}, errors.New("katana requires URLs or hosts with inferred HTTP targets")
	}

	targetsPath := filepath.Join(request.WorkDir, "targets.txt")
	resultsPath := filepath.Join(request.WorkDir, "results.jsonl")
	logPath := filepath.Join(request.WorkDir, "command.log")
	if err := writeTargetsFile(targetsPath, targets); err != nil {
		return PluginRunResult{}, err
	}

	depth := chooseString(strings.TrimSpace(request.Options["crawl_depth"]), "2")
	args := []string{"-list", targetsPath, "-j", "-d", depth, "-silent", "-o", resultsPath}
	if concurrency := strings.TrimSpace(request.Options["concurrency"]); concurrency != "" {
		args = append(args, "-c", concurrency)
	}
	args = append(args, strings.Fields(strings.TrimSpace(request.Options["extra_args"]))...)

	emitProgress(request, fmt.Sprintf("Katana crawling %d targets", len(targets)))
	output, commandLine, err := runCLICommand(ctx, request, "katana", args)
	writeCommandLog(logPath, commandLine, output)
	if err != nil {
		return PluginRunResult{Artifacts: baseCommandArtifacts(request.Job.ID, true, fileExists(resultsPath))}, err
	}

	findings, totals, err := parseKatanaJSONL(resultsPath, buildHostResolutionMap(request))
	if err != nil {
		return PluginRunResult{}, err
	}

	summary := fmt.Sprintf("katana discovered %d crawl observations across %d starting points.", totals.Total, len(targets))
	if totals.Total == 0 {
		summary = fmt.Sprintf("katana completed across %d starting points with no retained path observations.", len(targets))
	}

	return PluginRunResult{
		Summary:        summary,
		Artifacts:      baseCommandArtifacts(request.Job.ID, true, fileExists(resultsPath)),
		Findings:       totals,
		NucleiFindings: findings,
	}, nil
}

type zapConnectorPlugin struct{}

func (p *zapConnectorPlugin) Definition() PluginDefinitionView {
	return PluginDefinitionView{
		ID:               "zap-connector",
		Label:            "OWASP ZAP Connector",
		Description:      "Launch spider and active-scan passes through the ZAP API, poll progress, and ingest alerts into the workspace.",
		Mode:             "API connector",
		Family:           "Web DAST",
		Availability:     "available",
		AvailabilityTone: "accent",
	}
}

func (p *zapConnectorPlugin) Run(ctx context.Context, request pluginRunRequest) (PluginRunResult, error) {
	targets := explicitWebTargetsForRequest(request)
	if len(targets) == 0 {
		return PluginRunResult{}, errors.New("the ZAP connector requires URLs or hosts with inferred HTTP targets")
	}

	baseURL := chooseString(optionOrEnv(request.Options, []string{"api_base_url"}, "NWA_ZAP_API_URL", "ZAP_API_URL"), "http://127.0.0.1:8080")
	apiKey := optionOrEnv(request.Options, nil, "NWA_ZAP_API_KEY", "ZAP_API_KEY")
	client := integrationHTTPClient(connectorInsecure(request.Options, "NWA_ZAP_INSECURE", "ZAP_API_INSECURE"))
	resultsPath := filepath.Join(request.WorkDir, "alerts.json")

	alertsByIP := map[string][]storedNucleiFinding{}
	totals := FindingSummary{}
	serialized := make([]map[string]any, 0)
	for _, target := range targets {
		emitProgress(request, "ZAP spider queued for "+target)
		spiderID, err := zapAction(ctx, client, baseURL, apiKey, "spider", "scan", map[string]string{"url": target, "recurse": "true"})
		if err != nil {
			return PluginRunResult{}, err
		}
		if err := zapPoll(ctx, client, baseURL, apiKey, "spider", spiderID, request, target); err != nil {
			return PluginRunResult{}, err
		}
		if err := zapWaitPassive(ctx, client, baseURL, apiKey, request); err != nil {
			return PluginRunResult{}, err
		}

		emitProgress(request, "ZAP active scan queued for "+target)
		activeID, err := zapAction(ctx, client, baseURL, apiKey, "ascan", "scan", map[string]string{"url": target, "recurse": "true", "inScopeOnly": "false"})
		if err != nil {
			return PluginRunResult{}, err
		}
		if err := zapPoll(ctx, client, baseURL, apiKey, "ascan", activeID, request, target); err != nil {
			return PluginRunResult{}, err
		}
		if err := zapWaitPassive(ctx, client, baseURL, apiKey, request); err != nil {
			return PluginRunResult{}, err
		}

		alertRows, err := zapAlerts(ctx, client, baseURL, apiKey, target)
		if err != nil {
			return PluginRunResult{}, err
		}
		serialized = append(serialized, alertRows...)
		findings, summary := mapZAPAlerts(alertRows, buildHostResolutionMap(request))
		totals = mergeFindingSummaries(totals, summary)
		for ip, rows := range findings {
			alertsByIP[ip] = mergeStoredFindings(alertsByIP[ip], rows)
		}
	}

	payload, _ := json.MarshalIndent(serialized, "", "  ")
	_ = os.WriteFile(resultsPath, payload, 0o600)

	summary := fmt.Sprintf("ZAP completed across %d targets with %d alerts ingested.", len(targets), totals.Total)
	if totals.Total == 0 {
		summary = fmt.Sprintf("ZAP completed across %d targets with no alerts.", len(targets))
	}

	return PluginRunResult{
		Summary:        summary,
		Artifacts:      []jobArtifact{{Label: "Alerts", RelPath: filepath.Join(request.Job.ID, "alerts.json")}},
		Findings:       totals,
		NucleiFindings: alertsByIP,
	}, nil
}

type burpConnectorPlugin struct{}

func (p *burpConnectorPlugin) Definition() PluginDefinitionView {
	return PluginDefinitionView{
		ID:               "burp-connector",
		Label:            "Burp Suite DAST Connector",
		Description:      "Create or reuse Burp DAST sites, schedule on-demand scans, poll scan state, and ingest issues back into the workspace.",
		Mode:             "API connector",
		Family:           "Web DAST",
		Availability:     "available",
		AvailabilityTone: "accent",
	}
}

func (p *burpConnectorPlugin) Run(ctx context.Context, request pluginRunRequest) (PluginRunResult, error) {
	targets := explicitWebTargetsForRequest(request)
	if len(targets) == 0 {
		return PluginRunResult{}, errors.New("the Burp connector requires URLs or hosts with inferred HTTP targets")
	}

	baseURL := optionOrEnv(request.Options, []string{"api_base_url"}, "NWA_BURP_API_URL", "BURP_API_URL")
	token := optionOrEnv(request.Options, nil, "NWA_BURP_API_TOKEN", "BURP_API_TOKEN")
	if strings.TrimSpace(baseURL) == "" || strings.TrimSpace(token) == "" {
		return PluginRunResult{}, errors.New("the Burp connector requires BURP_API_URL and BURP_API_TOKEN")
	}

	client := integrationHTTPClient(connectorInsecure(request.Options, "NWA_BURP_INSECURE", "BURP_API_INSECURE"))
	resultsPath := filepath.Join(request.WorkDir, "issues.json")
	resolutions := buildHostResolutionMap(request)
	scanConfigIDs := parseCSVInts(optionOrEnv(request.Options, []string{"scan_config_ids"}, "NWA_BURP_SCAN_CONFIG_IDS", "BURP_SCAN_CONFIG_IDS"))
	parentID := parseIntDefault(optionOrEnv(request.Options, []string{"parent_id"}, "NWA_BURP_PARENT_ID", "BURP_PARENT_ID"), 0)
	explicitSiteID := parseIntDefault(optionOrEnv(request.Options, []string{"site_id"}, "NWA_BURP_SITE_ID", "BURP_SITE_ID"), 0)

	issuesByIP := map[string][]storedNucleiFinding{}
	totals := FindingSummary{}
	collected := make([]map[string]any, 0)
	for _, target := range targets {
		siteID := explicitSiteID
		if siteID == 0 {
			emitProgress(request, "Burp site creation for "+target)
			createdID, err := burpCreateSite(ctx, client, baseURL, token, target, parentID, scanConfigIDs)
			if err != nil {
				return PluginRunResult{}, err
			}
			siteID = createdID
		}

		emitProgress(request, "Burp scan scheduled for "+target)
		if err := burpScheduleScan(ctx, client, baseURL, token, siteID); err != nil {
			return PluginRunResult{}, err
		}

		scanID, err := burpWaitForLatestScan(ctx, client, baseURL, token, siteID, request)
		if err != nil {
			return PluginRunResult{}, err
		}

		emitProgress(request, "Burp issue sync for "+target)
		issues, err := burpScanIssues(ctx, client, baseURL, token, scanID)
		if err != nil {
			return PluginRunResult{}, err
		}
		collected = append(collected, issues...)

		findings, summary := mapBurpIssues(issues, resolutions)
		totals = mergeFindingSummaries(totals, summary)
		for ip, rows := range findings {
			issuesByIP[ip] = mergeStoredFindings(issuesByIP[ip], rows)
		}
	}

	payload, _ := json.MarshalIndent(collected, "", "  ")
	_ = os.WriteFile(resultsPath, payload, 0o600)

	summary := fmt.Sprintf("Burp completed across %d targets with %d issues ingested.", len(targets), totals.Total)
	if totals.Total == 0 {
		summary = fmt.Sprintf("Burp completed across %d targets with no issues.", len(targets))
	}

	return PluginRunResult{
		Summary:        summary,
		Artifacts:      []jobArtifact{{Label: "Issues", RelPath: filepath.Join(request.Job.ID, "issues.json")}},
		Findings:       totals,
		NucleiFindings: issuesByIP,
	}, nil
}

type tenableConnectorPlugin struct{}

func (p *tenableConnectorPlugin) Definition() PluginDefinitionView {
	return PluginDefinitionView{
		ID:               "tenable-connector",
		Label:            "Tenable VM Connector",
		Description:      "Launch a Tenable Vulnerability Management scan, poll completion, export the .nessus report, and import it into the workspace.",
		Mode:             "API connector",
		Family:           "Vulnerability management",
		Availability:     "available",
		AvailabilityTone: "accent",
	}
}

func (p *tenableConnectorPlugin) Run(ctx context.Context, request pluginRunRequest) (PluginRunResult, error) {
	return runTenableStyleConnector(ctx, request, tenableConnectorProfile{
		Label:          "Tenable VM",
		DefaultBaseURL: "https://cloud.tenable.com",
		EnvPrefix:      "TENABLE",
	})
}

type nessusConnectorPlugin struct{}

func (p *nessusConnectorPlugin) Definition() PluginDefinitionView {
	return PluginDefinitionView{
		ID:               "nessus-connector",
		Label:            "Nessus Manager Connector",
		Description:      "Launch a Nessus-managed scan, poll completion, export the .nessus report, and import it into the workspace.",
		Mode:             "API connector",
		Family:           "Vulnerability management",
		Availability:     "available",
		AvailabilityTone: "accent",
	}
}

func (p *nessusConnectorPlugin) Run(ctx context.Context, request pluginRunRequest) (PluginRunResult, error) {
	return runTenableStyleConnector(ctx, request, tenableConnectorProfile{
		Label:          "Nessus Manager",
		DefaultBaseURL: "https://127.0.0.1:8834",
		EnvPrefix:      "NESSUS",
	})
}

type tenableConnectorProfile struct {
	Label          string
	DefaultBaseURL string
	EnvPrefix      string
}

func runTenableStyleConnector(ctx context.Context, request pluginRunRequest, profile tenableConnectorProfile) (PluginRunResult, error) {
	baseURL := chooseString(
		strings.TrimSpace(request.Options["api_base_url"]),
		os.Getenv("NWA_"+profile.EnvPrefix+"_API_URL"),
		os.Getenv(profile.EnvPrefix+"_API_URL"),
		profile.DefaultBaseURL,
	)
	accessKey := chooseString(os.Getenv("NWA_"+profile.EnvPrefix+"_ACCESS_KEY"), os.Getenv(profile.EnvPrefix+"_ACCESS_KEY"))
	secretKey := chooseString(os.Getenv("NWA_"+profile.EnvPrefix+"_SECRET_KEY"), os.Getenv(profile.EnvPrefix+"_SECRET_KEY"))
	scanID := chooseString(strings.TrimSpace(request.Options["scan_id"]), os.Getenv("NWA_"+profile.EnvPrefix+"_SCAN_ID"), os.Getenv(profile.EnvPrefix+"_SCAN_ID"))
	if accessKey == "" || secretKey == "" || scanID == "" {
		return PluginRunResult{}, fmt.Errorf("%s connector requires %s_ACCESS_KEY, %s_SECRET_KEY, and %s_SCAN_ID", profile.Label, profile.EnvPrefix, profile.EnvPrefix, profile.EnvPrefix)
	}

	client := integrationHTTPClient(connectorInsecure(request.Options, "NWA_"+profile.EnvPrefix+"_INSECURE", profile.EnvPrefix+"_API_INSECURE"))
	hostIPs := uniqueStrings(append(append([]string(nil), request.Job.HostIPs...), resolveKnownHostsFromTargets(request.RawTargets)...))
	emitProgress(request, profile.Label+" launch requested")
	if err := tenableLaunch(ctx, client, baseURL, accessKey, secretKey, scanID, hostIPs); err != nil {
		return PluginRunResult{}, err
	}
	if err := tenableWaitForScan(ctx, client, baseURL, accessKey, secretKey, scanID, request, profile.Label); err != nil {
		return PluginRunResult{}, err
	}

	emitProgress(request, profile.Label+" export requested")
	fileID, err := tenableRequestExport(ctx, client, baseURL, accessKey, secretKey, scanID)
	if err != nil {
		return PluginRunResult{}, err
	}
	if err := tenableWaitForExport(ctx, client, baseURL, accessKey, secretKey, scanID, fileID, request, profile.Label); err != nil {
		return PluginRunResult{}, err
	}

	nessusPath := filepath.Join(request.WorkDir, "scan.nessus")
	if err := tenableDownloadExport(ctx, client, baseURL, accessKey, secretKey, scanID, fileID, nessusPath); err != nil {
		return PluginRunResult{}, err
	}

	return PluginRunResult{
		Summary:          fmt.Sprintf("%s export imported into the workspace.", profile.Label),
		Artifacts:        []jobArtifact{{Label: "Report", RelPath: filepath.Join(request.Job.ID, "scan.nessus")}},
		ImportedScanPath: nessusPath,
		ImportedScanName: strings.ToLower(strings.ReplaceAll(profile.Label, " ", "-")) + "-" + request.Job.ID,
	}, nil
}

func emitProgress(request pluginRunRequest, summary string) {
	if request.Progress != nil {
		request.Progress(summary)
	}
}

func baseCommandArtifacts(jobID string, includeTargets bool, includeResults bool) []jobArtifact {
	artifacts := make([]jobArtifact, 0, 3)
	if includeTargets {
		artifacts = append(artifacts, jobArtifact{Label: "Targets", RelPath: filepath.Join(jobID, "targets.txt")})
	}
	if includeResults {
		artifacts = append(artifacts, jobArtifact{Label: "Results", RelPath: filepath.Join(jobID, "results.jsonl")})
	}
	artifacts = append(artifacts, jobArtifact{Label: "Command log", RelPath: filepath.Join(jobID, "command.log")})
	return artifacts
}

func writeTargetsFile(path string, targets []string) error {
	return os.WriteFile(path, []byte(strings.Join(uniqueStrings(targets), "\n")+"\n"), 0o600)
}

func parseLineTargets(path string) ([]string, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	lines := strings.Split(strings.ReplaceAll(string(payload), "\r\n", "\n"), "\n")
	targets := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	return uniqueStrings(targets), nil
}

func httpxTargetsForRequest(request pluginRunRequest) []string {
	targets := append([]string(nil), nucleiTargetsForHosts(request.Hosts)...)
	for _, target := range request.RawTargets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		targets = append(targets, target)
	}
	return uniqueStrings(targets)
}

func explicitWebTargetsForRequest(request pluginRunRequest) []string {
	targets := append([]string(nil), nucleiTargetsForHosts(request.Hosts)...)
	for _, target := range request.RawTargets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		lower := strings.ToLower(target)
		switch {
		case strings.HasPrefix(lower, "http://"), strings.HasPrefix(lower, "https://"):
			targets = append(targets, target)
		case addrTypeForValue(target) != "" || strings.Contains(target, "."):
			targets = append(targets, "https://"+target, "http://"+target)
		}
	}
	return uniqueStrings(targets)
}

func dnsTargetsForRequest(request pluginRunRequest) []string {
	targets := make([]string, 0)
	for _, host := range request.Hosts {
		for _, hostname := range host.Hostnames {
			hostname = strings.TrimSpace(hostname)
			if hostname != "" {
				targets = append(targets, hostname)
			}
		}
		if host.DisplayName != "" && host.DisplayName != host.IP && addrTypeForValue(host.DisplayName) == "" {
			targets = append(targets, host.DisplayName)
		}
	}
	for _, raw := range request.RawTargets {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
			targets = append(targets, parsed.Hostname())
			continue
		}
		if addrTypeForValue(raw) == "" && !strings.Contains(raw, "/") {
			targets = append(targets, raw)
		}
	}
	return uniqueStrings(targets)
}

func subfinderTargetsForRequest(request pluginRunRequest) []string {
	targets := make([]string, 0, len(request.RawTargets))
	for _, raw := range request.RawTargets {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
			raw = parsed.Hostname()
		}
		if addrTypeForValue(raw) != "" || strings.Contains(raw, "/") {
			continue
		}
		if strings.Count(raw, ".") < 1 {
			continue
		}
		targets = append(targets, strings.ToLower(strings.Trim(raw, ".")))
	}
	return uniqueStrings(targets)
}

func decodeJSONObjectLines(path string) ([]map[string]any, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	rows := make([]map[string]any, 0)
	for {
		var row map[string]any
		if err := decoder.Decode(&row); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if len(row) > 0 {
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func parseHTTPXJSONL(path string, resolutions map[string]string) (map[string][]storedNucleiFinding, FindingSummary, error) {
	rows, err := decodeJSONObjectLines(path)
	if err != nil {
		return nil, FindingSummary{}, err
	}

	results := map[string][]storedNucleiFinding{}
	summary := FindingSummary{}
	for _, row := range rows {
		target := chooseString(stringField(row["url"]), stringField(row["input"]), stringField(row["host"]))
		if target == "" {
			continue
		}
		hostIP := resolveKnownIP(chooseString(stringField(row["ip"]), stringField(row["host"]), target), resolutions)
		if hostIP == "" {
			if parsed, err := url.Parse(target); err == nil && parsed.Hostname() != "" {
				hostIP = parsed.Hostname()
			}
		}
		if hostIP == "" {
			continue
		}

		statusCode := stringField(row["status_code"])
		title := strings.TrimSpace(stringField(row["title"]))
		server := strings.TrimSpace(stringField(row["webserver"]))
		tech := anyStrings(row["tech"])
		detail := joinNonEmpty([]string{
			prefixIf(title, "title: "),
			prefixIf(server, "server: "),
			prefixIf(strings.Join(tech, ", "), "tech: "),
		}, " · ")
		name := chooseString(prefixIf(statusCode, "HTTP "), "HTTP service observed")
		if title != "" {
			name = strings.TrimSpace(name + " · " + title)
		}
		finding := storedNucleiFinding{
			Source:      "httpx",
			TemplateID:  chooseString("httpx-"+statusCode, "httpx"),
			Name:        name,
			Severity:    "info",
			Target:      target,
			MatchedAt:   target,
			Type:        "web-census",
			Description: detail,
			Tags:        tech,
		}
		results[hostIP] = append(results[hostIP], finding)
		summary = addFindingSeverity(summary, finding.Severity)
	}
	for ip, findings := range results {
		results[ip] = mergeStoredFindings(nil, findings)
	}
	return results, summary, nil
}

func parseDNSXJSONL(path string, resolutions map[string]string) (map[string][]storedNucleiFinding, FindingSummary, error) {
	rows, err := decodeJSONObjectLines(path)
	if err != nil {
		return nil, FindingSummary{}, err
	}

	results := map[string][]storedNucleiFinding{}
	summary := FindingSummary{}
	for _, row := range rows {
		host := chooseString(stringField(row["host"]), stringField(row["input"]))
		if host == "" {
			continue
		}
		answers := append(anyStrings(row["a"]), anyStrings(row["aaaa"])...)
		cnames := anyStrings(row["cname"])
		hostIP := resolveKnownIP(host, resolutions)
		if hostIP == "" {
			for _, answer := range answers {
				if resolved := resolveKnownIP(answer, resolutions); resolved != "" {
					hostIP = resolved
					break
				}
			}
		}
		if hostIP == "" {
			continue
		}

		detail := joinNonEmpty([]string{
			prefixIf(strings.Join(answers, ", "), "A/AAAA: "),
			prefixIf(strings.Join(cnames, ", "), "CNAME: "),
			prefixIf(stringField(row["resolver"]), "resolver: "),
		}, " · ")
		finding := storedNucleiFinding{
			Source:      "dnsx",
			TemplateID:  "dnsx-observation",
			Name:        "DNS records observed",
			Severity:    "info",
			Target:      host,
			MatchedAt:   host,
			Type:        "dns-observation",
			Description: detail,
			Tags:        append([]string(nil), cnames...),
		}
		results[hostIP] = append(results[hostIP], finding)
		summary = addFindingSeverity(summary, finding.Severity)
	}
	for ip, findings := range results {
		results[ip] = mergeStoredFindings(nil, findings)
	}
	return results, summary, nil
}

func parseKatanaJSONL(path string, resolutions map[string]string) (map[string][]storedNucleiFinding, FindingSummary, error) {
	rows, err := decodeJSONObjectLines(path)
	if err != nil {
		return nil, FindingSummary{}, err
	}

	results := map[string][]storedNucleiFinding{}
	summary := FindingSummary{}
	for _, row := range rows {
		target := chooseString(stringField(row["url"]), nestedStringField(row, "request", "endpoint"), stringField(row["endpoint"]))
		if target == "" {
			continue
		}
		hostIP := resolveKnownIP(target, resolutions)
		if hostIP == "" {
			continue
		}
		statusCode := chooseString(nestedStringField(row, "response", "status_code"), stringField(row["status_code"]))
		name := "Discovered web path"
		if statusCode != "" {
			name = "Discovered web path · " + statusCode
		}
		finding := storedNucleiFinding{
			Source:      "katana",
			TemplateID:  "katana-path",
			Name:        name,
			Severity:    "info",
			Target:      target,
			MatchedAt:   target,
			Type:        "content-discovery",
			Description: joinNonEmpty([]string{prefixIf(statusCode, "status: "), prefixIf(nestedStringField(row, "request", "method"), "method: ")}, " · "),
		}
		results[hostIP] = append(results[hostIP], finding)
		summary = addFindingSeverity(summary, finding.Severity)
	}
	for ip, findings := range results {
		results[ip] = mergeStoredFindings(nil, findings)
	}
	return results, summary, nil
}

func countResponsiveTargets(findings map[string][]storedNucleiFinding) int {
	total := 0
	for _, rows := range findings {
		total += len(rows)
	}
	return total
}

func zapAction(ctx context.Context, client *http.Client, baseURL string, apiKey string, component string, action string, params map[string]string) (string, error) {
	body, err := zapJSON(ctx, client, baseURL, apiKey, component, "action", action, params)
	if err != nil {
		return "", err
	}
	return chooseString(stringField(body[action]), stringField(body["scan"])), nil
}

func zapPoll(ctx context.Context, client *http.Client, baseURL string, apiKey string, component string, scanID string, request pluginRunRequest, target string) error {
	for {
		body, err := zapJSON(ctx, client, baseURL, apiKey, component, "view", "status", map[string]string{"scanId": scanID})
		if err != nil {
			return err
		}
		status := parseIntDefault(stringField(body["status"]), 0)
		emitProgress(request, fmt.Sprintf("ZAP %s %s%% · %s", component, strconv.Itoa(status), target))
		if status >= 100 {
			return nil
		}
		if err := sleepWithContext(ctx, 2*time.Second); err != nil {
			return err
		}
	}
}

func zapWaitPassive(ctx context.Context, client *http.Client, baseURL string, apiKey string, request pluginRunRequest) error {
	for {
		body, err := zapJSON(ctx, client, baseURL, apiKey, "pscan", "view", "recordsToScan", nil)
		if err != nil {
			return err
		}
		remaining := parseIntDefault(stringField(body["recordsToScan"]), 0)
		emitProgress(request, fmt.Sprintf("ZAP passive queue %d remaining", remaining))
		if remaining == 0 {
			return nil
		}
		if err := sleepWithContext(ctx, 2*time.Second); err != nil {
			return err
		}
	}
}

func zapAlerts(ctx context.Context, client *http.Client, baseURL string, apiKey string, target string) ([]map[string]any, error) {
	body, err := zapJSON(ctx, client, baseURL, apiKey, "core", "view", "alerts", map[string]string{
		"baseurl": target,
		"start":   "0",
		"count":   "5000",
	})
	if err != nil {
		return nil, err
	}
	rows, _ := body["alerts"].([]any)
	results := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		if mapped, ok := row.(map[string]any); ok {
			results = append(results, mapped)
		}
	}
	return results, nil
}

func zapJSON(ctx context.Context, client *http.Client, baseURL string, apiKey string, component string, group string, name string, params map[string]string) (map[string]any, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	query := url.Values{}
	for key, value := range params {
		if strings.TrimSpace(value) != "" {
			query.Set(key, value)
		}
	}
	if apiKey != "" {
		query.Set("apikey", apiKey)
	}
	endpoint := fmt.Sprintf("%s/JSON/%s/%s/%s/", baseURL, component, group, name)
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("zaproxy api %s failed: %s", name, strings.TrimSpace(string(body)))
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return body, nil
}

func mapZAPAlerts(rows []map[string]any, resolutions map[string]string) (map[string][]storedNucleiFinding, FindingSummary) {
	results := map[string][]storedNucleiFinding{}
	summary := FindingSummary{}
	for _, row := range rows {
		target := chooseString(stringField(row["url"]), stringField(row["instanceurl"]))
		hostIP := resolveKnownIP(target, resolutions)
		if hostIP == "" {
			continue
		}
		severity := normalizeSeverity(stringField(row["risk"]))
		name := chooseString(stringField(row["alert"]), stringField(row["name"]), "ZAP alert")
		detail := joinNonEmpty([]string{
			prefixIf(stringField(row["param"]), "param: "),
			prefixIf(stringField(row["description"]), "desc: "),
			prefixIf(stringField(row["solution"]), "fix: "),
		}, " · ")
		finding := storedNucleiFinding{
			Source:      "zap",
			TemplateID:  chooseString(stringField(row["pluginId"]), slugString(name)),
			Name:        name,
			Severity:    severity,
			Target:      target,
			MatchedAt:   target,
			Type:        "zap-alert",
			Description: detail,
			Tags:        splitCSVTagField(row["cweid"], row["wascid"]),
		}
		results[hostIP] = append(results[hostIP], finding)
		summary = addFindingSeverity(summary, finding.Severity)
	}
	for ip, findings := range results {
		results[ip] = mergeStoredFindings(nil, findings)
	}
	return results, summary
}

var htmlTagPattern = regexp.MustCompile(`<[^>]+>`)

func burpCreateSite(ctx context.Context, client *http.Client, baseURL string, token string, target string, parentID int, scanConfigIDs []int) (int, error) {
	query := `mutation CreateSite($name: String!, $parentId: Int!, $startURL: String!, $scanConfigIds: [Int!]) {
  create_site(input: {name: $name, parent_id: $parentId, scope_v2: {start_urls: [{url: $startURL}]}, scan_config_ids: $scanConfigIds}) {
    site { id }
  }
}`
	var response struct {
		CreateSite struct {
			Site struct {
				ID int `json:"id"`
			} `json:"site"`
		} `json:"create_site"`
	}
	err := burpGraphQL(ctx, client, baseURL, token, query, map[string]any{
		"name":          "NWA " + hostFromTarget(target),
		"parentId":      parentID,
		"startURL":      target,
		"scanConfigIds": scanConfigIDs,
	}, &response)
	if err != nil {
		return 0, err
	}
	if response.CreateSite.Site.ID == 0 {
		return 0, errors.New("burp create_site returned no site id")
	}
	return response.CreateSite.Site.ID, nil
}

func burpScheduleScan(ctx context.Context, client *http.Client, baseURL string, token string, siteID int) error {
	query := `mutation CreateScheduleItem($siteId: Int!) {
  create_schedule_item(input: {site_id: $siteId, schedule_type: ON_DEMAND}) {
    schedule_item { id }
  }
}`
	var response struct {
		CreateScheduleItem struct {
			ScheduleItem struct {
				ID int `json:"id"`
			} `json:"schedule_item"`
		} `json:"create_schedule_item"`
	}
	if err := burpGraphQL(ctx, client, baseURL, token, query, map[string]any{"siteId": siteID}, &response); err != nil {
		return err
	}
	if response.CreateScheduleItem.ScheduleItem.ID == 0 {
		return errors.New("burp create_schedule_item returned no schedule id")
	}
	return nil
}

func burpWaitForLatestScan(ctx context.Context, client *http.Client, baseURL string, token string, siteID int, request pluginRunRequest) (int, error) {
	query := `query LatestScan($siteId: Int!) {
  scans(site_id: $siteId, limit: 1) {
    id
    status
  }
}`
	for {
		var response struct {
			Scans []struct {
				ID     int    `json:"id"`
				Status string `json:"status"`
			} `json:"scans"`
		}
		if err := burpGraphQL(ctx, client, baseURL, token, query, map[string]any{"siteId": siteID}, &response); err != nil {
			return 0, err
		}
		if len(response.Scans) > 0 {
			status := strings.ToLower(strings.TrimSpace(response.Scans[0].Status))
			emitProgress(request, "Burp scan "+humanizeStatus(status))
			switch status {
			case "succeeded", "completed", "succeeded_with_issues":
				return response.Scans[0].ID, nil
			case "failed", "cancelled", "canceled":
				return 0, fmt.Errorf("burp scan ended with status %s", response.Scans[0].Status)
			}
		}
		if err := sleepWithContext(ctx, 5*time.Second); err != nil {
			return 0, err
		}
	}
}

func burpScanIssues(ctx context.Context, client *http.Client, baseURL string, token string, scanID int) ([]map[string]any, error) {
	query := `query ScanIssues($scanId: Int!) {
  scan(id: $scanId) {
    issues {
      serial_number
      name
      severity
      path
      origin
      description_html
      remediation_html
      confidence
    }
  }
}`
	var response struct {
		Scan struct {
			Issues []map[string]any `json:"issues"`
		} `json:"scan"`
	}
	if err := burpGraphQL(ctx, client, baseURL, token, query, map[string]any{"scanId": scanID}, &response); err != nil {
		return nil, err
	}
	return response.Scan.Issues, nil
}

func burpGraphQL(ctx context.Context, client *http.Client, baseURL string, token string, query string, variables map[string]any, out any) error {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	payload, err := json.Marshal(map[string]any{
		"query":     query,
		"variables": variables,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/graphql/v1", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var raw struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("burp api request failed with status %d", resp.StatusCode)
	}
	if len(raw.Errors) > 0 {
		return errors.New(raw.Errors[0].Message)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw.Data, out)
}

func mapBurpIssues(rows []map[string]any, resolutions map[string]string) (map[string][]storedNucleiFinding, FindingSummary) {
	results := map[string][]storedNucleiFinding{}
	summary := FindingSummary{}
	for _, row := range rows {
		target := chooseString(stringField(row["origin"]), stringField(row["path"]))
		hostIP := resolveKnownIP(target, resolutions)
		if hostIP == "" {
			continue
		}
		severity := normalizeSeverity(stringField(row["severity"]))
		name := chooseString(stringField(row["name"]), "Burp issue")
		detail := joinNonEmpty([]string{
			stripHTMLSnippet(stringField(row["description_html"])),
			prefixIf(stripHTMLSnippet(stringField(row["remediation_html"])), "fix: "),
			prefixIf(stringField(row["confidence"]), "confidence: "),
		}, " · ")
		finding := storedNucleiFinding{
			Source:      "burp",
			TemplateID:  chooseString(stringField(row["serial_number"]), slugString(name)),
			Name:        name,
			Severity:    severity,
			Target:      target,
			MatchedAt:   target,
			Type:        "burp-issue",
			Description: detail,
		}
		results[hostIP] = append(results[hostIP], finding)
		summary = addFindingSeverity(summary, finding.Severity)
	}
	for ip, findings := range results {
		results[ip] = mergeStoredFindings(nil, findings)
	}
	return results, summary
}

func tenableLaunch(ctx context.Context, client *http.Client, baseURL string, accessKey string, secretKey string, scanID string, hostIPs []string) error {
	body := map[string]any{}
	if len(hostIPs) > 0 {
		body["alt_targets"] = strings.Join(hostIPs, ",")
	}
	_, err := tenableJSON(ctx, client, http.MethodPost, baseURL, accessKey, secretKey, "/scans/"+scanID+"/launch", body)
	return err
}

func tenableWaitForScan(ctx context.Context, client *http.Client, baseURL string, accessKey string, secretKey string, scanID string, request pluginRunRequest, label string) error {
	for {
		payload, err := tenableJSON(ctx, client, http.MethodGet, baseURL, accessKey, secretKey, "/scans/"+scanID+"/latest-status", nil)
		if err != nil {
			return err
		}
		status := strings.ToLower(chooseString(stringField(payload["status"]), nestedStringField(payload, "info", "status")))
		emitProgress(request, label+" "+humanizeStatus(status))
		switch status {
		case "completed", "imported":
			return nil
		case "aborted", "canceled", "cancelled", "error", "failed":
			return fmt.Errorf("%s scan ended with status %s", label, status)
		}
		if err := sleepWithContext(ctx, 5*time.Second); err != nil {
			return err
		}
	}
}

func tenableRequestExport(ctx context.Context, client *http.Client, baseURL string, accessKey string, secretKey string, scanID string) (string, error) {
	payload, err := tenableJSON(ctx, client, http.MethodPost, baseURL, accessKey, secretKey, "/scans/"+scanID+"/export", map[string]any{"format": "nessus"})
	if err != nil {
		return "", err
	}
	fileID := chooseString(stringField(payload["file"]), stringField(payload["file_id"]))
	if fileID == "" {
		return "", errors.New("tenable export request returned no file id")
	}
	return fileID, nil
}

func tenableWaitForExport(ctx context.Context, client *http.Client, baseURL string, accessKey string, secretKey string, scanID string, fileID string, request pluginRunRequest, label string) error {
	for {
		payload, err := tenableJSON(ctx, client, http.MethodGet, baseURL, accessKey, secretKey, "/scans/"+scanID+"/export/"+fileID+"/status", nil)
		if err != nil {
			return err
		}
		status := strings.ToLower(strings.TrimSpace(stringField(payload["status"])))
		emitProgress(request, label+" export "+humanizeStatus(status))
		switch status {
		case "ready", "finished":
			return nil
		case "error", "cancelled", "canceled", "failed":
			return fmt.Errorf("%s export ended with status %s", label, status)
		}
		if err := sleepWithContext(ctx, 4*time.Second); err != nil {
			return err
		}
	}
}

func tenableDownloadExport(ctx context.Context, client *http.Client, baseURL string, accessKey string, secretKey string, scanID string, fileID string, destination string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/scans/"+scanID+"/export/"+fileID+"/download", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-ApiKeys", fmt.Sprintf("accessKey=%s; secretKey=%s", accessKey, secretKey))
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("tenable export download failed: %s", strings.TrimSpace(string(body)))
	}
	output, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer output.Close()
	_, err = io.Copy(output, resp.Body)
	return err
}

func tenableJSON(ctx context.Context, client *http.Client, method string, baseURL string, accessKey string, secretKey string, path string, body any) (map[string]any, error) {
	var payload io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(baseURL, "/")+path, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ApiKeys", fmt.Sprintf("accessKey=%s; secretKey=%s", accessKey, secretKey))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("tenable api request failed: %s", strings.TrimSpace(string(body)))
	}
	if resp.ContentLength == 0 {
		return map[string]any{}, nil
	}
	var response map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		if errors.Is(err, io.EOF) {
			return map[string]any{}, nil
		}
		return nil, err
	}
	return response, nil
}

func integrationHTTPClient(insecure bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{
		Timeout:   60 * time.Second,
		Transport: transport,
	}
}

func connectorInsecure(options map[string]string, envKeys ...string) bool {
	if parseTruthy(strings.TrimSpace(options["api_insecure"])) {
		return true
	}
	for _, key := range envKeys {
		if parseTruthy(os.Getenv(key)) {
			return true
		}
	}
	return false
}

func optionOrEnv(options map[string]string, optionKeys []string, envKeys ...string) string {
	for _, key := range optionKeys {
		if strings.TrimSpace(options[key]) != "" {
			return strings.TrimSpace(options[key])
		}
	}
	for _, key := range envKeys {
		if strings.TrimSpace(os.Getenv(key)) != "" {
			return strings.TrimSpace(os.Getenv(key))
		}
	}
	return ""
}

func parseCSVInts(value string) []int {
	parts := strings.Split(value, ",")
	results := make([]int, 0, len(parts))
	for _, part := range parts {
		number := parseIntDefault(part, 0)
		if number > 0 {
			results = append(results, number)
		}
	}
	return results
}

func parseIntDefault(value string, fallback int) int {
	if number, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
		return number
	}
	return fallback
}

func anyStrings(value any) []string {
	switch typed := value.(type) {
	case []string:
		return uniqueStrings(typed)
	case []any:
		results := make([]string, 0, len(typed))
		for _, item := range typed {
			value := strings.TrimSpace(stringField(item))
			if value != "" {
				results = append(results, value)
			}
		}
		return uniqueStrings(results)
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return uniqueStrings(strings.FieldsFunc(typed, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\n' || r == '\t'
		}))
	default:
		value := strings.TrimSpace(stringField(value))
		if value == "" {
			return nil
		}
		return []string{value}
	}
}

func nestedStringField(row map[string]any, parent string, key string) string {
	nested, ok := row[parent].(map[string]any)
	if !ok {
		return ""
	}
	return stringField(nested[key])
}

func joinNonEmpty(values []string, separator string) string {
	filtered := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			filtered = append(filtered, value)
		}
	}
	return strings.Join(filtered, separator)
}

func prefixIf(value string, prefix string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return prefix + value
}

func stripHTMLSnippet(value string) string {
	value = htmlTagPattern.ReplaceAllString(value, " ")
	return strings.Join(strings.Fields(value), " ")
}

func slugString(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.NewReplacer(" ", "-", "/", "-", "\\", "-", ":", "-", ".", "-", ",", "-", ";", "-").Replace(value)
	value = strings.Trim(value, "-")
	if value == "" {
		return "finding"
	}
	return value
}

func splitCSVTagField(values ...any) []string {
	results := make([]string, 0)
	for _, value := range values {
		field := strings.TrimSpace(stringField(value))
		if field == "" || field == "0" {
			continue
		}
		results = append(results, strings.FieldsFunc(field, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t'
		})...)
	}
	return uniqueStrings(results)
}

func hostFromTarget(target string) string {
	if parsed, err := url.Parse(strings.TrimSpace(target)); err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	return strings.TrimSpace(target)
}

func resolveKnownHostsFromTargets(targets []string) []string {
	results := make([]string, 0, len(targets))
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if addrTypeForValue(target) != "" {
			results = append(results, target)
			continue
		}
		if parsed, err := url.Parse(target); err == nil && parsed.Hostname() != "" && addrTypeForValue(parsed.Hostname()) != "" {
			results = append(results, parsed.Hostname())
		}
	}
	return uniqueStrings(results)
}

func mergeFindingSummaries(left FindingSummary, right FindingSummary) FindingSummary {
	return FindingSummary{
		Total:    left.Total + right.Total,
		Critical: left.Critical + right.Critical,
		High:     left.High + right.High,
		Medium:   left.Medium + right.Medium,
		Low:      left.Low + right.Low,
		Info:     left.Info + right.Info,
	}
}

func sleepWithContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
