package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const nessusFixture = `<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="External Nessus">
    <ReportHost name="alpha.example.com">
      <HostProperties>
        <tag name="host-ip">10.0.0.44</tag>
        <tag name="host-fqdn">alpha.example.com</tag>
        <tag name="operating-system">Microsoft Windows Server 2022</tag>
        <tag name="HOST_START">2026-03-01 10:00:00</tag>
      </HostProperties>
      <ReportItem port="443" svc_name="www" protocol="tcp" severity="3" pluginID="20001" pluginName="TLS Weak Ciphers" pluginFamily="General">
        <plugin_output>Weak ciphers supported</plugin_output>
        <cve>CVE-2024-0001</cve>
      </ReportItem>
      <ReportItem port="0" svc_name="general" protocol="tcp" severity="2" pluginID="30001" pluginName="SMB Signing Disabled" pluginFamily="Windows">
        <description>Signing is disabled</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`

const nessusCSVFixture = `"Plugin ID","CVE","CVSS","Risk","Host","Protocol","Port","Name","Synopsis","Description","Solution","See Also","Plugin Output"
"19506","","0.0","Info","10.0.0.55","tcp","0","Nessus Scan Information","Scanner metadata","Scanner metadata","None","",""
"20002","CVE-2024-1111","8.8","High","10.0.0.55","tcp","443","TLS Weak Cipher Suites","Weak ciphers detected","Weak ciphers detected","Disable weak suites","https://example.com/advisory","Weak ciphers offered"
"30002","","5.0","Medium","10.0.0.55","tcp","445","SMB Signing Not Required","SMB signing is not enforced","SMB signing is not enforced","Require signing","",""`

func TestParseImportPayloadNormalizesNessus(t *testing.T) {
	parsed, err := parseImportPayload([]byte(nessusFixture), "alpha.nessus")
	if err != nil {
		t.Fatalf("parseImportPayload() error = %v", err)
	}
	if parsed.Scan.Scanner != "nessus" {
		t.Fatalf("Scanner = %q, want nessus", parsed.Scan.Scanner)
	}
	if parsed.FileExt != ".nessus" {
		t.Fatalf("FileExt = %q, want .nessus", parsed.FileExt)
	}

	alive := parsed.Scan.Alive()
	if len(alive) != 1 {
		t.Fatalf("Alive hosts = %d, want 1", len(alive))
	}
	host := alive[0]
	if host.Address.Addr != "10.0.0.44" {
		t.Fatalf("host address = %q, want 10.0.0.44", host.Address.Addr)
	}
	if got := host.OSGuess(); !strings.Contains(got, "Windows") {
		t.Fatalf("OSGuess() = %q, want Windows label", got)
	}
	if len(host.OpenPorts()) != 1 || host.OpenPorts()[0].Portid != "443" {
		t.Fatalf("OpenPorts() = %#v, want single 443/tcp port", host.OpenPorts())
	}

	findings := parsed.Findings["10.0.0.44"]
	if len(findings) != 2 {
		t.Fatalf("findings = %#v, want 2 nessus findings", findings)
	}
	if findings[0].Source != "nessus" {
		t.Fatalf("Source = %q, want nessus", findings[0].Source)
	}
}

func TestWorkspaceImportsNessusAndEnrichesHost(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "assessment.nessus")
	if err := os.WriteFile(path, []byte(nessusFixture), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	workspace, err := openWorkspace(root, nil, logger)
	if err != nil {
		t.Fatalf("openWorkspace() error = %v", err)
	}
	if _, err := workspace.importScanFromPath(path, "filesystem", "assessment.nessus"); err != nil {
		t.Fatalf("importScanFromPath() error = %v", err)
	}

	if workspace.workspaceStatus().ScanCount != 1 {
		t.Fatalf("ScanCount = %d, want 1", workspace.workspaceStatus().ScanCount)
	}
	if got := workspace.scans[0].record.Path; filepath.Ext(got) != ".nessus" {
		t.Fatalf("stored path = %q, want .nessus suffix", got)
	}

	host, ok := workspace.currentSnapshot().host("10.0.0.44")
	if !ok {
		t.Fatalf("host 10.0.0.44 missing after import")
	}
	if host.Findings.Total != 2 || len(host.NucleiFindings) != 2 {
		t.Fatalf("host findings = %#v, want 2 imported findings", host.NucleiFindings)
	}
	if host.NucleiFindings[0].Source != "nessus" {
		t.Fatalf("finding source = %q, want nessus", host.NucleiFindings[0].Source)
	}
}

func TestParseImportPayloadNormalizesNessusCSV(t *testing.T) {
	parsed, err := parseImportPayload([]byte(nessusCSVFixture), "report.csv")
	if err != nil {
		t.Fatalf("parseImportPayload() error = %v", err)
	}
	if parsed.Scan.Scanner != "nessus" {
		t.Fatalf("Scanner = %q, want nessus", parsed.Scan.Scanner)
	}
	if parsed.FileExt != ".csv" {
		t.Fatalf("FileExt = %q, want .csv", parsed.FileExt)
	}

	alive := parsed.Scan.Alive()
	if len(alive) != 1 {
		t.Fatalf("Alive hosts = %d, want 1", len(alive))
	}
	host := alive[0]
	if host.Address.Addr != "10.0.0.55" {
		t.Fatalf("host address = %q, want 10.0.0.55", host.Address.Addr)
	}
	if len(host.OpenPorts()) != 2 {
		t.Fatalf("OpenPorts() = %#v, want 2 normalized ports", host.OpenPorts())
	}

	findings := parsed.Findings["10.0.0.55"]
	if len(findings) != 3 {
		t.Fatalf("findings = %#v, want 3 nessus csv findings", findings)
	}
	if findings[0].Source != "nessus" {
		t.Fatalf("Source = %q, want nessus", findings[0].Source)
	}
}

func TestWorkspaceImportsNessusCSVAndDoesNotConfuseItWithZMap(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "nessus-report.csv")
	if err := os.WriteFile(path, []byte(nessusCSVFixture), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	workspace, err := openWorkspace(root, nil, logger)
	if err != nil {
		t.Fatalf("openWorkspace() error = %v", err)
	}
	if _, err := workspace.importScanFromPath(path, "filesystem", "nessus-report.csv"); err != nil {
		t.Fatalf("importScanFromPath() error = %v", err)
	}

	if workspace.scans[0].record.Scanner != "nessus" {
		t.Fatalf("Scanner = %q, want nessus", workspace.scans[0].record.Scanner)
	}
	host, ok := workspace.currentSnapshot().host("10.0.0.55")
	if !ok {
		t.Fatalf("host 10.0.0.55 missing after import")
	}
	if host.Findings.Total != 3 {
		t.Fatalf("Findings.Total = %d, want 3", host.Findings.Total)
	}
}

func TestParseImportPayloadNormalizesZMapCSV(t *testing.T) {
	payload := "saddr,sport,success\n10.0.0.70,443,1\n10.0.0.71,80,true\n"
	parsed, err := parseImportPayload([]byte(payload), "zmap.csv")
	if err != nil {
		t.Fatalf("parseImportPayload() error = %v", err)
	}
	if parsed.Scan.Scanner != "zmap" {
		t.Fatalf("Scanner = %q, want zmap", parsed.Scan.Scanner)
	}
	if len(parsed.Scan.Alive()) != 2 {
		t.Fatalf("Alive hosts = %d, want 2", len(parsed.Scan.Alive()))
	}
	if ports := parsed.Scan.Alive()[0].OpenPorts(); len(ports) == 0 {
		t.Fatalf("first host ports = %#v, want normalized open port", ports)
	}
}

func TestParseImportPayloadNormalizesZMapText(t *testing.T) {
	payload := "10.0.0.90\n10.0.0.91 443 tcp\n"
	parsed, err := parseImportPayload([]byte(payload), "zmap.txt")
	if err != nil {
		t.Fatalf("parseImportPayload() error = %v", err)
	}
	if parsed.Scan.Scanner != "zmap" {
		t.Fatalf("Scanner = %q, want zmap", parsed.Scan.Scanner)
	}
	if len(parsed.Scan.Alive()) != 2 {
		t.Fatalf("Alive hosts = %d, want 2", len(parsed.Scan.Alive()))
	}
	second := parsed.Scan.Alive()[1]
	if len(second.OpenPorts()) != 1 || second.OpenPorts()[0].Portid != "443" {
		t.Fatalf("second host ports = %#v, want 443/tcp", second.OpenPorts())
	}
}

func TestParseImportPayloadNormalizesMasscanJSON(t *testing.T) {
	payload := "{\"ip\":\"10.0.0.101\",\"ports\":[{\"port\":443,\"proto\":\"tcp\",\"status\":\"open\"}]}\n{\"ip\":\"10.0.0.102\",\"ports\":[{\"port\":80,\"proto\":\"tcp\",\"status\":\"open\"}]}\n"
	parsed, err := parseImportPayload([]byte(payload), "masscan.jsonl")
	if err != nil {
		t.Fatalf("parseImportPayload() error = %v", err)
	}
	if parsed.Scan.Scanner != "masscan" {
		t.Fatalf("Scanner = %q, want masscan", parsed.Scan.Scanner)
	}
	if len(parsed.Scan.Alive()) != 2 {
		t.Fatalf("Alive hosts = %d, want 2", len(parsed.Scan.Alive()))
	}
	if ports := parsed.Scan.Alive()[0].OpenPorts(); len(ports) == 0 {
		t.Fatalf("first host ports = %#v, want normalized open port", ports)
	}
}

func TestParseImportPayloadNormalizesMasscanText(t *testing.T) {
	payload := "Discovered open port 443/tcp on 10.0.0.111\nopen tcp 80 10.0.0.112 1710000000\n"
	parsed, err := parseImportPayload([]byte(payload), "masscan.txt")
	if err != nil {
		t.Fatalf("parseImportPayload() error = %v", err)
	}
	if parsed.Scan.Scanner != "masscan" {
		t.Fatalf("Scanner = %q, want masscan", parsed.Scan.Scanner)
	}
	if len(parsed.Scan.Alive()) != 2 {
		t.Fatalf("Alive hosts = %d, want 2", len(parsed.Scan.Alive()))
	}
}

func TestParseImportPayloadNormalizesNaabuJSON(t *testing.T) {
	payload := "{\"ip\":\"10.0.0.121\",\"port\":443,\"protocol\":\"tcp\"}\n{\"host\":\"10.0.0.122\",\"port\":8443,\"protocol\":\"tcp\"}\n"
	parsed, err := parseImportPayload([]byte(payload), "naabu.jsonl")
	if err != nil {
		t.Fatalf("parseImportPayload() error = %v", err)
	}
	if parsed.Scan.Scanner != "naabu" {
		t.Fatalf("Scanner = %q, want naabu", parsed.Scan.Scanner)
	}
	if len(parsed.Scan.Alive()) != 2 {
		t.Fatalf("Alive hosts = %d, want 2", len(parsed.Scan.Alive()))
	}
	first := parsed.Scan.Alive()[0]
	if len(first.OpenPorts()) != 1 || first.OpenPorts()[0].Portid != "443" {
		t.Fatalf("first host ports = %#v, want normalized 443/tcp port", first.OpenPorts())
	}
}
