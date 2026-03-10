package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const snapshotFixture = `<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -A" start="1710000000" startstr="Mon Mar  1 10:00:00 2026" version="7.95" xmloutputversion="1.05">
  <scaninfo type="syn" protocol="tcp" numservices="3" services="22,80,443"/>
  <verbose level="1"/>
  <debugging level="0"/>
  <host starttime="1710000001" endtime="1710000002">
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames>
      <hostname name="alpha.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ssh" product="OpenSSH" version="9.0"/>
        <script id="ssh-hostkey" output="ssh-rsa AAAA"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset" reason_ttl="64"/>
        <service name="https"/>
      </port>
    </ports>
    <distance value="3"/>
    <os>
      <osmatch name="Linux 6.x" accuracy="98" line="1">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="6.X" accuracy="98"/>
      </osmatch>
    </os>
  </host>
  <host starttime="1710000003" endtime="1710000004">
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.9" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="http" product="Apache httpd" version="2.4.49" servicefp="Apache banner" extrainfo="Ubuntu">
          <cpe>cpe:/a:apache:http_server:2.4.49</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="25">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="smtp" product="Exim" version="4.90">
          <cpe>cpe:/a:exim:exim:4.90</cpe>
        </service>
      </port>
    </ports>
    <distance value="5"/>
    <os>
      <osmatch name="FreeBSD" accuracy="93" line="2">
        <osclass type="general purpose" vendor="FreeBSD" osfamily="FreeBSD" osgen="13.X" accuracy="93"/>
      </osmatch>
    </os>
    <trace port="80" proto="tcp">
      <hop ttl="1" ipaddr="192.168.1.1" rtt="1.20"/>
      <hop ttl="2" ipaddr="10.0.0.9" rtt="2.40" host="mail.local"/>
    </trace>
  </host>
</nmaprun>`

func TestLoadSnapshotBuildsSearchAndBuckets(t *testing.T) {
	path := writeSnapshotFixture(t)

	snapshot, err := loadSnapshot(path)
	if err != nil {
		t.Fatalf("loadSnapshot() error = %v", err)
	}

	if snapshot.meta.LiveHosts != 2 {
		t.Fatalf("LiveHosts = %d, want 2", snapshot.meta.LiveHosts)
	}
	if len(snapshot.portBuckets) == 0 || snapshot.portBuckets[0].Label != "22" && snapshot.portBuckets[0].Label != "25" && snapshot.portBuckets[0].Label != "80" {
		t.Fatalf("unexpected port buckets: %#v", snapshot.portBuckets)
	}

	results := snapshot.searchHosts(HostFilter{Query: "ssh", Scope: "service", Sort: "ip", Page: 1, PageSize: 10})
	if len(results.Items) != 1 {
		t.Fatalf("service search returned %d hosts, want 1", len(results.Items))
	}
	if results.Items[0].IP != "10.0.0.5" {
		t.Fatalf("service search returned %q", results.Items[0].IP)
	}
	if host, ok := snapshot.host("10.0.0.9"); !ok || host.DisplayName != "10.0.0.9" {
		t.Fatalf("host 10.0.0.9 display name = %#v, want IP fallback", host)
	}

	portResults := snapshot.searchHosts(HostFilter{Query: "25", Scope: "port", Sort: "ip", Page: 1, PageSize: 10})
	if len(portResults.Items) != 1 || portResults.Items[0].IP != "10.0.0.9" {
		t.Fatalf("port search returned %#v", portResults.Items)
	}
}

func TestTraceGraphLinksSequentialHops(t *testing.T) {
	path := writeSnapshotFixture(t)

	snapshot, err := loadSnapshot(path)
	if err != nil {
		t.Fatalf("loadSnapshot() error = %v", err)
	}

	graph := snapshot.traceGraph("10.0.0.9")
	if len(graph.Nodes) != 2 {
		t.Fatalf("trace graph nodes = %d, want 2", len(graph.Nodes))
	}
	if len(graph.Links) != 1 {
		t.Fatalf("trace graph links = %d, want 1", len(graph.Links))
	}
	if graph.Links[0].Source != 0 || graph.Links[0].Target != 1 {
		t.Fatalf("unexpected trace link: %#v", graph.Links[0])
	}
}

func TestNucleiTargetsIncludesHTTPServices(t *testing.T) {
	path := writeSnapshotFixture(t)

	snapshot, err := loadSnapshot(path)
	if err != nil {
		t.Fatalf("loadSnapshot() error = %v", err)
	}

	targets := snapshot.nucleiTargets(HostFilter{Page: 1, PageSize: 50})
	if !strings.Contains(targets, "http://10.0.0.9") {
		t.Fatalf("nucleiTargets() = %q, want http target", targets)
	}
}

func TestTopologyGraphAggregatesTraceData(t *testing.T) {
	path := writeSnapshotFixture(t)

	snapshot, err := loadSnapshot(path)
	if err != nil {
		t.Fatalf("loadSnapshot() error = %v", err)
	}

	if snapshot.topology.Summary.TracedHosts != 1 {
		t.Fatalf("TracedHosts = %d, want 1", snapshot.topology.Summary.TracedHosts)
	}
	if snapshot.topology.Summary.Nodes != 2 {
		t.Fatalf("Nodes = %d, want 2", snapshot.topology.Summary.Nodes)
	}
	if snapshot.topology.Summary.Edges != 1 {
		t.Fatalf("Edges = %d, want 1", snapshot.topology.Summary.Edges)
	}

	nodeByID := map[string]TopologyGraphNode{}
	for _, node := range snapshot.topology.Nodes {
		nodeByID[node.ID] = node
	}

	if nodeByID["192.168.1.1"].Icon != "home" || !nodeByID["192.168.1.1"].Source {
		t.Fatalf("source node = %#v, want home source icon", nodeByID["192.168.1.1"])
	}
	if nodeByID["10.0.0.9"].Icon != "linux" {
		t.Fatalf("target node = %#v, want linux icon", nodeByID["10.0.0.9"])
	}
	if nodeByID["10.0.0.9"].Provider != "mail.local" {
		t.Fatalf("target node provider = %q, want mail.local", nodeByID["10.0.0.9"].Provider)
	}
	if len(snapshot.topology.Routes) != 1 {
		t.Fatalf("routes = %d, want 1", len(snapshot.topology.Routes))
	}
	if snapshot.topology.Routes[0].TargetID != "10.0.0.9" {
		t.Fatalf("route target = %q, want 10.0.0.9", snapshot.topology.Routes[0].TargetID)
	}
	if got := strings.Join(snapshot.topology.Routes[0].Hops, ","); got != "192.168.1.1,10.0.0.9" {
		t.Fatalf("route hops = %q, want source to target path", got)
	}
}

func TestHostSecurityEnrichmentAddsRecommendationsAndKnownVulns(t *testing.T) {
	path := writeSnapshotFixture(t)

	snapshot, err := loadSnapshot(path)
	if err != nil {
		t.Fatalf("loadSnapshot() error = %v", err)
	}

	host, ok := snapshot.host("10.0.0.9")
	if !ok {
		t.Fatalf("host 10.0.0.9 not found")
	}

	recommendationTitles := map[string]struct{}{}
	for _, item := range host.Recommendations {
		recommendationTitles[item.Title] = struct{}{}
	}
	for _, title := range []string{
		"Run managed nmap enrichment",
		"Validate mapped web services with nuclei",
		"Validate exposed mail service",
	} {
		if _, ok := recommendationTitles[title]; !ok {
			t.Fatalf("recommendations missing %q: %#v", title, host.Recommendations)
		}
	}

	vulnerabilityIDs := map[string]struct{}{}
	for _, item := range host.Vulnerabilities {
		vulnerabilityIDs[item.ID] = struct{}{}
	}
	for _, id := range []string{"CVE-2021-41773", "CVE-2019-10149"} {
		if _, ok := vulnerabilityIDs[id]; !ok {
			t.Fatalf("vulnerabilities missing %q: %#v", id, host.Vulnerabilities)
		}
	}

	if host.Exposure.Label != "High exposure" {
		t.Fatalf("Exposure.Label = %q, want High exposure", host.Exposure.Label)
	}
	if !strings.Contains(host.Exposure.Detail, "curated vulnerability matches") {
		t.Fatalf("Exposure.Detail = %q, want vulnerability-driven detail", host.Exposure.Detail)
	}
}

func TestBuildKnownVulnerabilitiesMatchesExactAndRangeRules(t *testing.T) {
	matches := buildKnownVulnerabilities([]PortRow{
		{
			Port:     "21",
			Protocol: "tcp",
			State:    "open",
			Service:  "ftp",
			Product:  "vsftpd",
			Version:  "2.3.4",
		},
		{
			Port:     "443",
			Protocol: "tcp",
			State:    "open",
			Service:  "ssl/http",
			Product:  "OpenSSL",
			Version:  "1.0.1f",
		},
	})

	ids := map[string]struct{}{}
	for _, item := range matches {
		ids[item.ID] = struct{}{}
	}
	for _, id := range []string{"CVE-2011-2523", "CVE-2014-0160"} {
		if _, ok := ids[id]; !ok {
			t.Fatalf("known vulnerabilities missing %q: %#v", id, matches)
		}
	}
}

func writeSnapshotFixture(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "scan.xml")
	if err := os.WriteFile(path, []byte(snapshotFixture), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}
