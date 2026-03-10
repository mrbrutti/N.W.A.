package nmap

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleScanXML = `<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -A" start="1710000000" startstr="Mon Mar  1 10:00:00 2026" version="7.95" xmloutputversion="1.05">
  <scaninfo type="syn" protocol="tcp" numservices="2" services="22,80"/>
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
      <portused state="open" proto="tcp" portid="22"/>
      <osmatch name="Linux 6.x" accuracy="98" line="1">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="6.X" accuracy="98">
          <cpe>cpe:/o:linux:linux_kernel:6</cpe>
        </osclass>
      </osmatch>
      <osfingerprint fingerprint="linux fingerprint"/>
    </os>
    <trace port="80" proto="tcp">
      <hop ttl="1" ipaddr="192.168.1.1" rtt="1.20"/>
      <hop ttl="2" ipaddr="10.0.0.5" rtt="2.40" host="alpha.local"/>
    </trace>
    <times srtt="120" rttvar="40" to="100000"/>
  </host>
  <host starttime="1710000003" endtime="1710000004">
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.9" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="http" product="Apache httpd" servicefp="Apache httpd banner" extrainfo="Ubuntu"/>
      </port>
    </ports>
    <distance value="5"/>
    <os>
      <osmatch name="FreeBSD" accuracy="93" line="2">
        <osclass type="general purpose" vendor="FreeBSD" osfamily="FreeBSD" osgen="13.X" accuracy="93"/>
      </osmatch>
    </os>
  </host>
</nmaprun>`

func TestParseFileReadsMetadataAndDistance(t *testing.T) {
	path := writeTempScan(t)

	scan, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile() error = %v", err)
	}

	if scan.Scanner != "nmap" {
		t.Fatalf("Scanner = %q, want nmap", scan.Scanner)
	}
	if scan.Startstr != "Mon Mar  1 10:00:00 2026" {
		t.Fatalf("Startstr = %q", scan.Startstr)
	}
	if len(scan.Alive()) != 2 {
		t.Fatalf("Alive() returned %d hosts, want 2", len(scan.Alive()))
	}
	if scan.Alive()[0].Distance != "3" {
		t.Fatalf("Distance = %q, want 3", scan.Alive()[0].Distance)
	}
}

func TestOSGuessReturnsSingleMatch(t *testing.T) {
	path := writeTempScan(t)
	scan, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile() error = %v", err)
	}

	guess := scan.Alive()[0].OSGuess()
	if guess != "Linux 6.x" {
		t.Fatalf("OSGuess() = %q, want Linux 6.x", guess)
	}
}

func TestWithBannerDoesNotDuplicateHost(t *testing.T) {
	path := writeTempScan(t)
	scan, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile() error = %v", err)
	}

	matches := scan.WithBanner("apache")
	if len(matches) != 1 {
		t.Fatalf("WithBanner() returned %d hosts, want 1", len(matches))
	}
	if matches[0].Address.Addr != "10.0.0.9" {
		t.Fatalf("WithBanner() returned %q", matches[0].Address.Addr)
	}
}

func TestParseBytesRecoversCompleteHostsFromTruncatedXML(t *testing.T) {
	truncated := sampleScanXML
	cut := strings.Index(truncated, `<host starttime="1710000003"`)
	if cut <= 0 {
		t.Fatal("failed to build truncated fixture")
	}
	truncated = truncated[:cut] + `<host starttime="1710000003"><status state="up"`

	scan, err := ParseBytes([]byte(truncated))
	if err == nil {
		t.Fatal("ParseBytes() error = nil, want partial parse warning")
	}

	var partial *PartialParseError
	if !errors.As(err, &partial) {
		t.Fatalf("ParseBytes() error = %T, want PartialParseError", err)
	}
	if partial.RecoveredHosts != 1 {
		t.Fatalf("RecoveredHosts = %d, want 1", partial.RecoveredHosts)
	}
	if len(scan.Alive()) != 1 {
		t.Fatalf("Alive() = %d, want 1 recovered host", len(scan.Alive()))
	}
	if scan.Alive()[0].Address.Addr != "10.0.0.5" {
		t.Fatalf("recovered host = %q, want 10.0.0.5", scan.Alive()[0].Address.Addr)
	}
	if scan.Scanner != "nmap" {
		t.Fatalf("Scanner = %q, want recovered root metadata", scan.Scanner)
	}
}

func writeTempScan(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "scan.xml")
	if err := os.WriteFile(path, []byte(sampleScanXML), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}
