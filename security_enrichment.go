package main

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"nwa/nmap"
)

var canonicalVersionPattern = regexp.MustCompile(`\d+(?:\.\d+)*[a-z]?`)

type versionComponent struct {
	number int
	suffix string
}

func cpeValues(values []nmap.Cpe) []string {
	if len(values) == 0 {
		return nil
	}

	results := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value.Value)
		if trimmed == "" {
			continue
		}
		results = append(results, trimmed)
	}
	if len(results) == 0 {
		return nil
	}
	return results
}

func buildRecommendations(coverage CoverageView, findings FindingSummary, ports []PortRow, hasHTTPTargets bool) []RecommendationView {
	items := map[string]RecommendationView{}

	add := func(key string, item RecommendationView) {
		existing, ok := items[key]
		if !ok {
			items[key] = item
			return
		}
		existing.Evidence = mergeInsightEvidence(existing.Evidence, item.Evidence)
		if recommendationToneWeight(item.Tone) > recommendationToneWeight(existing.Tone) {
			existing.Tone = item.Tone
		}
		items[key] = existing
	}

	if coverage.NeedsEnrichment {
		add("nmap-enrich", RecommendationView{
			Title:    "Run managed nmap enrichment",
			Detail:   "Capture scripts, OS detection, and traceroute so host review is not limited to the base service surface.",
			Evidence: coverage.Detail,
			Tone:     "accent",
		})
	}

	if hasHTTPTargets {
		detail := "Run nuclei against the mapped web surface to validate exposed HTTP endpoints and attach findings back to the host."
		if findings.Total > 0 {
			detail = "Re-run or expand nuclei coverage after service changes so current HTTP findings stay aligned with the mapped web surface."
		}
		add("nuclei-http", RecommendationView{
			Title:    "Validate mapped web services with nuclei",
			Detail:   detail,
			Evidence: "HTTP-like services were identified on this host.",
			Tone:     "warning",
		})
	}

	for _, port := range ports {
		if port.State != "open" {
			continue
		}

		switch {
		case port.Port == "21" || portHasAny(port, " ftp ", "vsftpd", "proftpd", "pure-ftpd"):
			add("ftp", RecommendationView{
				Title:    "Retire or harden FTP exposure",
				Detail:   "Treat FTP as a cleartext file-transfer surface unless FTPS is explicitly configured. Prefer SFTP/FTPS and verify anonymous access is disabled.",
				Evidence: portEvidence(port),
				Tone:     "warning",
			})
		case port.Port == "23" || portHasAny(port, " telnet "):
			add("telnet", RecommendationView{
				Title:    "Remove Telnet from reachable paths",
				Detail:   "Telnet exposes credentials and session traffic in cleartext. Replace it with SSH and restrict legacy administration paths.",
				Evidence: portEvidence(port),
				Tone:     "risk",
			})
		case port.Port == "25" || portHasAny(port, " smtp ", "exim", "postfix", "sendmail"):
			add("smtp", RecommendationView{
				Title:    "Validate exposed mail service",
				Detail:   "Check relay behavior, enforce TLS, review legacy auth paths, and confirm the MTA is patched before leaving SMTP reachable.",
				Evidence: portEvidence(port),
				Tone:     "warning",
			})
		case port.Port == "53" || portHasAny(port, " dns ", "domain", "bind"):
			add("dns", RecommendationView{
				Title:    "Constrain DNS recursion and transfer scope",
				Detail:   "Public DNS services should limit recursion to trusted clients and block unauthorized zone transfers.",
				Evidence: portEvidence(port),
				Tone:     "warning",
			})
		case port.Port == "111" || portHasAny(port, "rpcbind", "portmap"):
			add("rpcbind", RecommendationView{
				Title:    "Treat RPC exposure as an NFS pivot",
				Detail:   "rpcbind often signals additional RPC/NFS attack surface. Restrict it to trusted segments and enumerate dependent services.",
				Evidence: portEvidence(port),
				Tone:     "warning",
			})
		case port.Port == "139" || port.Port == "445" || portHasAny(port, "microsoft-ds", " netbios ", " samba ", " smb "):
			add("smb", RecommendationView{
				Title:    "Harden exposed SMB services",
				Detail:   "Restrict SMB to trusted networks, disable SMBv1, require signing where supported, and review guest or null-session exposure.",
				Evidence: portEvidence(port),
				Tone:     "risk",
			})
		case port.Port == "2049" || portHasAny(port, " nfs "):
			add("nfs", RecommendationView{
				Title:    "Audit NFS export boundaries",
				Detail:   "Review export lists, root_squash behavior, and network restrictions before leaving NFS reachable outside trusted segments.",
				Evidence: portEvidence(port),
				Tone:     "risk",
			})
		case port.Port == "2375" || portHasAny(port, "docker"):
			add("docker", RecommendationView{
				Title:    "Close unauthenticated Docker API exposure",
				Detail:   "Plain Docker API access on 2375 is typically high risk. Bind it to localhost or a protected network and require TLS on remote control paths.",
				Evidence: portEvidence(port),
				Tone:     "risk",
			})
		case port.Port == "3306" || portHasAny(port, " mysql "):
			add("mysql", RecommendationView{
				Title:    "Restrict direct MySQL reachability",
				Detail:   "Keep database listeners on private networks, require strong authentication, and prefer TLS for any remote administrative access.",
				Evidence: portEvidence(port),
				Tone:     "warning",
			})
		case port.Port == "3389" || portHasAny(port, "rdp", "remote desktop", "ms-wbt-server"):
			add("rdp", RecommendationView{
				Title:    "Gate RDP behind stronger controls",
				Detail:   "Require NLA, MFA and preferably VPN or jump-host access before leaving RDP reachable from broad networks.",
				Evidence: portEvidence(port),
				Tone:     "risk",
			})
		case port.Port == "5432" || portHasAny(port, " postgres ", "postgresql"):
			add("postgres", RecommendationView{
				Title:    "Constrain PostgreSQL exposure",
				Detail:   "Restrict `pg_hba.conf` scope, require strong auth, and avoid exposing PostgreSQL directly to untrusted networks.",
				Evidence: portEvidence(port),
				Tone:     "warning",
			})
		case port.Port == "5900" || portHasAny(port, " vnc "):
			add("vnc", RecommendationView{
				Title:    "Tunnel or restrict VNC access",
				Detail:   "VNC frequently lacks strong transport protection. Prefer SSH or VPN tunneling and keep the listener off broad network edges.",
				Evidence: portEvidence(port),
				Tone:     "risk",
			})
		case port.Port == "6379" || portHasAny(port, " redis "):
			add("redis", RecommendationView{
				Title:    "Keep Redis on private interfaces",
				Detail:   "Enable protected mode, require authentication or ACLs, and avoid exposing Redis directly to shared or public networks.",
				Evidence: portEvidence(port),
				Tone:     "risk",
			})
		case port.Port == "9200" || portHasAny(port, " elasticsearch "):
			add("elasticsearch", RecommendationView{
				Title:    "Require auth and TLS for Elasticsearch",
				Detail:   "Unauthenticated Elasticsearch exposure often leaks data and cluster metadata. Keep it behind auth, TLS, and network restrictions.",
				Evidence: portEvidence(port),
				Tone:     "risk",
			})
		case port.Port == "1433" || portHasAny(port, "mssql", "ms-sql", "sql server"):
			add("mssql", RecommendationView{
				Title:    "Restrict SQL Server ingress",
				Detail:   "Keep SQL Server listeners on trusted networks, review legacy protocol support, and require strong auth for administrative paths.",
				Evidence: portEvidence(port),
				Tone:     "warning",
			})
		}
	}

	results := make([]RecommendationView, 0, len(items))
	for _, item := range items {
		results = append(results, item)
	}
	sort.SliceStable(results, func(left, right int) bool {
		if recommendationToneWeight(results[left].Tone) != recommendationToneWeight(results[right].Tone) {
			return recommendationToneWeight(results[left].Tone) > recommendationToneWeight(results[right].Tone)
		}
		return results[left].Title < results[right].Title
	})
	return results
}

func buildKnownVulnerabilities(ports []PortRow) []VulnerabilityMatchView {
	items := map[string]VulnerabilityMatchView{}

	add := func(item VulnerabilityMatchView) {
		existing, ok := items[item.ID]
		if !ok {
			items[item.ID] = item
			return
		}
		existing.Evidence = mergeInsightEvidence(existing.Evidence, item.Evidence)
		items[item.ID] = existing
	}

	for _, port := range ports {
		if port.State != "open" {
			continue
		}

		switch {
		case portHasAny(port, "apache httpd", "apache http server", "apache:http_server") && portVersionExact(port, "2.4.49"):
			add(VulnerabilityMatchView{
				ID:             "CVE-2021-41773",
				Title:          "Apache HTTP Server path traversal",
				Severity:       "critical",
				SeverityTone:   severityTone("critical"),
				Detail:         "Apache HTTP Server 2.4.49 is affected by a path traversal issue that can lead to file disclosure and, in some configurations, remote code execution.",
				Evidence:       portEvidence(port),
				Recommendation: "Upgrade Apache HTTP Server beyond 2.4.49 and review CGI plus filesystem access controls on this vhost.",
				ReferenceURL:   "https://httpd.apache.org/security/vulnerabilities_24.html",
			})
		case portHasAny(port, "apache httpd", "apache http server", "apache:http_server") && portVersionExact(port, "2.4.50"):
			add(VulnerabilityMatchView{
				ID:             "CVE-2021-42013",
				Title:          "Apache HTTP Server incomplete traversal fix",
				Severity:       "critical",
				SeverityTone:   severityTone("critical"),
				Detail:         "Apache HTTP Server 2.4.50 carries the incomplete fix for the 2.4.49 traversal issue and can still permit traversal and remote code execution in some configurations.",
				Evidence:       portEvidence(port),
				Recommendation: "Upgrade Apache HTTP Server beyond 2.4.50 and review CGI plus filesystem access controls on this vhost.",
				ReferenceURL:   "https://httpd.apache.org/security/vulnerabilities_24.html",
			})
		case portHasAny(port, "exim") && portVersionBetween(port, "4.87", "4.91"):
			add(VulnerabilityMatchView{
				ID:             "CVE-2019-10149",
				Title:          "Exim remote command execution exposure",
				Severity:       "critical",
				SeverityTone:   severityTone("critical"),
				Detail:         "Exim 4.87 through 4.91 includes the Return of the WIZard vulnerability, a high-signal remote command execution issue on reachable mail servers.",
				Evidence:       portEvidence(port),
				Recommendation: "Upgrade Exim to 4.92 or later, then review message-routing paths and any internet-facing SMTP exposure.",
				ReferenceURL:   "https://nvd.nist.gov/vuln/detail/CVE-2019-10149",
			})
		case portHasAny(port, "vsftpd", "vsftpd_project:vsftpd") && portVersionExact(port, "2.3.4"):
			add(VulnerabilityMatchView{
				ID:             "CVE-2011-2523",
				Title:          "vsftpd 2.3.4 backdoored release",
				Severity:       "critical",
				SeverityTone:   severityTone("critical"),
				Detail:         "vsftpd 2.3.4 matches the compromised release associated with the backdoor that opens a shell on TCP 6200.",
				Evidence:       portEvidence(port),
				Recommendation: "Verify package provenance immediately, replace the service with a trusted build, and treat the host as potentially compromised until validated.",
				ReferenceURL:   "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
			})
		case portHasAny(port, "openssl", "openssl:openssl") && portVersionBetween(port, "1.0.1", "1.0.1f"):
			add(VulnerabilityMatchView{
				ID:             "CVE-2014-0160",
				Title:          "OpenSSL Heartbleed-era library",
				Severity:       "high",
				SeverityTone:   severityTone("high"),
				Detail:         "OpenSSL 1.0.1 through 1.0.1f is affected by Heartbleed, which can expose process memory, credentials, and potentially private key material.",
				Evidence:       portEvidence(port),
				Recommendation: "Upgrade to OpenSSL 1.0.1g or later, rotate keys and certificates after remediation, and invalidate affected credentials.",
				ReferenceURL:   "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
			})
		}
	}

	results := make([]VulnerabilityMatchView, 0, len(items))
	for _, item := range items {
		results = append(results, item)
	}
	sort.SliceStable(results, func(left, right int) bool {
		if severityWeight(results[left].Severity) != severityWeight(results[right].Severity) {
			return severityWeight(results[left].Severity) > severityWeight(results[right].Severity)
		}
		return results[left].ID < results[right].ID
	})
	return results
}

func recommendationToneWeight(tone string) int {
	switch strings.ToLower(strings.TrimSpace(tone)) {
	case "risk":
		return 4
	case "warning":
		return 3
	case "accent":
		return 2
	case "ok":
		return 1
	default:
		return 0
	}
}

func mergeInsightEvidence(existing string, incoming string) string {
	existing = strings.TrimSpace(existing)
	incoming = strings.TrimSpace(incoming)
	switch {
	case existing == "":
		return incoming
	case incoming == "":
		return existing
	case existing == incoming:
		return existing
	default:
		return strings.Join(uniqueStrings([]string{existing, incoming}), "; ")
	}
}

func portHasAny(port PortRow, needles ...string) bool {
	blob := portSearchBlob(port)
	for _, needle := range needles {
		needle = strings.ToLower(strings.TrimSpace(needle))
		if needle == "" {
			continue
		}
		if containsSearchToken(blob, needle) {
			return true
		}
	}
	return false
}

func containsSearchToken(blob string, needle string) bool {
	pattern := `(^|[^a-z0-9])` + regexp.QuoteMeta(needle) + `([^a-z0-9]|$)`
	return regexp.MustCompile(pattern).MatchString(blob)
}

func portSearchBlob(port PortRow) string {
	parts := []string{
		port.Port,
		port.Protocol,
		port.Service,
		port.Product,
		port.Version,
		port.ExtraInfo,
		port.OSType,
		port.Fingerprint,
	}
	parts = append(parts, port.CPEs...)
	return normalizeSearchTerms(parts)
}

func portEvidence(port PortRow) string {
	parts := []string{fmt.Sprintf("%s/%s", chooseString(port.Port, "?"), chooseString(port.Protocol, "tcp"))}
	if service := strings.TrimSpace(port.Service); service != "" {
		parts = append(parts, service)
	}
	if software := portSoftwareLabel(port); software != "" {
		if last := parts[len(parts)-1]; !strings.EqualFold(last, software) {
			parts = append(parts, software)
		}
	}
	return strings.Join(parts, " · ")
}

func portSoftwareLabel(port PortRow) string {
	parts := make([]string, 0, 3)
	if product := strings.TrimSpace(port.Product); product != "" {
		parts = append(parts, product)
	}
	if version := strings.TrimSpace(port.Version); version != "" {
		parts = append(parts, version)
	}
	if extra := strings.TrimSpace(port.ExtraInfo); extra != "" {
		parts = append(parts, extra)
	}
	return strings.Join(parts, " ")
}

func portVersionExact(port PortRow, target string) bool {
	for _, candidate := range portVersionCandidates(port) {
		if compareVersionStrings(candidate, target) == 0 {
			return true
		}
	}
	return false
}

func portVersionBetween(port PortRow, minimum string, maximum string) bool {
	for _, candidate := range portVersionCandidates(port) {
		if compareVersionStrings(candidate, minimum) >= 0 && compareVersionStrings(candidate, maximum) <= 0 {
			return true
		}
	}
	return false
}

func portVersionCandidates(port PortRow) []string {
	candidates := make([]string, 0, len(port.CPEs)+1)
	if version := canonicalVersion(strings.TrimSpace(port.Version)); version != "" {
		candidates = append(candidates, version)
	}
	for _, cpe := range port.CPEs {
		if version := cpeVersion(cpe); version != "" {
			candidates = append(candidates, version)
		}
	}
	return uniqueStrings(candidates)
}

func cpeVersion(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	switch {
	case strings.HasPrefix(raw, "cpe:2.3:"):
		parts := strings.Split(raw, ":")
		if len(parts) > 5 {
			return canonicalVersion(parts[5])
		}
	case strings.HasPrefix(raw, "cpe:/"):
		parts := strings.Split(raw, ":")
		if len(parts) > 4 {
			return canonicalVersion(parts[4])
		}
	}
	return ""
}

func canonicalVersion(raw string) string {
	return strings.ToLower(strings.TrimSpace(canonicalVersionPattern.FindString(strings.TrimSpace(raw))))
}

func compareVersionStrings(left string, right string) int {
	leftParts, ok := parseComparableVersion(left)
	if !ok {
		return strings.Compare(strings.ToLower(strings.TrimSpace(left)), strings.ToLower(strings.TrimSpace(right)))
	}
	rightParts, ok := parseComparableVersion(right)
	if !ok {
		return strings.Compare(strings.ToLower(strings.TrimSpace(left)), strings.ToLower(strings.TrimSpace(right)))
	}
	return compareComparableVersions(leftParts, rightParts)
}

func parseComparableVersion(raw string) ([]versionComponent, bool) {
	token := canonicalVersion(raw)
	if token == "" {
		return nil, false
	}

	segments := strings.Split(token, ".")
	parts := make([]versionComponent, 0, len(segments))
	for _, segment := range segments {
		index := 0
		for index < len(segment) && segment[index] >= '0' && segment[index] <= '9' {
			index++
		}
		if index == 0 {
			return nil, false
		}

		number, err := strconv.Atoi(segment[:index])
		if err != nil {
			return nil, false
		}
		parts = append(parts, versionComponent{
			number: number,
			suffix: segment[index:],
		})
	}
	return parts, true
}

func compareComparableVersions(left []versionComponent, right []versionComponent) int {
	limit := maxInt(len(left), len(right))
	for index := 0; index < limit; index++ {
		leftPart := versionComponent{}
		rightPart := versionComponent{}
		if index < len(left) {
			leftPart = left[index]
		}
		if index < len(right) {
			rightPart = right[index]
		}

		switch {
		case leftPart.number < rightPart.number:
			return -1
		case leftPart.number > rightPart.number:
			return 1
		}

		switch compareVersionSuffix(leftPart.suffix, rightPart.suffix) {
		case -1:
			return -1
		case 1:
			return 1
		}
	}
	return 0
}

func compareVersionSuffix(left string, right string) int {
	switch {
	case left == right:
		return 0
	case left == "":
		return -1
	case right == "":
		return 1
	case left < right:
		return -1
	default:
		return 1
	}
}
