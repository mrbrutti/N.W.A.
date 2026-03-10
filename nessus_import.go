package main

import (
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"nwa/nmap"
)

type nessusClientData struct {
	Reports []nessusReport `xml:"Report"`
}

type nessusReport struct {
	Name  string             `xml:"name,attr"`
	Hosts []nessusReportHost `xml:"ReportHost"`
}

type nessusReportHost struct {
	Name           string             `xml:"name,attr"`
	HostProperties []nessusHostTag    `xml:"HostProperties>tag"`
	Items          []nessusReportItem `xml:"ReportItem"`
}

type nessusHostTag struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

type nessusReportItem struct {
	Port         string   `xml:"port,attr"`
	Service      string   `xml:"svc_name,attr"`
	Protocol     string   `xml:"protocol,attr"`
	Severity     string   `xml:"severity,attr"`
	PluginID     string   `xml:"pluginID,attr"`
	PluginName   string   `xml:"pluginName,attr"`
	PluginFamily string   `xml:"pluginFamily,attr"`
	PluginOutput string   `xml:"plugin_output"`
	Synopsis     string   `xml:"synopsis"`
	Description  string   `xml:"description"`
	Solution     string   `xml:"solution"`
	RiskFactor   string   `xml:"risk_factor"`
	CVEs         []string `xml:"cve"`
	BIDs         []string `xml:"bid"`
	CPEs         []string `xml:"cpe"`
}

func parseNessusCSVImport(payload []byte, fileExt string) (parsedImport, error) {
	reader := csv.NewReader(bytes.NewReader(payload))
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true

	header, err := reader.Read()
	if err != nil {
		return parsedImport{}, err
	}
	indexByName := map[string]int{}
	for index, name := range header {
		indexByName[normalizeNessusCSVHeader(name)] = index
	}
	if !isNessusCSVHeader(indexByName) {
		return parsedImport{}, fmt.Errorf("csv does not look like a nessus export")
	}

	scan := nmap.Scan{
		Scanner: "nessus",
		Args:    "nessus csv import",
		ScanInfo: nmap.ScanInfo{
			Type:     "assessment",
			Protocol: "mixed",
		},
	}
	hostMap := map[string]*nmap.Host{}
	findings := map[string][]storedNucleiFinding{}
	protocols := map[string]struct{}{}

	for {
		record, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return parsedImport{}, err
		}

		hostValue := nessusCSVValue(record, indexByName, "host")
		if strings.TrimSpace(hostValue) == "" {
			continue
		}

		address := strings.TrimSpace(hostValue)
		host := hostMap[address]
		if host == nil {
			host = &nmap.Host{
				Status: nmap.Status{
					State:  "up",
					Reason: "nessus",
				},
				Address: nmap.Address{
					Addr:     address,
					AddrType: addrTypeForValue(address),
				},
			}
			hostMap[address] = host
		}

		port := strings.TrimSpace(nessusCSVValue(record, indexByName, "port"))
		protocol := strings.ToLower(strings.TrimSpace(nessusCSVValue(record, indexByName, "protocol")))
		if protocol == "" {
			protocol = "tcp"
		}
		protocols[protocol] = struct{}{}

		if port != "" && port != "0" {
			key := protocol + "/" + port
			duplicate := false
			for _, existing := range host.Ports {
				if existing.Protocol+"/"+existing.Portid == key {
					duplicate = true
					break
				}
			}
			if !duplicate {
				host.Ports = append(host.Ports, nmap.Port{
					Protocol: protocol,
					Portid:   port,
					State: nmap.State{
						State:  "open",
						Reason: "nessus",
					},
					Service: nmap.Service{
						Name: inferServiceName(port, protocol),
					},
				})
			}
		}

		finding := storedNucleiFinding{
			Source:      "nessus",
			TemplateID:  strings.TrimSpace(nessusCSVValue(record, indexByName, "plugin id")),
			Name:        chooseString(strings.TrimSpace(nessusCSVValue(record, indexByName, "name")), "Nessus finding"),
			Severity:    normalizeNessusSeverity("", nessusCSVValue(record, indexByName, "risk")),
			Target:      nessusFindingTarget(address, port, protocol),
			MatchedAt:   "",
			Type:        chooseString(inferServiceName(port, protocol), strings.TrimSpace(protocol), "nessus"),
			Description: chooseString(strings.TrimSpace(nessusCSVValue(record, indexByName, "plugin output")), strings.TrimSpace(nessusCSVValue(record, indexByName, "synopsis")), strings.TrimSpace(nessusCSVValue(record, indexByName, "description")), strings.TrimSpace(nessusCSVValue(record, indexByName, "solution"))),
			Tags: uniqueStrings(append(
				splitNessusCSVList(nessusCSVValue(record, indexByName, "cve")),
				splitNessusCSVList(nessusCSVValue(record, indexByName, "bid"))...,
			)),
		}
		findings[address] = mergeStoredFindings(findings[address], []storedNucleiFinding{finding})
	}

	if len(hostMap) == 0 {
		return parsedImport{}, fmt.Errorf("nessus csv import contained no hosts")
	}

	scan.Hosts = make([]nmap.Host, 0, len(hostMap))
	for _, host := range hostMap {
		sort.SliceStable(host.Ports, func(left, right int) bool {
			return comparePorts(host.Ports[left].Portid, host.Ports[left].Protocol, host.Ports[right].Portid, host.Ports[right].Protocol)
		})
		scan.Hosts = append(scan.Hosts, *host)
	}
	if len(protocols) == 1 {
		for protocol := range protocols {
			scan.ScanInfo.Protocol = protocol
		}
	}

	return parsedImport{
		Scan:     scan,
		Findings: findings,
		FileExt:  fileExt,
	}, nil
}

func parseNessusImport(payload []byte, fileExt string) (parsedImport, error) {
	var document nessusClientData
	if err := xml.Unmarshal(payload, &document); err != nil {
		return parsedImport{}, err
	}

	scan := nmap.Scan{
		Scanner: "nessus",
		Args:    "nessus import",
		ScanInfo: nmap.ScanInfo{
			Type:     "assessment",
			Protocol: "mixed",
		},
	}
	findings := map[string][]storedNucleiFinding{}
	protocols := map[string]struct{}{}

	for _, report := range document.Reports {
		if strings.TrimSpace(report.Name) != "" {
			scan.Args = report.Name
		}
		for _, reportHost := range report.Hosts {
			host, hostFindings, hostProtocolSet, startedAt := buildNessusHost(reportHost)
			if strings.TrimSpace(startedAt) != "" && strings.TrimSpace(scan.Startstr) == "" {
				scan.Startstr = startedAt
			}
			if strings.TrimSpace(host.Address.Addr) == "" {
				continue
			}
			scan.Hosts = append(scan.Hosts, host)
			for protocol := range hostProtocolSet {
				protocols[protocol] = struct{}{}
			}
			if len(hostFindings) == 0 {
				continue
			}
			findings[host.Address.Addr] = mergeStoredFindings(findings[host.Address.Addr], hostFindings)
		}
	}

	if len(scan.Hosts) == 0 {
		return parsedImport{}, fmt.Errorf("nessus import contained no hosts")
	}

	if len(protocols) == 1 {
		for protocol := range protocols {
			scan.ScanInfo.Protocol = protocol
		}
	}

	return parsedImport{
		Scan:     scan,
		Findings: findings,
		FileExt:  fileExt,
	}, nil
}

func looksLikeNessusCSV(payload []byte) bool {
	reader := csv.NewReader(bytes.NewReader(payload))
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		return false
	}

	indexByName := map[string]int{}
	for index, name := range header {
		indexByName[normalizeNessusCSVHeader(name)] = index
	}
	return isNessusCSVHeader(indexByName)
}

func isNessusCSVHeader(indexByName map[string]int) bool {
	_, hasHost := indexByName["host"]
	_, hasPluginID := indexByName["plugin id"]
	_, hasRisk := indexByName["risk"]
	_, hasName := indexByName["name"]
	_, hasPort := indexByName["port"]
	_, hasProtocol := indexByName["protocol"]
	return hasHost && hasPluginID && hasRisk && hasName && hasPort && hasProtocol
}

func normalizeNessusCSVHeader(value string) string {
	value = strings.TrimSpace(strings.TrimPrefix(value, "\ufeff"))
	value = strings.ToLower(value)
	replacer := strings.NewReplacer("_", " ", "-", " ", "/", " ")
	value = replacer.Replace(value)
	return strings.Join(strings.Fields(value), " ")
}

func nessusCSVValue(record []string, indexByName map[string]int, name string) string {
	index, ok := indexByName[normalizeNessusCSVHeader(name)]
	if !ok || index < 0 || index >= len(record) {
		return ""
	}
	return strings.TrimSpace(record[index])
}

func splitNessusCSVList(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r'
	})
	results := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			results = append(results, field)
		}
	}
	return results
}

func buildNessusHost(reportHost nessusReportHost) (nmap.Host, []storedNucleiFinding, map[string]struct{}, string) {
	tagValues := map[string]string{}
	for _, tag := range reportHost.HostProperties {
		key := strings.ToLower(strings.TrimSpace(tag.Name))
		if key == "" {
			continue
		}
		tagValues[key] = strings.TrimSpace(tag.Value)
	}

	address := chooseString(
		tagValues["host-ip"],
		tagValues["host-ipv6"],
		reportHost.Name,
	)
	host := nmap.Host{
		Status: nmap.Status{
			State:  "up",
			Reason: "nessus",
		},
		Address: nmap.Address{
			Addr:     strings.TrimSpace(address),
			AddrType: addrTypeForValue(address),
		},
	}

	hostNames := uniqueStrings([]string{
		tagValues["host-fqdn"],
		tagValues["hostname"],
		tagValues["netbios-name"],
		tagValues["host-rdns"],
		reportHost.Name,
	})
	for _, hostname := range hostNames {
		if hostname == host.Address.Addr {
			continue
		}
		host.HostNames = append(host.HostNames, nmap.HostName{
			Name: hostname,
			Type: "user",
		})
	}

	if osLabel := chooseString(tagValues["operating-system"], tagValues["operating_system"], tagValues["os"]); osLabel != "" {
		host.OS.OSMatches = []nmap.OSMatch{{
			Name:     osLabel,
			Accuracy: "90",
			OSClasses: []nmap.OSClass{{
				OSFamily: osFamilyForLabel(osLabel),
				Vendor:   osVendorForLabel(osLabel),
				Accuracy: "90",
			}},
		}}
	}

	portMap := map[string]nmap.Port{}
	portOrder := make([]string, 0)
	findings := make([]storedNucleiFinding, 0, len(reportHost.Items))
	protocols := map[string]struct{}{}
	for _, item := range reportHost.Items {
		port := strings.TrimSpace(item.Port)
		protocol := strings.ToLower(strings.TrimSpace(item.Protocol))
		if protocol == "" {
			protocol = "tcp"
		}
		protocols[protocol] = struct{}{}

		if port != "" && port != "0" {
			key := protocol + "/" + port
			current, ok := portMap[key]
			if !ok {
				current = nmap.Port{
					Protocol: protocol,
					Portid:   port,
					State: nmap.State{
						State:  "open",
						Reason: "nessus",
					},
				}
				portOrder = append(portOrder, key)
			}
			current.Service = mergeService(current.Service, nmap.Service{
				Name:      normalizeNessusService(item.Service, port, protocol),
				ExtraInfo: strings.TrimSpace(item.PluginFamily),
			})
			portMap[key] = current
		}

		findings = append(findings, storedNucleiFinding{
			Source:      "nessus",
			TemplateID:  strings.TrimSpace(item.PluginID),
			Name:        chooseString(strings.TrimSpace(item.PluginName), "Nessus finding"),
			Severity:    normalizeNessusSeverity(item.Severity, item.RiskFactor),
			Target:      nessusFindingTarget(host.Address.Addr, port, protocol),
			MatchedAt:   "",
			Type:        chooseString(strings.TrimSpace(item.PluginFamily), normalizeNessusService(item.Service, port, protocol)),
			Description: summarizeNessusDescription(item),
			Tags:        uniqueStrings(append(append([]string(nil), item.CVEs...), append(item.BIDs, item.CPEs...)...)),
		})
	}

	host.Ports = make([]nmap.Port, 0, len(portOrder))
	for _, key := range portOrder {
		host.Ports = append(host.Ports, portMap[key])
	}
	sort.SliceStable(host.Ports, func(left, right int) bool {
		return comparePorts(host.Ports[left].Portid, host.Ports[left].Protocol, host.Ports[right].Portid, host.Ports[right].Protocol)
	})

	return host, mergeStoredFindings(nil, findings), protocols, chooseString(tagValues["host_start"], tagValues["host_start_iso"])
}

func normalizeNessusSeverity(level string, riskFactor string) string {
	switch strings.TrimSpace(level) {
	case "4":
		return "critical"
	case "3":
		return "high"
	case "2":
		return "medium"
	case "1":
		return "low"
	case "0":
		return "info"
	}
	return normalizeSeverity(riskFactor)
}

func summarizeNessusDescription(item nessusReportItem) string {
	return chooseString(
		strings.TrimSpace(item.PluginOutput),
		strings.TrimSpace(item.Synopsis),
		strings.TrimSpace(item.Description),
		strings.TrimSpace(item.Solution),
	)
}

func normalizeNessusService(service string, port string, protocol string) string {
	service = strings.TrimSpace(service)
	switch strings.ToLower(service) {
	case "", "unknown":
		return inferServiceName(port, protocol)
	case "www":
		return "http"
	default:
		return service
	}
}

func nessusFindingTarget(host string, port string, protocol string) string {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if host == "" {
		return ""
	}
	if port == "" || port == "0" {
		return host
	}
	if protocol == "" {
		protocol = "tcp"
	}
	return netJoinHostPort(host, port) + "/" + protocol
}

func inferServiceName(port string, protocol string) string {
	if label, ok := criticalPorts[port]; ok {
		return label
	}
	switch strings.TrimSpace(port) {
	case "443":
		return "https"
	case "53":
		return "dns"
	default:
		if strings.EqualFold(protocol, "udp") && port == "161" {
			return "snmp"
		}
	}
	return ""
}

func netJoinHostPort(host string, port string) string {
	if parsed, err := netip.ParseAddr(host); err == nil && parsed.Is6() {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

func addrTypeForValue(value string) string {
	parsed, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return ""
	}
	if parsed.Is6() {
		return "ipv6"
	}
	return "ipv4"
}

func osFamilyForLabel(label string) string {
	lower := strings.ToLower(strings.TrimSpace(label))
	switch {
	case strings.Contains(lower, "windows"):
		return "Windows"
	case strings.Contains(lower, "linux"):
		return "Linux"
	case strings.Contains(lower, "mac"), strings.Contains(lower, "darwin"):
		return "Mac OS"
	case strings.Contains(lower, "cisco"):
		return "Cisco"
	default:
		return ""
	}
}

func osVendorForLabel(label string) string {
	lower := strings.ToLower(strings.TrimSpace(label))
	switch {
	case strings.Contains(lower, "windows"):
		return "Microsoft"
	case strings.Contains(lower, "linux"):
		return "Linux"
	case strings.Contains(lower, "mac"), strings.Contains(lower, "darwin"):
		return "Apple"
	case strings.Contains(lower, "cisco"):
		return "Cisco"
	default:
		return ""
	}
}

func parseNessusPort(value string) int {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0
	}
	return port
}
