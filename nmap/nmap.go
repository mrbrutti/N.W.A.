package nmap

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

type Scan struct {
	ScanInfo         ScanInfo
	Verbose          string
	Debugging        string
	Hosts            []Host
	Scanner          string
	Args             string
	Start            string
	Startstr         string
	Version          string
	XMLOutputVersion string
}

type rawScan struct {
	ScanInfo         ScanInfo `xml:"scaninfo"`
	Verbose          levelTag `xml:"verbose"`
	Debugging        levelTag `xml:"debugging"`
	Hosts            []Host   `xml:"host"`
	Scanner          string   `xml:"scanner,attr"`
	Args             string   `xml:"args,attr"`
	Start            string   `xml:"start,attr"`
	Startstr         string   `xml:"startstr,attr"`
	Version          string   `xml:"version,attr"`
	XMLOutputVersion string   `xml:"xmloutputversion,attr"`
}

type levelTag struct {
	Level string `xml:"level,attr"`
}

type ScanInfo struct {
	Type        string `xml:"type,attr"`
	Protocol    string `xml:"protocol,attr"`
	NumServices string `xml:"numservices,attr"`
	Services    string `xml:"services,attr"`
}

type Host struct {
	StartTime     string        `xml:"starttime,attr"`
	EndTime       string        `xml:"endtime,attr"`
	Status        Status        `xml:"status"`
	Address       Address       `xml:"address"`
	HostNames     []HostName    `xml:"hostnames>hostname"`
	Ports         []Port        `xml:"ports>port"`
	OS            OS            `xml:"os"`
	Distance      string        `xml:"-"`
	DistanceValue distanceTag   `xml:"distance"`
	TCPSequence   TCPSequence   `xml:"tcpsequence"`
	IPIDSequence  IPIDSequence  `xml:"ipidsequence"`
	TCPTSSequence TCPTSSequence `xml:"tcptssequence"`
	Trace         Trace         `xml:"trace"`
	Times         Times         `xml:"times"`
}

type distanceTag struct {
	Value string `xml:"value,attr"`
}

type Status struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type HostName struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type Port struct {
	Protocol string   `xml:"protocol,attr"`
	Portid   string   `xml:"portid,attr"`
	State    State    `xml:"state"`
	Service  Service  `xml:"service"`
	Scripts  []Script `xml:"script"`
}

type State struct {
	State      string `xml:"state,attr"`
	Reason     string `xml:"reason,attr"`
	Reason_ttl string `xml:"reason_ttl,attr"`
}

type Service struct {
	Name        string `xml:"name,attr"`
	Product     string `xml:"product,attr"`
	Version     string `xml:"version,attr"`
	FingerPrint string `xml:"servicefp,attr"`
	ExtraInfo   string `xml:"extrainfo,attr"`
	OSType      string `xml:"ostype,attr"`
	Method      string `xml:"method,attr"`
	Conf        string `xml:"conf,attr"`
	CPEs        []Cpe  `xml:"cpe"`
}

type Script struct {
	Id     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type OS struct {
	PortsUsed     []PortUsed    `xml:"portused"`
	OSMatches     []OSMatch     `xml:"osmatch"`
	OSFingerPrint OSFingerPrint `xml:"osfingerprint"`
}

type PortUsed struct {
	State    string `xml:"state,attr"`
	Protocol string `xml:"proto,attr"`
	Portid   string `xml:"portid,attr"`
}

type OSMatch struct {
	Name      string    `xml:"name,attr"`
	Accuracy  string    `xml:"accuracy,attr"`
	Line      string    `xml:"line,attr"`
	OSClasses []OSClass `xml:"osclass"`
}

type OSFingerPrint struct {
	Fingerprint string `xml:"fingerprint,attr"`
}

type OSClass struct {
	Type     string `xml:"type,attr"`
	Vendor   string `xml:"vendor,attr"`
	OSFamily string `xml:"osfamily,attr"`
	OSGen    string `xml:"osgen,attr"`
	Accuracy string `xml:"accuracy,attr"`
	CPEs     []Cpe  `xml:"cpe"`
}

type Cpe struct {
	Value string `xml:",innerxml"`
}

type TCPSequence struct {
	Index      string `xml:"index,attr"`
	Difficulty string `xml:"difficulty,attr"`
	Values     string `xml:"values,attr"`
}

type IPIDSequence struct {
	Class  string `xml:"class,attr"`
	Values string `xml:"values,attr"`
}

type TCPTSSequence struct {
	Class  string `xml:"class,attr"`
	Values string `xml:"values,attr"`
}

type Trace struct {
	Port     string `xml:"port,attr"`
	Protocol string `xml:"proto,attr"`
	Hops     []Hop  `xml:"hop"`
}

type Hop struct {
	Ttl    string `xml:"ttl,attr"`
	Rtt    string `xml:"rtt,attr"`
	IPAddr string `xml:"ipaddr,attr"`
	Host   string `xml:"host,attr"`
}

type Times struct {
	Srtt   string `xml:"srtt,attr"`
	Tttvar string `xml:"rttvar,attr"`
	To     string `xml:"to,attr"`
}

type OpenList struct {
	Name string
	Size int
	Type string
}

type PartialParseError struct {
	Cause          error
	RecoveredHosts int
}

func (e *PartialParseError) Error() string {
	if e == nil {
		return ""
	}
	if e.RecoveredHosts <= 0 {
		return e.Cause.Error()
	}
	return fmt.Sprintf("%v (recovered %d complete hosts)", e.Cause, e.RecoveredHosts)
}

func (e *PartialParseError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (s *Scan) Alive() []Host {
	alive := make([]Host, 0, len(s.Hosts))
	for _, host := range s.Hosts {
		if host.Status.State == "up" {
			alive = append(alive, host)
		}
	}
	return alive
}

func (s *Scan) Dead() []Host {
	dead := make([]Host, 0, len(s.Hosts))
	for _, host := range s.Hosts {
		if host.Status.State == "down" {
			dead = append(dead, host)
		}
	}
	return dead
}

func (s *Scan) OpenPorts() []OpenList {
	counts := map[string]int{}
	for _, host := range s.Alive() {
		for _, port := range host.OpenPorts() {
			counts[port.Portid]++
		}
	}
	return sortedOpenLists(counts, "port")
}

func (s *Scan) OSList() []OpenList {
	counts := map[string]int{}
	for _, host := range s.Alive() {
		if guess := host.OSGuess(); guess != "" {
			counts[guess]++
		}
	}
	return sortedOpenLists(counts, "os")
}

func (s *Scan) WithOpenPort(port string) []Host {
	needle := strings.TrimSpace(strings.ToLower(port))
	if needle == "" {
		return nil
	}

	hosts := make([]Host, 0)
	for _, host := range s.Alive() {
		for _, openPort := range host.OpenPorts() {
			if strings.EqualFold(openPort.Portid, needle) {
				hosts = append(hosts, host)
				break
			}
		}
	}
	return hosts
}

func (s *Scan) WithService(service string) []Host {
	return s.filterOpenPortHosts(service, func(port Port, needle string) bool {
		return containsFold(port.Service.Name, needle)
	})
}

func (s *Scan) WithBanner(banner string) []Host {
	return s.filterOpenPortHosts(banner, func(port Port, needle string) bool {
		return containsFold(port.Service.Product, needle) ||
			containsFold(port.Service.FingerPrint, needle)
	})
}

func (s *Scan) WithOS(query string) []Host {
	needle := strings.TrimSpace(strings.ToLower(query))
	if needle == "" {
		return nil
	}

	matches := make([]Host, 0)
	for _, host := range s.Alive() {
		if containsFold(host.OSGuess(), needle) {
			matches = append(matches, host)
		}
	}
	return matches
}

func (h *Host) OpenPorts() []Port {
	openPorts := make([]Port, 0, len(h.Ports))
	for _, port := range h.Ports {
		if port.State.State == "open" {
			openPorts = append(openPorts, port)
		}
	}
	return openPorts
}

func (h *Host) HostnameLabels() []string {
	labels := make([]string, 0, len(h.HostNames))
	for _, hostName := range h.HostNames {
		name := strings.TrimSpace(hostName.Name)
		if name != "" {
			labels = append(labels, name)
		}
	}
	return labels
}

func (h *Host) PrimaryHostname() string {
	labels := h.HostnameLabels()
	if len(labels) == 0 {
		return ""
	}
	return labels[0]
}

func (h *Host) OSGuess() string {
	if len(h.OS.OSMatches) > 0 {
		return strings.TrimSpace(h.OS.OSMatches[0].Name)
	}
	return ""
}

func Parse(scan *Scan, filename string) (Scan, error) {
	parsed, err := ParseFile(filename)
	if err != nil {
		return *scan, err
	}
	*scan = parsed
	return *scan, nil
}

func ParseFile(filename string) (Scan, error) {
	payload, err := os.ReadFile(filename)
	if err != nil {
		return Scan{}, err
	}

	return ParseBytes(payload)
}

func ParseBytes(payload []byte) (Scan, error) {
	if len(payload) == 0 {
		return Scan{}, nil
	}

	var raw rawScan
	if err := xml.Unmarshal(payload, &raw); err != nil {
		recovered, recoveredHosts := recoverScan(payload)
		if recoveredHosts > 0 {
			return recovered, &PartialParseError{
				Cause:          err,
				RecoveredHosts: recoveredHosts,
			}
		}
		return Scan{}, err
	}

	return finalizeRawScan(raw), nil
}

func finalizeRawScan(raw rawScan) Scan {
	for index := range raw.Hosts {
		raw.Hosts[index].Distance = raw.Hosts[index].DistanceValue.Value
	}

	return Scan{
		ScanInfo:         raw.ScanInfo,
		Verbose:          raw.Verbose.Level,
		Debugging:        raw.Debugging.Level,
		Hosts:            raw.Hosts,
		Scanner:          raw.Scanner,
		Args:             raw.Args,
		Start:            raw.Start,
		Startstr:         raw.Startstr,
		Version:          raw.Version,
		XMLOutputVersion: raw.XMLOutputVersion,
	}
}

func recoverScan(payload []byte) (Scan, int) {
	decoder := xml.NewDecoder(bytes.NewReader(payload))
	scan := Scan{}
	recoveredHosts := 0

	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return scan, recoveredHosts
		}

		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}

		switch start.Name.Local {
		case "nmaprun":
			applyRootAttrs(&scan, start.Attr)
		case "scaninfo":
			scan.ScanInfo = scanInfoFromAttrs(start.Attr)
		case "verbose":
			scan.Verbose = attrValue(start.Attr, "level")
		case "debugging":
			scan.Debugging = attrValue(start.Attr, "level")
		case "host":
			var host Host
			if err := decoder.DecodeElement(&host, &start); err != nil {
				return scan, recoveredHosts
			}
			host.Distance = host.DistanceValue.Value
			scan.Hosts = append(scan.Hosts, host)
			recoveredHosts++
		}
	}

	return scan, recoveredHosts
}

func applyRootAttrs(scan *Scan, attrs []xml.Attr) {
	if scan == nil {
		return
	}
	scan.Scanner = attrValue(attrs, "scanner")
	scan.Args = attrValue(attrs, "args")
	scan.Start = attrValue(attrs, "start")
	scan.Startstr = attrValue(attrs, "startstr")
	scan.Version = attrValue(attrs, "version")
	scan.XMLOutputVersion = attrValue(attrs, "xmloutputversion")
}

func scanInfoFromAttrs(attrs []xml.Attr) ScanInfo {
	return ScanInfo{
		Type:        attrValue(attrs, "type"),
		Protocol:    attrValue(attrs, "protocol"),
		NumServices: attrValue(attrs, "numservices"),
		Services:    attrValue(attrs, "services"),
	}
}

func attrValue(attrs []xml.Attr, key string) string {
	for _, attr := range attrs {
		if attr.Name.Local == key {
			return attr.Value
		}
	}
	return ""
}

func (s *Scan) filterOpenPortHosts(query string, match func(Port, string) bool) []Host {
	needle := strings.TrimSpace(strings.ToLower(query))
	if needle == "" {
		return nil
	}

	matches := make([]Host, 0)
	for _, host := range s.Alive() {
		for _, port := range host.OpenPorts() {
			if match(port, needle) {
				matches = append(matches, host)
				break
			}
		}
	}
	return matches
}

func sortedOpenLists(counts map[string]int, kind string) []OpenList {
	results := make([]OpenList, 0, len(counts))
	for name, size := range counts {
		results = append(results, OpenList{Name: name, Size: size, Type: kind})
	}

	slices.SortStableFunc(results, func(left, right OpenList) int {
		if left.Size != right.Size {
			return right.Size - left.Size
		}
		return strings.Compare(left.Name, right.Name)
	})
	return results
}

func containsFold(value string, needle string) bool {
	return strings.Contains(strings.ToLower(value), needle)
}
