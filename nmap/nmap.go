package nmap

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"strings"
)

type Scan struct {
	NmapRun   NmapRun  `xml:"nmaprun"`
	ScanInfo  ScanInfo `xml:"scaninfo"`
	Verbose   string   `xml:"verbose,attr"`
	Debugging string   `xml:"debugging,attr"`
	Hosts     []Host   `xml:"host"`
}

type NmapRun struct {
	Scanner          string `xml:"scanner,attr"`
	Args             string `xml:"args,attr"`
	Start            string `xml:"start,attr"`
	Startstr         string `xml:"startstr,attr"`
	Version          string `xml:"version,attr"`
	XMLOutputVersion string `xml:"xmloutputversion,attr"`
}

type ScanInfo struct {
	Type        string `xml:"type,attr"`
	protocol    string `xml:"protocol,attr"`
	numservices string `xml:"numservices,attr"`
	services    string `xml:"services,attr"`
}

type Host struct {
	StartTime     string        `xml:"starttime,attr"`
	EndTime       string        `xml:"endtime,attr"`
	Status        Status        `xml:"status"`
	Address       Address       `xml:"address"`
	HostNames     []HostName    `xml:"hostnames>hostname"`
	Ports         []Port        `xml:"ports>port"`
	OS            OS            `xml:"os"`
	Distance      string        `xml:"distance>value,attr"`
	TCPSequence   TCPSequence   `xml:"tcpsequence"`
	IPIDSequence  IPIDSequence  `xml:"ipidsequence"`
	TCPTSSequence TCPTSSequence `xml:"tcptssequence"`
	Trace         Trace         `xml:"trace"`
	Times         Times         `xml:"times"`
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

type HostPorts struct {
	Ports []Port `xml:"port"`
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

// Returns only IPs that are live. 
func (s *Scan) Alive() []Host {
	alive_hosts := []Host{}
	for _, host := range s.Hosts {
		if host.Status.State == "up" {
			alive_hosts = append(alive_hosts, host)
		}
	}
	return alive_hosts
}

// Returns only IPs that are dead. 
func (s *Scan) Dead() []Host {
	alive_hosts := []Host{}
	for _, host := range s.Hosts {
		if host.Status.State == "down" {
			alive_hosts = append(alive_hosts, host)
		}
	}
	return alive_hosts
}

type OpenList struct {
	Name string
	Size int
	Type string
}

func searchport(list []OpenList, port string) int {
	for i, p := range list {
		if p.Name == port {
			return i
		}
	}
	return -1
}

// returns a OpenPorts struct of ports and amount of hosts.
func (s *Scan) OpenPorts() []OpenList {
	open_ports := []OpenList{}
	for _, host := range s.Alive() {
		for _, p := range host.OpenPorts() {
			i := searchport(open_ports, p.Portid)
			if i >= 0 {
				open_ports[i].Size += 1
			} else {
				open_ports = append(open_ports, OpenList{p.Portid, 1, "port"})
			}
		}
	}
	return open_ports
}

func searchos(list []OpenList, os string) int {
	for i, p := range list {
		if p.Name == os {
			return i
		}
	}
	return -1
}

// returns a OpenList struct of OSes and amount of hosts.
func (s *Scan) OSList() []OpenList {
	open_ports := []OpenList{}
	for _, host := range s.Alive() {
		i := searchport(open_ports, host.OSGuess())
		if i >= 0 {
			open_ports[i].Size += 1
		} else {
			open_ports = append(open_ports, OpenList{host.OSGuess(), 1, "os"})
		}
	}
	return open_ports
}

// Return only IPs that have port X open.
func (s *Scan) WithOpenPort(port string) []Host {
	phosts := []Host{}
	for _, h := range s.Alive() {
		for _, p := range h.OpenPorts() {
			if p.Portid == port {
				phosts = append(phosts, h)
			}
		}
	}
	return phosts
}

// Return only IPs that have Service X open.
func (s *Scan) WithService(service string) []Host {
	phosts := []Host{}
	for _, h := range s.Alive() {
		for _, p := range h.OpenPorts() {
			if strings.Contains(p.Service.Name, service) {
				phosts = append(phosts, h)
			}
		}
	}
	return phosts
}

// Return only IPs that have Banner X open.
func (s *Scan) WithBanner(banner string) []Host {
	phosts := []Host{}
	for _, h := range s.Alive() {
		for _, p := range h.OpenPorts() {
			if strings.Contains(p.Service.Product, banner) {
				phosts = append(phosts, h)
			}
			if strings.Contains(p.Service.FingerPrint, banner) {
				phosts = append(phosts, h)
			}
		}
	}
	return phosts
}

// Return only IPs that have Service X open.
func (s *Scan) WithOS(ooss string) []Host {
	phosts := []Host{}
	for _, h := range s.Alive() {
		if strings.Contains(h.OSGuess(), ooss) {
			phosts = append(phosts, h)
		}
	}
	return phosts
}

// Returns list of open ports. 
//
//
func (p *Host) OpenPorts() []Port {
	open_ports := []Port{}
	for _, port := range p.Ports {
		if port.State.State == "open" {
			open_ports = append(open_ports, port)
		}
	}
	return open_ports
}

func (h *Host) OSGuess() string {
	if len(h.OS.OSMatches) > 1 {
		return h.OS.OSMatches[0].Name
	}
	return ""
}

func Parse(scan *Scan, filename string) (Scan, error) {
	nmap, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("error: %v", err)
		return *scan, err
	}

	err = xml.Unmarshal(nmap, &scan)
	if err != nil {
		fmt.Printf("error: %v", err)
		return *scan, err
	}
	return *scan, nil
}
