package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"nwa/nmap"
)

type zmapObservation struct {
	Address  string
	Port     string
	Protocol string
	Success  bool
}

func parseZMapCSVImport(payload []byte, fileExt string) (parsedImport, error) {
	reader := csv.NewReader(bytes.NewReader(payload))
	header, err := reader.Read()
	if err != nil {
		return parsedImport{}, err
	}

	indexByName := map[string]int{}
	for index, name := range header {
		indexByName[strings.ToLower(strings.TrimSpace(name))] = index
	}
	if ipColumnIndex(indexByName) < 0 {
		return parsedImport{}, errors.New("zmap csv is missing an address column")
	}

	observations := make([]zmapObservation, 0)
	for {
		record, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return parsedImport{}, err
		}
		observation := zmapObservation{
			Address:  csvValue(record, indexByName, "saddr", "ip", "addr", "host"),
			Port:     csvValue(record, indexByName, "port", "sport", "dport"),
			Protocol: csvValue(record, indexByName, "proto", "protocol"),
			Success:  csvSuccess(record, indexByName),
		}
		observations = append(observations, observation)
	}

	return buildZMapImport(observations, fileExt)
}

func parseZMapJSONImport(payload []byte, fileExt string) (parsedImport, error) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return parsedImport{}, errors.New("zmap payload is empty")
	}

	observations := make([]zmapObservation, 0)
	if trimmed[0] == '[' {
		var rows []map[string]any
		if err := json.Unmarshal(trimmed, &rows); err != nil {
			return parsedImport{}, err
		}
		for _, row := range rows {
			observations = append(observations, jsonObservation(row))
		}
	} else {
		decoder := json.NewDecoder(bytes.NewReader(trimmed))
		for {
			var row map[string]any
			if err := decoder.Decode(&row); err != nil {
				if err == io.EOF {
					break
				}
				return parsedImport{}, err
			}
			observations = append(observations, jsonObservation(row))
		}
	}

	return buildZMapImport(observations, fileExt)
}

func parseZMapTextImport(payload []byte, fileExt string) (parsedImport, error) {
	lines := strings.Split(strings.ReplaceAll(string(payload), "\r\n", "\n"), "\n")
	observations := make([]zmapObservation, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		address := strings.TrimSpace(fields[0])
		if addrTypeForValue(address) == "" {
			continue
		}

		observation := zmapObservation{
			Address: address,
			Success: true,
		}
		if len(fields) > 1 {
			observation.Port = strings.TrimSpace(fields[1])
		}
		if len(fields) > 2 {
			observation.Protocol = strings.TrimSpace(fields[2])
		}
		observations = append(observations, observation)
	}

	return buildZMapImport(observations, fileExt)
}

func buildZMapImport(observations []zmapObservation, fileExt string) (parsedImport, error) {
	return buildPortObservationImport("zmap", "zmap", "zmap import", observations, fileExt)
}

func buildPortObservationImport(scanner string, reason string, args string, observations []zmapObservation, fileExt string) (parsedImport, error) {
	hostMap := map[string]*nmap.Host{}
	protocols := map[string]struct{}{}
	for _, observation := range observations {
		if !observation.Success {
			continue
		}
		address := strings.TrimSpace(observation.Address)
		if addrTypeForValue(address) == "" {
			continue
		}
		host := hostMap[address]
		if host == nil {
			host = &nmap.Host{
				Status: nmap.Status{
					State:  "up",
					Reason: reason,
				},
				Address: nmap.Address{
					Addr:     address,
					AddrType: addrTypeForValue(address),
				},
			}
			hostMap[address] = host
		}

		port := strings.TrimSpace(observation.Port)
		protocol := strings.ToLower(strings.TrimSpace(observation.Protocol))
		if protocol == "" {
			protocol = "tcp"
		}
		if port == "" {
			continue
		}
		protocols[protocol] = struct{}{}
		key := protocol + "/" + port
		duplicate := false
		for _, existing := range host.Ports {
			if existing.Protocol+"/"+existing.Portid == key {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		host.Ports = append(host.Ports, nmap.Port{
			Protocol: protocol,
			Portid:   port,
			State: nmap.State{
				State:  "open",
				Reason: reason,
			},
			Service: nmap.Service{
				Name: inferServiceName(port, protocol),
			},
		})
	}

	if len(hostMap) == 0 {
		return parsedImport{}, fmt.Errorf("zmap import contained no live hosts")
	}

	addresses := make([]string, 0, len(hostMap))
	for address := range hostMap {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)

	hosts := make([]nmap.Host, 0, len(addresses))
	for _, address := range addresses {
		hosts = append(hosts, *hostMap[address])
	}

	scan := nmap.Scan{
		Scanner: scanner,
		Args:    args,
		ScanInfo: nmap.ScanInfo{
			Type:     "discovery",
			Protocol: "mixed",
		},
		Hosts: hosts,
	}
	if len(protocols) == 1 {
		for protocol := range protocols {
			scan.ScanInfo.Protocol = protocol
		}
	}

	return parsedImport{
		Scan:    scan,
		FileExt: fileExt,
	}, nil
}

func ipColumnIndex(indexByName map[string]int) int {
	for _, candidate := range []string{"saddr", "ip", "addr", "host"} {
		if index, ok := indexByName[candidate]; ok {
			return index
		}
	}
	return -1
}

func csvValue(record []string, indexByName map[string]int, names ...string) string {
	for _, name := range names {
		index, ok := indexByName[name]
		if !ok || index < 0 || index >= len(record) {
			continue
		}
		value := strings.TrimSpace(record[index])
		if value != "" {
			return value
		}
	}
	return ""
}

func csvSuccess(record []string, indexByName map[string]int) bool {
	success := csvValue(record, indexByName, "success")
	if success != "" {
		return parseTruthy(success)
	}

	classification := strings.ToLower(csvValue(record, indexByName, "classification", "status"))
	if classification == "" {
		return true
	}
	switch classification {
	case "success", "succeeded", "open", "up", "matched":
		return true
	case "fail", "failed", "closed", "down", "reset", "error", "timeout":
		return false
	default:
		return true
	}
}

func jsonObservation(row map[string]any) zmapObservation {
	return zmapObservation{
		Address: chooseString(
			stringFromAny(row["saddr"]),
			stringFromAny(row["ip"]),
			stringFromAny(row["addr"]),
			stringFromAny(row["host"]),
		),
		Port: chooseString(
			stringFromAny(row["port"]),
			stringFromAny(row["sport"]),
			stringFromAny(row["dport"]),
		),
		Protocol: chooseString(
			stringFromAny(row["proto"]),
			stringFromAny(row["protocol"]),
		),
		Success: jsonSuccess(row),
	}
}

func jsonSuccess(row map[string]any) bool {
	if success, ok := row["success"]; ok {
		return parseTruthy(stringFromAny(success))
	}
	classification := strings.ToLower(chooseString(
		stringFromAny(row["classification"]),
		stringFromAny(row["status"]),
	))
	if classification == "" {
		return true
	}
	switch classification {
	case "success", "succeeded", "open", "up", "matched":
		return true
	case "fail", "failed", "closed", "down", "reset", "error", "timeout":
		return false
	default:
		return true
	}
}

func stringFromAny(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case json.Number:
		return typed.String()
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func parseTruthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "0", "false", "no", "n":
		return false
	default:
		return true
	}
}

func looksLikeJSONImport(payload []byte) bool {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return false
	}
	return trimmed[0] == '{' || trimmed[0] == '['
}

func looksLikeCSVImport(payload []byte) bool {
	lines := bytes.SplitN(payload, []byte{'\n'}, 2)
	if len(lines) == 0 {
		return false
	}
	header := strings.ToLower(strings.TrimSpace(string(lines[0])))
	return strings.Contains(header, ",") && (strings.Contains(header, "saddr") || strings.Contains(header, "ip") || strings.Contains(header, "addr"))
}

func looksLikeLineImport(payload []byte) bool {
	lines := bytes.SplitN(payload, []byte{'\n'}, 4)
	found := 0
	for _, line := range lines {
		value := strings.TrimSpace(string(line))
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		if addrTypeForValue(fields[0]) == "" {
			return false
		}
		found++
	}
	return found > 0
}
