package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

func parseMasscanJSONImport(payload []byte, fileExt string) (parsedImport, error) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return parsedImport{}, errors.New("masscan payload is empty")
	}

	observations := make([]zmapObservation, 0)
	appendEntry := func(row map[string]any) {
		ip := strings.TrimSpace(stringField(row["ip"]))
		if ip == "" {
			return
		}
		ports, ok := row["ports"].([]any)
		if !ok {
			return
		}
		for _, item := range ports {
			portRow, ok := item.(map[string]any)
			if !ok {
				continue
			}
			observations = append(observations, zmapObservation{
				Address:  ip,
				Port:     stringField(portRow["port"]),
				Protocol: chooseString(stringField(portRow["proto"]), stringField(portRow["protocol"])),
				Success:  strings.EqualFold(chooseString(stringField(portRow["status"]), "open"), "open"),
			})
		}
	}

	if trimmed[0] == '[' {
		var rows []map[string]any
		if err := json.Unmarshal(trimmed, &rows); err != nil {
			return parsedImport{}, err
		}
		for _, row := range rows {
			appendEntry(row)
		}
	} else {
		lines := strings.Split(strings.ReplaceAll(string(trimmed), "\r\n", "\n"), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(line), ","), ","))
			if line == "" || line == "[" || line == "]" {
				continue
			}
			var row map[string]any
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				return parsedImport{}, err
			}
			appendEntry(row)
		}
	}

	return buildPortObservationImport("masscan", "masscan", "masscan import", observations, fileExt)
}

func parseMasscanTextImport(payload []byte, fileExt string) (parsedImport, error) {
	lines := strings.Split(strings.ReplaceAll(string(payload), "\r\n", "\n"), "\n")
	observations := make([]zmapObservation, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "discovered open port "):
			remainder := strings.TrimSpace(line[len("Discovered open port "):])
			parts := strings.Fields(remainder)
			if len(parts) < 3 {
				continue
			}
			portProto := strings.SplitN(strings.TrimSpace(parts[0]), "/", 2)
			if len(portProto) != 2 {
				continue
			}
			address := strings.TrimSpace(parts[2])
			observations = append(observations, zmapObservation{
				Address:  address,
				Port:     strings.TrimSpace(portProto[0]),
				Protocol: strings.TrimSpace(portProto[1]),
				Success:  true,
			})
		case strings.HasPrefix(lower, "open "):
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			observations = append(observations, zmapObservation{
				Protocol: strings.TrimSpace(fields[1]),
				Port:     strings.TrimSpace(fields[2]),
				Address:  strings.TrimSpace(fields[3]),
				Success:  true,
			})
		}
	}
	return buildPortObservationImport("masscan", "masscan", "masscan import", observations, fileExt)
}

func looksLikeMasscanJSON(payload []byte) bool {
	sample := strings.ToLower(string(payload))
	return strings.Contains(sample, "\"ip\"") && strings.Contains(sample, "\"ports\"")
}

func looksLikeMasscanText(payload []byte) bool {
	line := strings.ToLower(strings.TrimSpace(string(payload)))
	return strings.HasPrefix(line, "discovered open port ") || strings.HasPrefix(line, "open ")
}

func stringField(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case float64:
		return fmt.Sprintf("%.0f", typed)
	case json.Number:
		return typed.String()
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}
