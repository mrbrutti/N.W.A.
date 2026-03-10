package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

func parseNaabuJSONImport(payload []byte, fileExt string) (parsedImport, error) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return parsedImport{}, errors.New("naabu payload is empty")
	}

	observations := make([]zmapObservation, 0)
	if trimmed[0] == '[' {
		var rows []map[string]any
		if err := json.Unmarshal(trimmed, &rows); err != nil {
			return parsedImport{}, err
		}
		for _, row := range rows {
			observations = append(observations, naabuObservation(row))
		}
	} else {
		decoder := json.NewDecoder(bytes.NewReader(trimmed))
		for {
			var row map[string]any
			if err := decoder.Decode(&row); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return parsedImport{}, err
			}
			observations = append(observations, naabuObservation(row))
		}
	}
	return buildPortObservationImport("naabu", "naabu", "naabu import", observations, fileExt)
}

func parseNaabuTextImport(payload []byte, fileExt string) (parsedImport, error) {
	lines := strings.Split(strings.ReplaceAll(string(payload), "\r\n", "\n"), "\n")
	observations := make([]zmapObservation, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		host := line
		port := ""
		protocol := "tcp"
		if strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			host = strings.TrimSpace(parts[0])
			port = strings.TrimSpace(parts[len(parts)-1])
		}
		if strings.Contains(port, "/") {
			portParts := strings.SplitN(port, "/", 2)
			port = strings.TrimSpace(portParts[0])
			protocol = strings.TrimSpace(portParts[1])
		}
		observations = append(observations, zmapObservation{
			Address:  host,
			Port:     port,
			Protocol: protocol,
			Success:  true,
		})
	}
	return buildPortObservationImport("naabu", "naabu", "naabu import", observations, fileExt)
}

func looksLikeNaabuJSON(payload []byte) bool {
	sample := strings.ToLower(string(payload))
	return strings.Contains(sample, "\"port\"") && (strings.Contains(sample, "\"ip\"") || strings.Contains(sample, "\"host\"")) && strings.Contains(sample, "\"protocol\"")
}

func looksLikeNaabuText(payload []byte) bool {
	line := strings.TrimSpace(strings.ToLower(string(payload)))
	return strings.Contains(line, ":") && !strings.Contains(line, ",")
}

func naabuObservation(row map[string]any) zmapObservation {
	return zmapObservation{
		Address:  chooseString(stringField(row["ip"]), stringField(row["host"]), stringField(row["input"])),
		Port:     stringField(row["port"]),
		Protocol: chooseString(stringField(row["protocol"]), "tcp"),
		Success:  true,
	}
}
