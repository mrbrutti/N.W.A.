package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"nwa/nmap"
)

type parsedImport struct {
	Scan     nmap.Scan
	Findings map[string][]storedNucleiFinding
	FileExt  string
}

func parseImportFile(path string) (parsedImport, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return parsedImport{}, err
	}
	return parseImportPayload(payload, filepath.Base(path))
}

func parseImportPayload(payload []byte, name string) (parsedImport, error) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return parsedImport{}, errors.New("scan file is empty")
	}

	ext := normalizedFileExt(name)
	if root, ok := sniffXMLRoot(trimmed); ok {
		switch root {
		case "nmaprun":
			scan, err := nmap.ParseBytes(payload)
			return parsedImport{
				Scan:    scan,
				FileExt: chooseImportExt(ext, ".xml"),
			}, err
		case "NessusClientData_v2":
			return parseNessusImport(payload, chooseImportExt(ext, ".nessus"))
		}
	}

	switch ext {
	case ".nessus":
		return parseNessusImport(payload, ".nessus")
	case ".csv":
		if looksLikeNessusCSV(trimmed) {
			return parseNessusCSVImport(payload, ".csv")
		}
		return parseZMapCSVImport(payload, ".csv")
	case ".json", ".jsonl", ".ndjson":
		if looksLikeMasscanJSON(trimmed) {
			return parseMasscanJSONImport(payload, ext)
		}
		if looksLikeNaabuJSON(trimmed) {
			return parseNaabuJSONImport(payload, ext)
		}
		return parseZMapJSONImport(payload, ext)
	case ".txt", ".lst", ".list":
		if looksLikeMasscanText(trimmed) {
			return parseMasscanTextImport(payload, ext)
		}
		if looksLikeNaabuText(trimmed) {
			return parseNaabuTextImport(payload, ext)
		}
		return parseZMapTextImport(payload, ext)
	}

	if looksLikeJSONImport(trimmed) {
		if looksLikeMasscanJSON(trimmed) {
			return parseMasscanJSONImport(payload, chooseImportExt(ext, ".jsonl"))
		}
		if looksLikeNaabuJSON(trimmed) {
			return parseNaabuJSONImport(payload, chooseImportExt(ext, ".jsonl"))
		}
		return parseZMapJSONImport(payload, chooseImportExt(ext, ".jsonl"))
	}
	if looksLikeCSVImport(trimmed) {
		if looksLikeNessusCSV(trimmed) {
			return parseNessusCSVImport(payload, chooseImportExt(ext, ".csv"))
		}
		return parseZMapCSVImport(payload, chooseImportExt(ext, ".csv"))
	}
	if looksLikeLineImport(trimmed) {
		if looksLikeMasscanText(trimmed) {
			return parseMasscanTextImport(payload, chooseImportExt(ext, ".txt"))
		}
		if looksLikeNaabuText(trimmed) {
			return parseNaabuTextImport(payload, chooseImportExt(ext, ".txt"))
		}
		return parseZMapTextImport(payload, chooseImportExt(ext, ".txt"))
	}
	if len(trimmed) > 0 && trimmed[0] == '<' {
		scan, err := nmap.ParseBytes(payload)
		if err == nil || isRecoverableNmap(err) {
			return parsedImport{
				Scan:    scan,
				FileExt: chooseImportExt(ext, ".xml"),
			}, err
		}
	}

	return parsedImport{}, fmt.Errorf("unsupported scan format for %q", name)
}

func isRecoverableNmap(err error) bool {
	if err == nil {
		return true
	}
	var partial *nmap.PartialParseError
	return errors.As(err, &partial)
}

func chooseImportExt(current string, fallback string) string {
	if strings.TrimSpace(current) != "" {
		return current
	}
	return fallback
}

func normalizedFileExt(name string) string {
	return strings.ToLower(strings.TrimSpace(filepath.Ext(strings.TrimSpace(name))))
}

func sniffXMLRoot(payload []byte) (string, bool) {
	decoder := xml.NewDecoder(bytes.NewReader(payload))
	for {
		token, err := decoder.Token()
		if err != nil {
			return "", false
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		return start.Name.Local, true
	}
}

func findingsSummary(findings map[string][]storedNucleiFinding) FindingSummary {
	summary := FindingSummary{}
	for _, hostFindings := range findings {
		for _, finding := range hostFindings {
			summary = addFindingSeverity(summary, finding.Severity)
		}
	}
	return summary
}

func mergeFindingMaps(base map[string][]storedNucleiFinding, incoming map[string][]storedNucleiFinding) map[string][]storedNucleiFinding {
	if len(base) == 0 && len(incoming) == 0 {
		return nil
	}

	merged := make(map[string][]storedNucleiFinding, len(base)+len(incoming))
	for ip, findings := range base {
		merged[ip] = append([]storedNucleiFinding(nil), findings...)
	}
	for ip, findings := range incoming {
		merged[ip] = mergeStoredFindings(merged[ip], findings)
	}
	return merged
}

func enrichmentsFromFindings(findings map[string][]storedNucleiFinding) map[string]hostEnrichment {
	if len(findings) == 0 {
		return nil
	}

	enrichments := make(map[string]hostEnrichment, len(findings))
	for ip, hostFindings := range findings {
		enrichments[ip] = hostEnrichment{
			Nuclei: append([]storedNucleiFinding(nil), hostFindings...),
		}
	}
	return enrichments
}
