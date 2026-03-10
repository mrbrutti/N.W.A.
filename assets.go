package main

import (
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"path/filepath"
	"strings"
)

//go:embed web/css/* web/js/* web/images/* web/templates/*.html
var webAssets embed.FS

func loadTemplates() (*template.Template, error) {
	funcs := template.FuncMap{
		"join":           strings.Join,
		"base":           filepath.Base,
		"severityTone":   severityTone,
		"findingGroupID": findingGroupID,
		"maxBucketCount": func(items []Bucket) int {
			maxCount := 0
			for _, item := range items {
				if item.Count > maxCount {
					maxCount = item.Count
				}
			}
			return maxCount
		},
		"percent": func(value int, total int) int {
			if total <= 0 {
				return 0
			}
			return (value * 100) / total
		},
		"pluralize": func(count int, singular string, plural string) string {
			if count == 1 {
				return singular
			}
			return plural
		},
		"sliceBuckets": func(items []Bucket, limit int) []Bucket {
			if limit <= 0 || len(items) == 0 {
				return nil
			}
			if len(items) <= limit {
				return items
			}
			return items[:limit]
		},
		"json": func(value any) string {
			payload, err := json.Marshal(value)
			if err != nil {
				return "[]"
			}
			return string(payload)
		},
	}

	return template.New("site").Funcs(funcs).ParseFS(webAssets, "web/templates/*.html")
}

func embeddedSubdir(path string) (fs.FS, error) {
	return fs.Sub(webAssets, path)
}
