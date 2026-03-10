#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "==> Checking Go formatting"
tmp_file="$(mktemp)"
find . -name '*.go' -not -path './vendor/*' -print0 | xargs -0 gofmt -l | tee "$tmp_file"
if [[ -s "$tmp_file" ]]; then
  echo "Go files above are not gofmt-formatted." >&2
  rm -f "$tmp_file"
  exit 1
fi
rm -f "$tmp_file"

echo "==> Checking frontend JavaScript syntax"
if [[ -f web/js/app.js ]]; then
  node --check web/js/app.js
fi

echo "==> Running Go tests"
if [[ -f go.mod ]]; then
  go test ./...
fi

echo "Local validation passed."
