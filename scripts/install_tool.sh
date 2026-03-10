#!/bin/sh
set -eu

exec go run ./scripts/install_tool.go "$@"
