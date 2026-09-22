#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
if [[ "${1:-}" == "--stop" ]]; then
    shift
    exec python3 deploy/w03_deploy.py stop "$@"
fi
exec python3 deploy/w03_deploy.py down "$@"
