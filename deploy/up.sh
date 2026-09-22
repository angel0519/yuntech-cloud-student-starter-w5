#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
exec python3 deploy/w03_deploy.py up "$@"
