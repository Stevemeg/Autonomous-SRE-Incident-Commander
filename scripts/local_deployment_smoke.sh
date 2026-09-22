#!/usr/bin/env bash
set -Eeuo pipefail
# Supply already built/scanned artifacts; never rebuild a different deployment image.
exec python scripts/deployment_smoke.py "$@"
