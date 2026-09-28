#!/usr/bin/env python3
"""Start (or remove) the disposable environment the load harness measures.

    python scripts/load_environment.py up --image asic-backend:phase14-p16closure
    python scripts/load_harness.py ... (the exact command is printed by ``up``)
    python scripts/load_environment.py down

``up`` creates, on a private Docker network:

* ``asic-load-db``  - pgvector/pgvector:pg16, migrated to head as the schema owner, with a login
  ``asic_load_runtime`` in the unprivileged ``asic_app`` role (no BYPASSRLS, no DELETE);
* ``asic-load-api`` - the supplied backend image running ``python -m asic.api`` as that login,
  limited to 2 CPUs and 1 GiB (the documented measurement shape), development HS256
  authentication with the harness's issuer (``asic-load-idp``) and audience, published on
  127.0.0.1:18080.

Everything is local test infrastructure: the passwords and the signing secret are generated per
run, never written to disk, and printed only inside the harness command for this run.
"""

from __future__ import annotations

import argparse
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
NETWORK = "asic-load"
DB, API = "asic-load-db", "asic-load-api"
DB_IMAGE = "pgvector/pgvector:pg16"
DB_PORT, API_PORT = 55480, 18080


def run(*command: str, check: bool = True) -> str:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if check and result.returncode:
        raise SystemExit(f"{' '.join(command[:3])} failed: {result.stderr[-1500:]}")
    return result.stdout.strip()


def down() -> None:
    for name in (API, DB):
        run("docker", "rm", "-f", name, check=False)
    run("docker", "network", "rm", NETWORK, check=False)


def up(image: str) -> None:
    down()
    owner_password = secrets.token_hex(12)
    runtime_password = secrets.token_hex(12)
    jwt_secret = secrets.token_hex(24)
    run("docker", "network", "create", NETWORK)
    run(
        "docker", "run", "-d", "--name", DB, "--network", NETWORK,
        "-e", "POSTGRES_USER=postgres", "-e", f"POSTGRES_PASSWORD={owner_password}",
        "-e", "POSTGRES_DB=asic", "-p", f"127.0.0.1:{DB_PORT}:5432", DB_IMAGE,
    )  # fmt: skip
    deadline = time.monotonic() + 90
    while (
        run("docker", "exec", DB, "pg_isready", "-U", "postgres", "-d", "asic", check=False).find(
            "accepting"
        )
        < 0
    ):
        if time.monotonic() > deadline:
            raise SystemExit("database did not become ready")
        time.sleep(1)
    time.sleep(3)  # the image restarts the server once after initdb
    admin_url = f"postgresql+psycopg2://postgres:{owner_password}@127.0.0.1:{DB_PORT}/asic"
    migrated = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=REPO,
        env={**os.environ, "ASIC_MIGRATION_DATABASE_URL": admin_url,
             "PYTHONPATH": str(REPO / "src")},
        capture_output=True,
        text=True,
        check=False,
    )  # fmt: skip
    if migrated.returncode:
        raise SystemExit(f"migration failed: {migrated.stderr[-1500:]}")
    run(
        "docker", "exec", DB, "psql", "-U", "postgres", "-d", "asic", "-v", "ON_ERROR_STOP=1",
        "-c", f"CREATE ROLE asic_load_runtime LOGIN PASSWORD '{runtime_password}' NOSUPERUSER "
        "NOBYPASSRLS IN ROLE asic_app",
    )  # fmt: skip
    run(
        "docker", "run", "-d", "--name", API, "--network", NETWORK,
        "--cpus", "2", "--memory", "1g", "-p", f"127.0.0.1:{API_PORT}:8000",
        "-e", f"ASIC_DATABASE_URL=postgresql+psycopg2://asic_load_runtime:{runtime_password}"
        f"@{DB}:5432/asic",
        "-e", "ASIC_DEPLOYMENT_ENVIRONMENT=local", "-e", "ASIC_AUTH_MODE=development_hs256",
        "-e", f"ASIC_JWT_SECRET={jwt_secret}", "-e", "ASIC_JWT_ISSUER=asic-load-idp", "-e", "ASIC_JWT_AUDIENCE=asic-api", "-e", "ASIC_API_HOST=0.0.0.0",
        "-e", "ASIC_METRICS_ENABLED=true", "-e", "ASIC_LOG_LEVEL=WARNING",
        image, "/usr/local/bin/python", "-m", "asic.api",
    )  # fmt: skip
    deadline = time.monotonic() + 60
    while True:
        probe = run(
            "curl", "-s", "-o", os.devnull, "-w", "%{http_code}",
            f"http://127.0.0.1:{API_PORT}/readyz", check=False,
        )  # fmt: skip
        if probe == "200":
            break
        if time.monotonic() > deadline:
            raise SystemExit("API did not become ready")
        time.sleep(1)
    app_url = f"postgresql+psycopg2://asic_load_runtime:{runtime_password}@127.0.0.1:{DB_PORT}/asic"
    print("environment ready; run, for example:")
    print(
        f'  python scripts/load_harness.py --admin-url "{admin_url}" --app-url "{app_url}" '
        f"--api-url http://127.0.0.1:{API_PORT} --jwt-secret {jwt_secret} "
        f"--api-container {API} --profile steady --output tmp/load-steady.json"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    start = sub.add_parser("up")
    start.add_argument("--image", required=True, help="backend image to measure")
    sub.add_parser("down")
    args = parser.parse_args()
    if args.command == "up":
        up(args.image)
    else:
        down()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
