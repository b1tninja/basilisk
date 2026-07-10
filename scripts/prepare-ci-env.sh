#!/usr/bin/env bash
# Create .env files for CI from committed examples; inject secrets from the environment.
set -euo pipefail
cd "$(dirname "$0")/.."

cp .env.test.example .env.test
cp .env.example .env

if [[ -n "${BASILISK_TOKEN_SECRET:-}" ]]; then
  python - <<'PY'
import os
from pathlib import Path

secret = os.environ["BASILISK_TOKEN_SECRET"]
for name in (".env.test", ".env"):
    path = Path(name)
    lines = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if not line.startswith("BASILISK_TOKEN_SECRET=")
    ]
    lines.append(f"BASILISK_TOKEN_SECRET={secret}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
fi

echo "Prepared .env.test and .env for CI"
