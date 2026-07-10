from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

COMPOSE_FILE = Path(__file__).resolve().parents[2] / "docker-compose.e2e.yml"


@dataclass
class GpgKey:
    email: str
    key_id: str
    fingerprint: str


class GpgRunner:
    """Run gpg inside gpg-tester container via docker compose exec."""

    def __init__(self, compose_file: Path | None = None) -> None:
        self._compose = str(compose_file or COMPOSE_FILE)

    def _exec(self, homedir: str, *args: str) -> subprocess.CompletedProcess:
        cmd = [
            "docker",
            "compose",
            "-f",
            self._compose,
            "exec",
            "-T",
            "gpg-tester",
            "gpg",
            "--homedir",
            homedir,
            *args,
        ]
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

    def generate_key(self, email: str, homedir: str) -> GpgKey:
        self._exec(
            homedir,
            "--batch",
            "--yes",
            "--quick-generate-key",
            email,
            "rsa2048",
            "default",
            "0",
        )
        show = self._exec(homedir, "--with-colons", "--list-keys", email)
        key_id = ""
        fpr = ""
        for line in show.stdout.splitlines():
            if line.startswith("pub:"):
                parts = line.split(":")
                key_id = parts[4]
            if line.startswith("fpr:"):
                fpr = line.split(":")[9]
                break
        return GpgKey(email=email, key_id=key_id, fingerprint=fpr.upper())

    def send_keys(self, keyserver: str, key_id: str, homedir: str) -> subprocess.CompletedProcess:
        return self._exec(homedir, "--keyserver", keyserver, "--send-keys", key_id)

    def recv_keys(self, keyserver: str, key_id: str, homedir: str) -> subprocess.CompletedProcess:
        return self._exec(homedir, "--keyserver", keyserver, "--recv-keys", key_id)
