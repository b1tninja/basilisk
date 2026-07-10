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

    def _compose_exec(self, *args: str) -> subprocess.CompletedProcess:
        cmd = ["docker", "compose", "-f", self._compose, "exec", "-T", "gpg-tester", *args]
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

    def _exec(self, homedir: str, *args: str) -> subprocess.CompletedProcess:
        return self._compose_exec("gpg", "--homedir", homedir, *args)

    def _ensure_homedir(self, homedir: str) -> None:
        result = self._compose_exec("mkdir", "-p", homedir)
        if result.returncode != 0:
            raise RuntimeError(f"failed to create gpg homedir {homedir}: {result.stderr}")

    @staticmethod
    def _parse_fingerprint(colon_output: str) -> str:
        for line in colon_output.splitlines():
            if not line.startswith("fpr:"):
                continue
            parts = line.split(":")
            for part in reversed(parts):
                candidate = part.strip().upper()
                if len(candidate) == 40 and all(c in "0123456789ABCDEF" for c in candidate):
                    return candidate
        return ""

    def generate_key(self, email: str, homedir: str) -> GpgKey:
        self._ensure_homedir(homedir)
        result = self._exec(
            homedir,
            "--batch",
            "--yes",
            "--quick-generate-key",
            email,
            "rsa2048",
            "default",
            "0",
        )
        if result.returncode != 0:
            raise RuntimeError(f"gpg generate failed: {result.stderr or result.stdout}")

        show = self._exec(homedir, "--with-colons", "--list-keys", email)
        if show.returncode != 0:
            raise RuntimeError(f"gpg list failed: {show.stderr or show.stdout}")

        fingerprint = self._parse_fingerprint(show.stdout)
        if not fingerprint:
            raise RuntimeError(f"no fingerprint found in gpg output:\n{show.stdout}")

        key_id = fingerprint[-16:]
        return GpgKey(email=email, key_id=key_id, fingerprint=fingerprint)

    def send_keys(self, keyserver: str, key_id: str, homedir: str) -> subprocess.CompletedProcess:
        return self._exec(homedir, "--keyserver", keyserver, "--send-keys", key_id)

    def recv_keys(self, keyserver: str, key_id: str, homedir: str) -> subprocess.CompletedProcess:
        return self._exec(homedir, "--keyserver", keyserver, "--recv-keys", key_id)
