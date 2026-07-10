from __future__ import annotations

import subprocess
import time
from pathlib import Path

import httpx
import pytest

COMPOSE_FILE = Path(__file__).resolve().parents[2] / "docker-compose.e2e.yml"


@pytest.fixture(scope="session")
def docker_compose():
    subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "up", "-d", "--build"],
        check=True,
    )
    url = "http://localhost:8080"
    deadline = time.time() + 120
    while time.time() < deadline:
        try:
            r = httpx.get(f"{url}/health", timeout=2)
            if r.status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(2)
    else:
        pytest.fail("basilisk service did not become healthy")
    yield url
    subprocess.run(["docker", "compose", "-f", str(COMPOSE_FILE), "down", "-v"], check=False)


@pytest.fixture
def basilisk_url(docker_compose: str) -> str:
    return docker_compose


@pytest.fixture
def gpg_runner():
    from tests.helpers.gpg_runner import GpgRunner

    return GpgRunner()
