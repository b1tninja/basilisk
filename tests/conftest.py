import os
from pathlib import Path

import pytest
from dotenv import load_dotenv
from pysequoia import Cert

load_dotenv(".env.test", override=True)
load_dotenv(".env.example", override=False)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "keys" / "sample.asc"


import pytest

from basilisk.observability.metrics import reset
from basilisk.security.rate_limit import reset_limiter


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    monkeypatch.setenv("BASILISK_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("BASILISK_BLOB_PATH", str(tmp_path / "blobs"))
    monkeypatch.setenv("BASILISK_DEV_APPROVE", "1")
    get_settings.cache_clear()
    reset()
    reset_limiter()
    yield
    get_settings.cache_clear()


@pytest.fixture
def sample_armored() -> str:
    return FIXTURE.read_text(encoding="utf-8")


@pytest.fixture
def sample_fingerprint(sample_armored: str) -> str:
    return Cert.from_bytes(sample_armored.encode()).fingerprint.upper()


# late import after env setup
from basilisk.config import get_settings  # noqa: E402
