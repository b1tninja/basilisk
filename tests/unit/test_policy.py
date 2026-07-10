import pytest

from basilisk.openpgp.ingest import IngestError, parse_armored_keytext
from basilisk.openpgp.policy import PolicyConfig, validate_cert_policy, validate_options_nm


@pytest.fixture
def sample_armored() -> str:
    from pathlib import Path

    return (Path(__file__).resolve().parents[1] / "fixtures" / "keys" / "sample.asc").read_text(
        encoding="utf-8"
    )


@pytest.mark.unit
def test_valid_v4_key_passes(sample_armored):
    parsed = parse_armored_keytext(sample_armored, path="v1")
    assert len(parsed.fingerprint) == 40


@pytest.mark.unit
def test_reject_empty():
    with pytest.raises(IngestError) as exc:
        parse_armored_keytext("", path="v1")
    assert exc.value.status == 422


@pytest.mark.unit
def test_reject_non_armor():
    with pytest.raises(IngestError):
        parse_armored_keytext("not a key", path="v1")


@pytest.mark.unit
def test_reject_options_nm(sample_armored):
    with pytest.raises(IngestError) as exc:
        validate_options_nm(sample_armored + "?options=nm")
    assert "options=nm" in str(exc.value)


@pytest.mark.unit
def test_reject_oversize(sample_armored, monkeypatch):
    monkeypatch.setenv("BASILISK_MAX_UPLOAD_BYTES", "100")
    from basilisk.config import get_settings

    get_settings.cache_clear()
    with pytest.raises(IngestError) as exc:
        parse_armored_keytext(sample_armored, path="v1")
    assert exc.value.status == 413
    get_settings.cache_clear()


@pytest.mark.unit
def test_reject_multi_cert(sample_armored):
    doubled = sample_armored + "\n" + sample_armored
    with pytest.raises(IngestError) as exc:
        parse_armored_keytext(doubled, path="v1")
    assert "one public key" in str(exc.value).lower()


@pytest.mark.unit
def test_reject_no_email_uid(sample_armored, monkeypatch):
    monkeypatch.setenv("BASILISK_REQUIRE_EMAIL_UID", "1")
    from basilisk.config import get_settings

    get_settings.cache_clear()
    parsed = parse_armored_keytext(sample_armored, path="v1")
    config = PolicyConfig.from_settings()
    bad = type(parsed)(
        fingerprint=parsed.fingerprint,
        key_id=parsed.key_id,
        uids=["No Email Name"],
        armored=parsed.armored,
        raw_cert=parsed.raw_cert,
    )
    with pytest.raises(IngestError) as exc:
        validate_cert_policy(bad, "v1", config=config)
    assert "email" in str(exc.value).lower()
    get_settings.cache_clear()
