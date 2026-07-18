-- Migration 005: immutable-ish digest log for key blob changes (TOFU / transparency)
CREATE TABLE IF NOT EXISTS cert_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    event TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cert_history_fpr ON cert_history(fingerprint);
