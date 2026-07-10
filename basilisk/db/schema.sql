CREATE TABLE IF NOT EXISTS certs (
    fingerprint TEXT PRIMARY KEY,
    approval_state TEXT NOT NULL DEFAULT 'pending',
    blob_uri TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    canonical_blob_uri TEXT,
    approved_uids TEXT NOT NULL DEFAULT '[]',
    pending_uids TEXT NOT NULL DEFAULT '[]',
    claimer_email TEXT,
    claimer_oid TEXT,
    key_id TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS identifiers (
    identifier TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    id_type TEXT NOT NULL,
    FOREIGN KEY (fingerprint) REFERENCES certs(fingerprint)
);

CREATE TABLE IF NOT EXISTS emails (
    email TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY (email, fingerprint),
    FOREIGN KEY (fingerprint) REFERENCES certs(fingerprint)
);

CREATE TABLE IF NOT EXISTS bearer_tokens (
    token_hash TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    logic_app_run_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_certs_state ON certs(approval_state);
CREATE INDEX IF NOT EXISTS idx_identifiers_fpr ON identifiers(fingerprint);
