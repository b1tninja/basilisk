-- Portal: pending UID index, claimer tracking, composite email index
ALTER TABLE certs ADD COLUMN pending_uids TEXT NOT NULL DEFAULT '[]';
ALTER TABLE certs ADD COLUMN claimer_email TEXT;
ALTER TABLE certs ADD COLUMN claimer_oid TEXT;

CREATE TABLE IF NOT EXISTS emails_new (
    email TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY (email, fingerprint),
    FOREIGN KEY (fingerprint) REFERENCES certs(fingerprint)
);

INSERT OR IGNORE INTO emails_new (email, fingerprint)
SELECT email, fingerprint FROM emails;

DROP TABLE emails;
ALTER TABLE emails_new RENAME TO emails;

CREATE INDEX IF NOT EXISTS idx_certs_claimer_email ON certs(claimer_email);
CREATE INDEX IF NOT EXISTS idx_certs_claimer_oid ON certs(claimer_oid);
