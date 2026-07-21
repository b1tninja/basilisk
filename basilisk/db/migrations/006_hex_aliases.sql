-- Multi-valued hex identity aliases (short key ID, fpr32 prefix/suffix).
-- identifier alone is no longer unique across certs.
CREATE TABLE IF NOT EXISTS identifiers_new (
    identifier TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    id_type TEXT NOT NULL,
    PRIMARY KEY (identifier, id_type, fingerprint),
    FOREIGN KEY (fingerprint) REFERENCES certs(fingerprint)
);

INSERT OR IGNORE INTO identifiers_new (identifier, fingerprint, id_type)
SELECT identifier, fingerprint, id_type FROM identifiers;

DROP TABLE identifiers;
ALTER TABLE identifiers_new RENAME TO identifiers;

CREATE INDEX IF NOT EXISTS idx_identifiers_fpr ON identifiers(fingerprint);
CREATE INDEX IF NOT EXISTS idx_identifiers_lookup ON identifiers(identifier, id_type);
