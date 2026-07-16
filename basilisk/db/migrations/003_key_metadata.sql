-- Store OpenPGP key expiration (ISO 8601) extracted at ingest time
ALTER TABLE certs ADD COLUMN key_expiration TEXT;
