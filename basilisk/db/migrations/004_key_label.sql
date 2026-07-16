-- Migration 004: user-settable friendly label for a key (max 200 chars, owner only)
ALTER TABLE certs ADD COLUMN label TEXT;
