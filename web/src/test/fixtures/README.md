# OpenPGP interop fixtures

`ada-pub.asc`, `ada-sec.asc`, `sealed.asc` — a throwaway key and one
signed-and-encrypted message, checked in so `subkey-signature.test.js` needs
neither a local GnuPG nor the network.

**They exist because openpgp.js cannot produce them.** It signs with the
primary key, so every fixture the JS suite can mint takes `matchSigner`'s
first branch — the primary's fingerprint ending with the signature's key id.
GnuPG prefers a *signing subkey* when one exists, which is the only way to
reach the `getKeyIDs()` fallback. Before these, deleting that fallback passed
the entire suite.

The secret key is committed on purpose and is safe to commit: it was generated
for this file, has an empty passphrase, protects nothing, and is not used
anywhere else. It is the same bargain as the SSH private keys next door — the
`*.asc` rule in `.gitignore` exists to stop *real* armored key material from
being committed, and this directory is the stated exception. Do not reuse this
key for anything, and do not add a fixture here that was ever real.

`.gitattributes` marks them `-text` for the reason the SSH fixtures do: the
key id and fingerprint below are byte-asserted, and a CRLF conversion on
checkout would be a silent corruption.

Generated once with GnuPG 2.4.9:

```bash
export GNUPGHOME=$(mktemp -d) && chmod 700 "$GNUPGHOME"
gpg --batch --quick-gen-key --passphrase '' "Ada Fixture <ada@fixture.test>" ed25519 cert 0
FPR=$(gpg --list-keys --with-colons | awk -F: '/^fpr:/{print $10; exit}')
gpg --batch --passphrase '' --quick-add-key "$FPR" ed25519 sign 0
gpg --batch --passphrase '' --quick-add-key "$FPR" cv25519 encr 0
echo "sealed payload" | gpg --batch --passphrase '' --armor --sign --encrypt -r "$FPR" > sealed.asc
gpg --armor --export "$FPR" > ada-pub.asc
gpg --batch --pinentry-mode loopback --passphrase '' --armor --export-secret-keys "$FPR" > ada-sec.asc
```

Primary `3F8C269E9661ADF747CC7AB8FA0AE8CB2F7DFBFC`, signing subkey id
`D0FA677B683331C9`. The primary does **not** end with that id — that is the
whole point, and the test asserts it, so a future GnuPG that stopped
preferring the subkey fails loudly here instead of passing for a new reason.

## What is not here

GnuPG 2.4.9 emits no **subpacket 35** (Intended Recipient Fingerprint):
sign-and-encrypt writes subpacket 33 (issuer fingerprint) and 16 (issuer key
id) and nothing else, and `--dump-options` offers no way to ask for it. So the
engine half of the intended-recipient check has no fixture here and cannot get
one from this tool — it is covered at module level with a constructed packet.
