# SSH interop fixtures

Generated once with OpenSSH 10.3p1 (`ssh-keygen` from Git for Windows,
OpenSSL 3.5.6) and checked in so the tests need neither a local
`ssh-keygen` nor the network. The `.gitattributes` here marks everything
`-text` — these files are byte-asserted, and a CRLF conversion would be a
silent test-corruption.

Generating commands (from this directory):

```bash
printf 'basilisk sshsig fixture payload\n' > payload.txt

ssh-keygen -t ed25519        -N "" -C "fixture@basilisk" -f id_ed25519  -q
ssh-keygen -t ecdsa  -b 256  -N "" -C "fixture@basilisk" -f id_ecdsa256 -q
ssh-keygen -t ecdsa  -b 384  -N "" -C "fixture@basilisk" -f id_ecdsa384 -q
ssh-keygen -t ecdsa  -b 521  -N "" -C "fixture@basilisk" -f id_ecdsa521 -q
ssh-keygen -t rsa    -b 3072 -N "" -C "fixture@basilisk" -f id_rsa      -q
ssh-keygen -t ed25519 -N "correct horse" -C "fixture@basilisk" -f id_ed25519_enc -q

# Passphrase-protected copies of the plaintext keys above, at four different
# KDF rounds counts (`-p` rewrites in place and keeps the comment). Encrypting
# *copies of known keys* is the point: the test asserts the decrypted material
# equals the plaintext fixture field for field, which no amount of agreeing
# with our own encryptor can fake. `id_ed25519_enc` above covers the current
# ssh-keygen default of 24 rounds.
cp id_ed25519  id_ed25519_enc1  && ssh-keygen -p -a 1  -N "correct horse" -f id_ed25519_enc1  -q
cp id_ecdsa256 id_ecdsa256_enc  && ssh-keygen -p -a 4  -N "correct horse" -f id_ecdsa256_enc  -q
cp id_rsa      id_rsa_enc       && ssh-keygen -p -a 16 -N "correct horse" -f id_rsa_enc       -q
rm -f id_ed25519_enc1.pub id_ecdsa256_enc.pub id_rsa_enc.pub

for f in id_ed25519 id_ecdsa256 id_ecdsa384 id_ecdsa521 id_rsa; do
  ssh-keygen -lf $f.pub
done > fingerprints.txt

for k in id_ed25519 id_ecdsa256 id_rsa; do
  ssh-keygen -Y sign -f $k -n file payload.txt
  mv payload.txt.sig payload.$k.file.sshsig
done
ssh-keygen -Y sign -f id_ed25519 -n git payload.txt
mv payload.txt.sig payload.id_ed25519.git.sshsig
```

These keys exist to be public. They are test vectors, not secrets — do not
use them for anything, and do not "rotate" them without regenerating every
derived file above, because the tests assert bytes, not relationships.

Every `*_enc*` file has the passphrase `correct horse`. All four are opened
by `parseOpensshPrivateKey` now — `bcrypt_pbkdf` landed, and the refusal
these once existed to prove is gone. Their remaining job is stricter: the
three made with `-p` are copies of the plaintext key beside them, so
decrypting one and comparing it to its plaintext original is an interop
assertion against `ssh-keygen`, not a round-trip through our own code.

Note the KDF rounds counts are load-bearing and deliberately spread (1, 4,
16, 24). `ssh-keygen` defaults to 24 today; it defaulted to 16 in older
OpenSSH, so a fixture regenerated on a different machine may not carry the
rounds count the tests assert. Regenerate all of them together, and check
the `-a` flags above still match what the tests expect.
