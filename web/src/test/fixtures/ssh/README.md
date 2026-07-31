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
`id_ed25519_enc` (passphrase `correct horse`) exists solely to prove the
encrypted-container refusal message; nothing decrypts it.
