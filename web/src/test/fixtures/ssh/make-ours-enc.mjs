#!/usr/bin/env node
/**
 * Regenerate the `ours_*_enc` fixtures — and prove `ssh-keygen` reads them.
 *
 * The other direction was already covered: `id_*_enc*` are keys *ssh-keygen*
 * encrypted, and the suite decrypts them and compares field by field against
 * the plaintext original beside each one. That proves our reader.
 *
 * Nothing proved our *writer*. A round trip through our own encryptor and our
 * own decryptor agrees with itself no matter how wrong both halves are — two
 * bugs that cancel look exactly like no bugs. So this script encrypts the same
 * plaintext fixtures with `encodeOpensshPrivateKey`, writes the containers out,
 * and then hands each one to `ssh-keygen -y -P`, which will only print a public
 * key if it derived the bcrypt_pbkdf key, ran aes256-ctr the same way, and
 * found a well-formed private section with matching checkints underneath.
 *
 * Run it from anywhere:
 *
 *   node web/src/test/fixtures/ssh/make-ours-enc.mjs
 *
 * It is a one-shot, not a test: `ssh-format.test.js` asserts against the
 * checked-in bytes so the suite needs no local `ssh-keygen`. Re-run this only
 * when the writer changes on purpose, and paste the output into README.md —
 * that transcript is the record that the interop claim was checked, and by
 * what.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  encodeOpensshPrivateKey,
  parseOpensshPrivateKey,
} from "../../../lib/ssh/openssh-key-v1.js";

const HERE = dirname(fileURLToPath(import.meta.url));

/** The same passphrase every other encrypted fixture here carries. */
const PASSPHRASE = "correct horse";

/** plaintext fixture → the container we write from it. */
const PAIRS = [
  ["id_ed25519", "ours_ed25519_enc"],
  ["id_ecdsa256", "ours_ecdsa256_enc"],
  ["id_rsa", "ours_rsa_enc"],
];

/** `ssh-keygen -y` prints `type base64` with no comment; compare that much. */
const publicPair = (line) => String(line).trim().split(/\s+/).slice(0, 2).join(" ");

let failures = 0;
for (const [plain, out] of PAIRS) {
  const source = await parseOpensshPrivateKey(readFileSync(join(HERE, plain), "utf8"));
  const pem = await encodeOpensshPrivateKey(source, {
    comment: source.comment,
    passphrase: PASSPHRASE,
  });
  writeFileSync(join(HERE, out), pem, "utf8");

  const derived = execFileSync(
    "ssh-keygen",
    ["-y", "-P", PASSPHRASE, "-f", join(HERE, out)],
    { encoding: "utf8" }
  );
  const expected = readFileSync(join(HERE, `${plain}.pub`), "utf8");
  const ok = publicPair(derived) === publicPair(expected);
  if (!ok) failures++;
  console.log(
    `${ok ? "ok  " : "FAIL"} ${out}: ssh-keygen -y -P opened it and derived ` +
      `${publicPair(derived).slice(0, 28)}…` +
      (ok ? " (matches its .pub)" : `\n     expected ${publicPair(expected)}`)
  );
}

// Which OpenSSH said so. `ssh -V` writes to stderr and always has; asking
// `ssh-keygen` for a version instead starts it generating a key in $HOME.
console.log(
  `read by ${String(spawnSync("ssh", ["-V"], { encoding: "utf8" }).stderr || "").trim()}`
);

if (failures) {
  console.error(`${failures} container(s) ssh-keygen could not open — do not check these in.`);
  process.exit(1);
}
