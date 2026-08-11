import { KeyCard } from "basilisk-portal";

/*
 * Every JWK below came out of `genkey` — `basilisk run` on `genkey ed25519 |
 * export jwk | out $kp` and friends. The public halves are what the engine's
 * `publicJwkText` puts in `traits.publicJwk`: the same key re-exported through
 * `crypto.subtle.exportKey("jwk", …)` with the private scalar gone.
 *
 * Nothing here is hand-written, which matters more for this card than for most:
 * it derives the SSH fingerprint and public line from the JWK itself, so an
 * invented `x` would draw a fingerprint of nothing.
 */

const ED_PUBLIC = `{
  "key_ops": [
    "verify"
  ],
  "ext": true,
  "alg": "Ed25519",
  "crv": "Ed25519",
  "x": "cAh1pwA4axi_AKahQ1bkmo1DZWkHS6JtZGAz55f4X_w",
  "kty": "OKP"
}`;

const ED_PRIVATE = `{
  "key_ops": [
    "sign"
  ],
  "ext": true,
  "alg": "Ed25519",
  "crv": "Ed25519",
  "d": "Rr3wdwDbwm-EYc1IX4zU2L0c48oiVkHcdW-M1hXemjc",
  "x": "cAh1pwA4axi_AKahQ1bkmo1DZWkHS6JtZGAz55f4X_w",
  "kty": "OKP"
}`;

const P256_PUBLIC = `{
  "key_ops": [
    "verify"
  ],
  "ext": true,
  "kty": "EC",
  "x": "qzw0ORRjaDAHPheUKsnuUgXIveORUrtQqgbTLgSxf6w",
  "y": "wU1og7RBZbrq8FL54KvhSAsKhxyl1b5ZSU3T6CcSthE",
  "crv": "P-256"
}`;

const X25519_PUBLIC = `{
  "key_ops": [],
  "ext": true,
  "crv": "X25519",
  "x": "gnNdum-bTUfBE1eDTzElcbVC_ewf8oOXHNxh6-iYaSw",
  "kty": "OKP"
}`;

const AES_SECRET = `{
  "key_ops": [
    "encrypt",
    "decrypt"
  ],
  "ext": true,
  "alg": "A256GCM",
  "kty": "oct",
  "k": "InXvRgw77hyhhFiZrqiL1DiQe_hsdfhThuB0hzMibTM"
}`;

/**
 * The masked private tile — the state the card exists for.
 *
 * `half` and `withheld` are two props doing two jobs, and this is where the
 * split pays. `half="private"` says what the artifact *is*; `withheld` names
 * what is deliberately not on screen and the recipe edit that would put it
 * there. Everything still drawn — algorithm, `SHA256:` fingerprint, public
 * line — is derived from the public half, so a masked tile is informative
 * rather than blank. `publicOnly` removes the raw toggle, and nothing else.
 */
export const MaskedPrivate = () => (
  <KeyCard
    content={ED_PRIVATE}
    jwk={ED_PUBLIC}
    alg="ed25519"
    comment="ada@lovelace.dev"
    half="private"
    withheld="private scalar not shown — reveal the tile, or `out $kp` to write it to a file"
    publicOnly
  />
);

/**
 * The keypair tip: a bare `genkey` with no `out`. There is no body at all —
 * `content` is the empty string, and the public half rides `traits`. The card
 * is the entire artifact, which is why the withheld sentence has to name the
 * edit rather than gesture at a toggle that is not there.
 */
export const KeypairTip = () => (
  <KeyCard
    content=""
    jwk={ED_PUBLIC}
    alg="ed25519"
    half="both"
    withheld="private half not shown — add `out $kp` to the recipe to write both halves"
    publicOnly
  />
);

/**
 * The public half, unmasked. The raw JWK is one toggle down rather than the
 * whole tile — the `raw` link is the only thing `publicOnly` was hiding above.
 */
export const PublicHalf = () => (
  <KeyCard content={ED_PUBLIC} alg="ed25519" comment="ada@lovelace.dev" half="public" />
);

/**
 * The half axis, on four real keys.
 *
 * `secret` is the one that is not a half: a symmetric key has none, and the
 * caption says so in words instead of calling it "the secret half". Note what
 * the AES and X25519 rows *lack* — SSH has no key type for either, so the
 * public line is absent rather than empty. An empty row would imply one exists.
 */
export const Halves = () => (
  <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr)", gap: 14 }}>
    <KeyCard content={ED_PUBLIC} alg="ed25519" half="public" />
    <KeyCard content={P256_PUBLIC} alg="ec/p256" half="public" />
    <KeyCard content={X25519_PUBLIC} alg="x25519" half="public" />
    <KeyCard content={AES_SECRET} alg="aes/256" half="secret" />
  </div>
);

/**
 * A key whose kind cannot know which half it holds says nothing rather than
 * guessing — no caption at all beside the algorithm. The pre-computed
 * `fingerprint` prop is the OpenPGP path: grouped hex rather than the
 * `SHA256:` form, because that is the shape that kind's id is compared in.
 */
export const UnknownHalf = () => (
  <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr)", gap: 14 }}>
    <KeyCard content={P256_PUBLIC} alg="ec/p256" />
    <KeyCard
      content=""
      alg="openpgp/ed25519"
      fingerprint="EF15CD3F7594784371E82C0A904908A0F0ECF0AB"
      half="public"
      publicOnly
    />
  </div>
);
