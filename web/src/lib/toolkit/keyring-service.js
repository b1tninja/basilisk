/**
 * The vault service behind "Add to My Keys" (§33c, §34d).
 *
 * The action table reaches no vault of its own — services are injected, never
 * imported — so this is where the button actually stores something. It is a
 * module rather than a closure inside `ArtifactTile.tsx` for the same reason
 * the table is a table: a widget that encoded key material would be a second
 * encoder, and two encoders that can disagree about a key's identity is the
 * failure mode. Every branch below therefore ends in `agent-ops.js`'s own
 * encoder — the one `agent.save` uses — so a key added by a click lands under
 * the same id as the same key saved by a recipe.
 *
 * Loaded lazily on the way in, matching `engine.js`, which reaches
 * `agent-ops.js` through a dynamic import: OpenPGP and the SSH codecs are not
 * worth pulling into the notebook's first paint for a button most tiles never
 * render.
 */

import { hasPrivateKeyMaterial } from "./artifact-actions.js";

/**
 * Whether this browser can hold a key at all.
 *
 * Asked by the tile, so the *absence* of the service is what `available()`
 * reads — the environment fact arrives as `ACTION_REASONS.noVault`, a sentence
 * the user can act on, rather than as a button that silently never appeared.
 */
export function vaultAvailable() {
  return typeof indexedDB !== "undefined";
}

/**
 * Name the form of a body we cannot store, so the refusal says what it saw.
 * "Unsupported" tells a user nothing; "an armored PGP PUBLIC KEY BLOCK" tells
 * them they clicked the wrong tile.
 *
 * @param {string} body
 */
function nameTheForm(body) {
  const armor = body.match(/-----BEGIN ([A-Z0-9 ]+?)-----/);
  if (armor) return `an armored ${armor[1]} block`;
  if (/^(ssh-|ecdsa-sha2-|sk-ssh-)/.test(body)) return "an OpenSSH public line";
  if (/^\s*[{[]/.test(body)) {
    try {
      const parsed = JSON.parse(body);
      if (parsed?.kty && !parsed.d) return `a public ${parsed.kty} JWK, with no private half`;
      if (parsed?.kty) return `a ${parsed.kty} JWK this build has no storage form for`;
    } catch (_) {
      /* fall through to the generic JSON naming */
    }
    return "a JSON body that is not a JWK";
  }
  return "a body in no key form this build recognises";
}

/**
 * The private JWK behind a tile body, whatever shape it arrived in.
 *
 * openssh-key-v1 armor goes back through `ssh.decode` rather than being
 * re-parsed here: that path already owns the wire format, and round-tripping
 * through it means the id the vault files this key under is the same id the
 * codec would compute from the key itself.
 *
 * @param {string} body
 * @returns {Promise<JsonWebKey>}
 */
async function privateJwkFrom(body) {
  if (body.includes("BEGIN OPENSSH PRIVATE KEY")) {
    const { execSshDecode } = await import("./ssh-ops.js");
    const decoded = await execSshDecode({ type: "text", data: body });
    const privateKey = decoded?.data?.privateKey;
    if (!privateKey) {
      throw new Error(
        "This OpenSSH block carries only a public key — My Keys stores private keys."
      );
    }
    return crypto.subtle.exportKey("jwk", privateKey);
  }
  let jwk = null;
  try {
    jwk = JSON.parse(body);
  } catch (_) {
    jwk = null;
  }
  if (!jwk || typeof jwk !== "object" || !jwk.kty || !jwk.d) {
    throw new Error(
      `My Keys cannot store ${nameTheForm(body)} — it holds OpenPGP private keys, OpenSSH private keys and private JWKs.`
    );
  }
  return jwk;
}

/**
 * Store an artifact's body in My Keys at device protection.
 *
 * `saveKey` is called **without `onConflict`**, so the vault's default refusal
 * stands: re-saving over a key held behind a passkey throws
 * `protectionDowngradeMessage`, verbatim, and the tile renders it. The reason
 * that asymmetry with `agent.save` is deliberate is written at the action's
 * call site in `artifact-actions.js`.
 *
 * @param {{ content?: string, alg?: string }} artifact
 * @returns {Promise<{ fingerprint: string, kind: "pgp"|"ssh"|"raw", already: boolean }>}
 */
export async function addPrivateKeyToMyKeys(artifact = {}) {
  const body = String(artifact.content ?? "").trim();
  if (!body) throw new Error("This tile has no body to store.");
  if (!hasPrivateKeyMaterial({ content: body })) {
    throw new Error(
      `My Keys cannot store ${nameTheForm(body)} — it holds OpenPGP private keys, OpenSSH private keys and private JWKs.`
    );
  }

  const { listKeys, saveKey } = await import("../vault.js");

  /** @type {{ fingerprint: string, payload: string, uid: string, email: string, kind: "pgp"|"ssh"|"raw", publicLine?: string, alg?: string }} */
  let record;
  if (body.includes("PGP PRIVATE KEY BLOCK")) {
    const { inspectPrivateKey } = await import("../key-export.js");
    const info = await inspectPrivateKey(body);
    record = {
      fingerprint: info.fingerprint,
      payload: body,
      // The key names itself. Nothing the notebook knows about it beats its
      // own uid, and inventing a label here would make the same key read
      // differently depending on which door it came through.
      uid: info.uid || info.email || info.fingerprint,
      email: info.email || "",
      kind: "pgp",
    };
  } else {
    const { vaultMaterialFromPrivateJwk } = await import("./agent-ops.js");
    const jwk = await privateJwkFrom(body);
    const material = await vaultMaterialFromPrivateJwk(jwk);
    const alg =
      String(artifact.alg || "").toLowerCase() ||
      String(jwk.crv || jwk.kty || "").toLowerCase();
    record = {
      fingerprint: material.id,
      payload: material.payload,
      // `agent.save`'s own naming for a keypair with no email or name given.
      // Matching it is the point: a key stored either way reads the same.
      uid: `${alg} keypair`,
      email: "",
      kind: material.kind,
      publicLine: material.publicLine,
      alg,
    };
  }

  /**
   * Read before the write, for the *receipt* only — never as a guard. The
   * guard is inside `saveKey`'s own transaction, where two tabs cannot race
   * it; this is one word in a log line, and treating it as more than that is
   * how a check-then-act creeps back in.
   */
  const already = (await listKeys()).some((k) => k.fingerprint === record.fingerprint);

  await saveKey({
    fingerprint: record.fingerprint,
    armoredPrivate: record.payload,
    uid: record.uid,
    email: record.email,
    protection: "device",
    ...(record.kind === "pgp"
      ? {}
      : { kind: record.kind, publicLine: record.publicLine, alg: record.alg }),
  });

  return { fingerprint: record.fingerprint, kind: record.kind, already };
}
