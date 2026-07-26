/**
 * Toolkit WebAuthn step bodies (main-thread ceremonies + soft MDS helpers).
 *
 * create / get / prf need `navigator.credentials` — recipes using those ops
 * must run on the window thread, not in the crypto worker.
 */

import { parseAttestationObject } from "../webauthn/attestation.js";
import { lookupAaguidInMds, normalizeAaguid } from "../webauthn/mds.js";
import { createPasskeyPrf, getPasskeyPrf } from "../vault.js";

/**
 * @returns {Promise<{ type: "text", data: string, meta: object }>}
 */
export async function execWaCaps() {
  /** @type {Record<string, *>} */
  const caps = {
    publicKeyCredential: typeof PublicKeyCredential !== "undefined",
    credentialsCreate: typeof navigator !== "undefined" && !!navigator.credentials?.create,
    credentialsGet: typeof navigator !== "undefined" && !!navigator.credentials?.get,
  };

  if (typeof PublicKeyCredential !== "undefined") {
    try {
      if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
        caps.userVerifyingPlatformAuthenticator =
          await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      }
    } catch (err) {
      caps.userVerifyingPlatformAuthenticator = null;
      caps.uvpaError = err?.message || String(err);
    }
    try {
      if (typeof PublicKeyCredential.isConditionalMediationAvailable === "function") {
        caps.conditionalMediation =
          await PublicKeyCredential.isConditionalMediationAvailable();
      }
    } catch (err) {
      caps.conditionalMediation = null;
      caps.conditionalError = err?.message || String(err);
    }
    try {
      if (typeof PublicKeyCredential.getClientCapabilities === "function") {
        caps.clientCapabilities = await PublicKeyCredential.getClientCapabilities();
      }
    } catch (err) {
      caps.clientCapabilities = null;
      caps.clientCapsError = err?.message || String(err);
    }
  }

  return {
    type: "text",
    data: JSON.stringify(caps, null, 2),
    meta: { kind: "opaque", webauthn: "caps" },
  };
}

/**
 * @param {Record<string, *>} params
 * @returns {Promise<{ type: "bytes", data: Uint8Array, meta: object }>}
 */
export async function execWaCreate(params = {}) {
  assertCredentialsApi("create");
  const user = String(params.user || "basilisk-toolkit");
  const { prfIkm, mds } = await createPasskeyPrf(user);
  return {
    type: "bytes",
    data: prfIkm,
    meta: {
      sensitive: true,
      kind: "opaque",
      length: prfIkm.length,
      webauthn: "prf-ikm",
      mds: mds
        ? {
            status: mds.status,
            aaguid: mds.aaguid,
            description: mds.description || "",
            detail: mds.detail || "",
          }
        : undefined,
    },
  };
}

/**
 * Assertion ceremony; returns client extension results (incl. PRF presence) as JSON.
 * Prefer `webauthn.prf` when you need pipeline PRF IKM bytes.
 * @returns {Promise<{ type: "text", data: string, meta: object }>}
 */
export async function execWaGet() {
  assertCredentialsApi("get");
  const cred = /** @type {PublicKeyCredential} */ (
    await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        userVerification: "preferred",
        timeout: 120_000,
      },
    })
  );
  if (!cred) throw new Error("WebAuthn get cancelled or failed");
  const ext = cred.getClientExtensionResults?.() || {};
  const payload = {
    id: cred.id,
    type: cred.type,
    authenticatorAttachment: /** @type {*} */ (cred).authenticatorAttachment || null,
    clientExtensionResults: ext,
  };
  return {
    type: "text",
    data: JSON.stringify(payload, null, 2),
    meta: { kind: "opaque", webauthn: "assertion" },
  };
}

/**
 * @returns {Promise<{ type: "bytes", data: Uint8Array, meta: object }>}
 */
export async function execWaPrf() {
  assertCredentialsApi("get");
  const prfIkm = await getPasskeyPrf();
  return {
    type: "bytes",
    data: prfIkm,
    meta: {
      sensitive: true,
      kind: "opaque",
      length: prfIkm.length,
      webauthn: "prf-ikm",
    },
  };
}

/**
 * Parse attestationObject bytes → AAGUID / fmt JSON.
 * @param {{ type: string, data: * } | null} value
 * @returns {Promise<{ type: "text", data: string, meta: object }>}
 */
export async function execWaAttest(value) {
  if (!value || value.type !== "bytes") {
    throw new Error("webauthn.attest expects attestationObject bytes");
  }
  const parsed = parseAttestationObject(value.data);
  if (!parsed) throw new Error("Could not parse attestationObject");
  const payload = {
    fmt: parsed.fmt,
    aaguid: parsed.aaguid,
    authDataLength: parsed.authData?.length ?? 0,
  };
  return {
    type: "text",
    data: JSON.stringify(payload, null, 2),
    meta: { kind: "opaque", webauthn: "attest", aaguid: parsed.aaguid },
  };
}

/**
 * Soft MDS lookup for an AAGUID (param, or aaguid field in prior JSON text).
 * @param {{ type: string, data: * } | null} value
 * @param {Record<string, *>} params
 * @returns {Promise<{ type: "text", data: string, meta: object }>}
 */
export async function execWaMds(value, params = {}) {
  let aaguid = String(params.aaguid || "").trim();
  if (!aaguid && value?.type === "text") {
    try {
      const obj = JSON.parse(String(value.data || ""));
      aaguid = String(obj?.aaguid || "").trim();
    } catch {
      aaguid = String(value.data || "").trim();
    }
  }
  if (!aaguid) {
    throw new Error("webauthn.mds needs an aaguid param or prior JSON with an aaguid field");
  }
  const result = await lookupAaguidInMds(normalizeAaguid(aaguid));
  return {
    type: "text",
    data: JSON.stringify(result, null, 2),
    meta: { kind: "opaque", webauthn: "mds", aaguid: result.aaguid },
  };
}

/**
 * @param {"create"|"get"} op
 */
function assertCredentialsApi(op) {
  if (typeof navigator === "undefined" || !navigator.credentials?.[op]) {
    throw new Error(
      `WebAuthn ${op} requires the main browser thread (navigator.credentials). ` +
        "Recipes with webauthn.create / webauthn.get / webauthn.prf cannot run in a Worker."
    );
  }
}
