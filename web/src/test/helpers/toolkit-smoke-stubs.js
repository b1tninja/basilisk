/**
 * Vitest-only globals for toolkit smoke (WebAuthn PRF + HKP fetch).
 *
 * MUST NOT be imported from production pages or lib/. Fixed PRF IKM is for
 * deterministic CI only — never use these stubs (or their IKM) for real vault keys.
 */

/**
 * @param {string} name
 */
function assertVitestOnly(name) {
  const inVitest =
    (typeof process !== "undefined" &&
      !!(process.env?.VITEST || process.env?.VITEST_WORKER_ID)) ||
    (typeof import.meta !== "undefined" && !!import.meta.vitest);
  if (!inVitest) {
    throw new Error(
      `${name} is Vitest-only and must not run outside the test runner`
    );
  }
}

/**
 * Stub `navigator.credentials` + `location` so WebAuthn create/get/prf and
 * `agent.save protection=passkey` run under Vitest (Node) without an authenticator.
 * Returns the fixed PRF IKM used by create/get.
 *
 * @param {(name: string, value: unknown) => void} stubGlobal  vitest `vi.stubGlobal`
 * @param {Uint8Array} [fixedIkm]
 * @returns {Uint8Array}
 */
export function installWebAuthnPrfStub(stubGlobal, fixedIkm) {
  assertVitestOnly("installWebAuthnPrfStub");
  if (typeof stubGlobal !== "function") {
    throw new Error("installWebAuthnPrfStub requires vi.stubGlobal");
  }

  const ikm =
    fixedIkm && fixedIkm.byteLength
      ? fixedIkm
      : crypto.getRandomValues(new Uint8Array(32));
  const rawId = new Uint8Array(16);
  for (let i = 0; i < rawId.length; i++) rawId[i] = i + 1;

  const makeCred = () => ({
    id: "basilisk-verb-smoke-cred",
    rawId: rawId.buffer,
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {},
    getClientExtensionResults: () => ({
      prf: {
        results: {
          first: ikm.buffer.slice(
            ikm.byteOffset,
            ikm.byteOffset + ikm.byteLength
          ),
        },
      },
    }),
  });

  stubGlobal("location", {
    hostname: "localhost",
    origin: "http://localhost",
    href: "http://localhost/",
    protocol: "http:",
    host: "localhost",
  });

  const prevNav =
    typeof globalThis.navigator === "object" && globalThis.navigator
      ? { ...globalThis.navigator }
      : {};
  stubGlobal("navigator", {
    ...prevNav,
    credentials: {
      create: async () => makeCred(),
      get: async () => makeCred(),
    },
  });

  stubGlobal("PublicKeyCredential", {
    isUserVerifyingPlatformAuthenticatorAvailable: async () => true,
    isConditionalMediationAvailable: async () => false,
    getClientCapabilities: async () => ({ extension: { prf: true } }),
  });

  return ikm;
}

/**
 * Install fetch mock for This-site HKP used by verb smoke.
 * @param {{ fingerprint: string, armoredPublic: string, email?: string }} key
 * @param {(name: string, value: unknown) => void} stubGlobal  vitest `vi.stubGlobal`
 */
export function installHkpFetchMock(key, stubGlobal) {
  assertVitestOnly("installHkpFetchMock");
  if (typeof stubGlobal !== "function") {
    throw new Error("installHkpFetchMock requires vi.stubGlobal");
  }

  const fpr = String(key.fingerprint || "").toUpperCase();
  const armored = key.armoredPublic;
  const email = key.email || "alice@example.com";
  const bobFpr = (fpr.slice(0, -1) + (fpr.endsWith("0") ? "1" : "0")).toUpperCase();
  stubGlobal("fetch", async (url) => {
    const u = String(url);
    if (u.includes("/api/v1/search")) {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          results: [
            {
              fingerprint: fpr,
              email,
              uid: `Alice <${email}>`,
              approval_state: "approved",
              armoredKey: armored,
            },
            {
              fingerprint: bobFpr,
              email: "bob@example.com",
              uid: "Bob <bob@example.com>",
              approval_state: "approved",
              armoredKey: armored,
            },
          ],
        }),
      };
    }
    if (u.includes("/api/v1/key/")) {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          approval_state: "approved",
          approved_uids: [`Alice <${email}>`],
          key_id: fpr.slice(-16),
          revoked: false,
        }),
      };
    }
    if (u.includes("/pks/lookup")) {
      return {
        ok: true,
        status: 200,
        text: async () => armored,
      };
    }
    throw new Error(`toolkit-smoke-stubs unexpected fetch ${u}`);
  });
}
