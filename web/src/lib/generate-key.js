/**
 * Generate an OpenPGP keypair via the crypto Web Worker.
 *
 * @param {object} opts
 * @param {string} opts.email
 * @param {string} [opts.name]
 * @param {number|null} [opts.keyExpirationTime]  seconds from now
 * @param {string} [opts.passphrase]
 * @returns {Promise<{ armoredPublic: string, armoredPrivate: string, fingerprint: string }>}
 */
export function generateKeyViaWorker(opts) {
  return new Promise((resolve, reject) => {
    let worker;
    try {
      worker = new Worker(new URL("./crypto-worker.js", import.meta.url), {
        type: "module",
      });
    } catch (err) {
      reject(err);
      return;
    }
    const id = `gen-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const timer = setTimeout(() => {
      try {
        worker.terminate();
      } catch (_) {
        /* ignore */
      }
      reject(new Error("Key generation timed out"));
    }, 60_000);

    worker.onmessage = (ev) => {
      if (ev.data?.id !== id) return;
      clearTimeout(timer);
      try {
        worker.terminate();
      } catch (_) {
        /* ignore */
      }
      if (ev.data.ok) {
        resolve({
          armoredPublic: ev.data.armoredPublic,
          armoredPrivate: ev.data.armoredPrivate,
          fingerprint: ev.data.fingerprint,
        });
      } else {
        reject(new Error(ev.data.error || "Key generation failed"));
      }
    };
    worker.onerror = (err) => {
      clearTimeout(timer);
      try {
        worker.terminate();
      } catch (_) {
        /* ignore */
      }
      reject(err?.message ? new Error(err.message) : new Error("Worker error"));
    };

    worker.postMessage({
      id,
      type: "generate",
      email: opts.email,
      name: opts.name || "",
      keyExpirationTime: opts.keyExpirationTime ?? null,
      passphrase: opts.passphrase || "",
    });
  });
}
