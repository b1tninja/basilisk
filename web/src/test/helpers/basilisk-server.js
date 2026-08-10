/**
 * The real keyserver, spawned, for the browser suite to talk to.
 *
 * The first version of this was a JavaScript stub that reimplemented
 * `/pks/lookup` faithfully enough to pass. It was deleted on purpose: two
 * implementations of one idea can disagree, and the one under test is never
 * the one users hit. This runs `basilisk/serve.py` — the Flask service this
 * repo ships — and points the page's `/pks/*` and `/api/v1/*` at it.
 *
 * ## No Docker, and no Azure
 *
 * `basilisk/db/factory.py` picks its stores from one environment variable:
 * with `AZURE_STORAGE_CONNECTION_STRING` set it uses Azure Tables and Blobs,
 * and **unset** it falls back to `SqliteCertStore` and `LocalBlobStore`. Those
 * are the drop-in replacements, they are the default path, and they need
 * nothing running. `docker-compose.e2e.yml` brings up azurite because the
 * *Python* e2e deliberately exercises the Azure branch; the browser suite has
 * no such need, so it spawns the app directly into a fresh temp directory.
 *
 * ## Same-origin, which is the whole reason this works
 *
 * `hkp-ops.js` resolves against `${location.origin}/pks/lookup` — "This site".
 * If the page fetched a keyserver on another port it would be cross-origin,
 * `connect-src 'self'` would refuse it, and the suite would be testing a
 * relaxed policy instead of the shipped one. So `routes` **proxies** rather
 * than redirects: the browser sees one origin, the loopback file server, and
 * every directory request is forwarded to Flask and piped back. Nothing about
 * the page's policy changes.
 *
 * ## What may skip, and what may not
 *
 * `ssh-format.test.js`'s lesson, applied to an interpreter instead of a
 * browser: **only an absent Python or an uninstalled dependency stands the
 * suite down.** An interpreter that is present and a server that will not
 * start is a real failure and is reported as one, with whatever the process
 * wrote before it died — because a harness that filed "the app raised on
 * boot" under "no Python" would skip itself green on the day the server broke.
 *
 * @module test/helpers/basilisk-server
 */

import { spawn } from "node:child_process";
import { createServer, request as httpRequest } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/** Repo root — `web/src/test/helpers/` is four levels down from it. */
export const REPO_ROOT = fileURLToPath(new URL("../../../../", import.meta.url));

/** Paths the page must reach on the real server rather than in `dist/`. */
export const PROXIED_PREFIXES = ["/pks/", "/api/v1/", "/claim/", "/.well-known/"];

/**
 * The interpreter to run, preferring the repo's virtualenv.
 *
 * A bare `python` on PATH is very unlikely to have `pysequoia` — the ingest
 * path's OpenPGP parser and a compiled dependency — so the venv is checked
 * first and the fallbacks exist only so the *classifier* can report what was
 * wrong rather than nothing being tried.
 *
 * @returns {string[]} candidate executables, best first
 */
export function pythonCandidates() {
  const venv = [
    join(REPO_ROOT, ".venv", "Scripts", "python.exe"),
    join(REPO_ROOT, ".venv", "bin", "python"),
  ].filter((p) => existsSync(p));
  return [...venv, "python3", "python"];
}

/**
 * What a failed interpreter probe means: nothing installed, or something
 * broken. Pure and exported so both branches can be asserted, because an
 * environment only ever exercises one of them.
 *
 * @param {string} message
 * @returns {"absent"|"broken"}
 */
export function classifyPythonFailure(message) {
  const m = String(message);
  // No interpreter at all.
  if (/ENOENT/.test(m)) return "absent";
  if (/is not recognized as an internal or external command/i.test(m)) return "absent";
  if (/command not found/i.test(m)) return "absent";
  // An interpreter, but the server's dependencies were never installed.
  if (/ModuleNotFoundError|ImportError|No module named/.test(m)) return "absent";
  // Anything else — a syntax error in the app, a DLL that will not load, a
  // permission refusal — is the environment failing and must not skip.
  return "broken";
}

/**
 * @param {string} exe
 * @param {string[]} args
 * @param {{ env?: Record<string, string>, timeout?: number }} [opts]
 * @returns {Promise<{ code: number|null, stdout: string, stderr: string }>}
 */
function run(exe, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(exe, args, {
      cwd: REPO_ROOT,
      env: { ...process.env, ...(opts.env || {}) },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    if (opts.timeout) {
      setTimeout(() => child.kill(), opts.timeout).unref?.();
    }
  });
}

/**
 * Whether the real server can be run at all.
 *
 * Imports the app and its OpenPGP parser rather than merely checking that an
 * interpreter answers `--version`: a Python without `pysequoia` looks fine to
 * `--version` and fails on the first upload.
 *
 * @returns {Promise<{ ok: boolean, python: string, reason: string, kind: ""|"absent"|"broken" }>}
 */
export async function basiliskAvailability() {
  /** @type {string[]} */
  const tried = [];
  for (const exe of pythonCandidates()) {
    let result;
    try {
      result = await run(exe, ["-c", "import flask, pysequoia, basilisk.serve"], {
        timeout: 60000,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      tried.push(`${exe}: ${msg}`);
      if (classifyPythonFailure(msg) === "broken") {
        return { ok: false, python: exe, reason: msg, kind: "broken" };
      }
      continue;
    }
    if (result.code === 0) return { ok: true, python: exe, reason: "", kind: "" };
    const msg = `${result.stderr || result.stdout}`.trim();
    tried.push(`${exe}: ${msg.split("\n").pop()}`);
    if (classifyPythonFailure(msg) === "broken") {
      return { ok: false, python: exe, reason: msg, kind: "broken" };
    }
  }
  return {
    ok: false,
    python: "",
    reason: `no python could import the server: ${tried.join("; ")}`,
    kind: "absent",
  };
}

/** A free TCP port, released immediately before Flask claims it. */
function freePort() {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = /** @type {import("node:net").AddressInfo} */ (probe.address());
      probe.close(() => resolve(port));
    });
  });
}

/**
 * Azure Easy Auth's client principal header, forged.
 *
 * Not a hole cut for the tests: `basilisk/auth/azure.py` refuses a forged
 * principal unless `BASILISK_DEV_AUTH` is set, which this harness sets and
 * production does not. Without it there is no way to reach
 * `POST /api/v1/me/keys` at all, and that is the branch of `publishArmoredKey`
 * a signed-in person takes.
 *
 * @param {{ email: string, name?: string }} user
 * @returns {Record<string, string>}
 */
export function easyAuthHeaders(user) {
  const claims = [
    {
      typ: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
      val: user.email,
    },
    { typ: "http://schemas.microsoft.com/identity/claims/objectidentifier", val: "e2e-oid" },
    { typ: "name", val: user.name || user.email },
  ];
  return {
    "x-ms-client-principal": Buffer.from(
      JSON.stringify({ claims }),
      "utf8"
    ).toString("base64"),
    // The trusted-edge marker; a principal header alone is refused.
    "x-ms-client-principal-id": "e2e-oid",
    "x-ms-client-principal-idp": "aad",
  };
}

/**
 * @typedef {object} BasiliskServer
 * @property {string} origin          where Flask is listening
 * @property {string} dataDir         the temp dir its SQLite file and blobs live in
 * @property {(req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => boolean} routes
 *   `serveDist`'s hook: proxies the directory paths, declines everything else.
 * @property {() => Record<string, number>} counts
 * @property {() => { method: string, path: string, query: string }[]} requests
 * @property {() => void} resetCounts
 * @property {(user: { email: string, name?: string }|null) => void} signIn
 * @property {() => string} log       everything the process has written
 * @property {() => Promise<void>} close
 */

/**
 * Start the server on a free loopback port and wait for `/health`.
 *
 * @param {object} [opts]
 * @param {string} [opts.python]        interpreter, from `basiliskAvailability()`
 * @param {boolean} [opts.rejectRevoked]
 *   Basilisk refuses a revoked key at upload by default
 *   (`BASILISK_REJECT_REVOKED`). Pass `false` to model a directory holding a
 *   key that was revoked *after* it was accepted, which is the only way that
 *   state is reachable and is what a client has to cope with.
 * @param {number} [opts.timeout]       readiness deadline, ms
 * @returns {Promise<BasiliskServer>}
 */
export async function startBasilisk(opts = {}) {
  const python = opts.python || (await basiliskAvailability()).python;
  if (!python) throw new Error("startBasilisk: no usable python");

  const port = await freePort();
  const dataDir = await mkdtemp(join(tmpdir(), "basilisk-e2e-"));
  const origin = `http://127.0.0.1:${port}`;

  const child = spawn(
    python,
    ["-m", "basilisk.serve", "--host", "127.0.0.1", "--port", String(port)],
    {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        // Unset, so `db/factory.py` chooses SqliteCertStore + LocalBlobStore.
        AZURE_STORAGE_CONNECTION_STRING: "",
        BASILISK_BASE_URL: origin,
        BASILISK_DB_PATH: join(dataDir, "basilisk.db"),
        BASILISK_BLOB_PATH: join(dataDir, "blobs"),
        BASILISK_TOKEN_SECRET: "browser-e2e-secret",
        // The no-authentication approval route the seeding path needs.
        BASILISK_DEV_APPROVE: "1",
        // Accept a forged Easy Auth principal; refused without this.
        BASILISK_DEV_AUTH: "1",
        BASILISK_UPLOAD_RATE_LIMIT_SEC: "0",
        BASILISK_UPLOAD_FPR_RATE_LIMIT_SEC: "0",
        BASILISK_SENDTOKEN_RATE_LIMIT_SEC: "0",
        BASILISK_LOOKUP_RATE_LIMIT_SEC: "0",
        ...(opts.rejectRevoked === false ? { BASILISK_REJECT_REVOKED: "0" } : {}),
        PYTHONUNBUFFERED: "1",
      },
    }
  );

  let log = "";
  child.stdout.on("data", (d) => (log += d));
  child.stderr.on("data", (d) => (log += d));
  /** @type {Error|null} */
  let died = null;
  child.on("error", (err) => (died = err));
  child.on("close", (code) => {
    if (code !== 0 && code !== null) {
      died = died || new Error(`basilisk exited with code ${code}`);
    }
  });

  const deadline = Date.now() + (opts.timeout || 60000);
  let ready = false;
  while (Date.now() < deadline) {
    if (died) break;
    try {
      const r = await fetch(`${origin}/health`);
      if (r.ok) {
        ready = true;
        break;
      }
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  if (!ready) {
    child.kill();
    await rm(dataDir, { recursive: true, force: true }).catch(() => {});
    // Everything the process said, not a timeout with no cause.
    throw new Error(
      `basilisk did not answer /health${died ? ` (${died.message})` : ""}:\n${log.trim() || "(no output)"}`
    );
  }

  /** @type {Record<string, number>} */
  let counts = Object.create(null);
  /** @type {{ method: string, path: string, query: string }[]} */
  const requests = [];
  /** @type {{ email: string, name?: string }|null} */
  let user = null;

  /** @param {string} name */
  function bump(name) {
    counts[name] = (counts[name] || 0) + 1;
  }

  /**
   * Name a request the way an assertion wants to read it — `lookup.get`,
   * `lookup.index`, `key`, `search`, `add`, `me`, `me.keys`.
   * @param {string} method @param {string} path @param {URLSearchParams} params
   */
  function label(method, path, params) {
    if (path === "/pks/lookup") return `lookup.${params.get("op") || "get"}`;
    if (path === "/pks/add") return "add";
    if (path === "/api/v1/search") return "search";
    if (path === "/api/v1/me") return "me";
    if (path === "/api/v1/me/keys") return "me.keys";
    if (path.startsWith("/api/v1/key/")) return "key";
    if (path.startsWith("/api/v1/dev/")) return "dev";
    return `${method.toLowerCase()} ${path}`;
  }

  /**
   * @param {import("node:http").IncomingMessage} req
   * @param {import("node:http").ServerResponse} res
   * @returns {boolean}
   */
  function routes(req, res) {
    const raw = req.url || "/";
    const [path, query = ""] = raw.split("?");
    if (!PROXIED_PREFIXES.some((p) => path.startsWith(p))) return false;

    const method = String(req.method || "GET").toUpperCase();
    requests.push({ method, path, query });
    bump(label(method, path, new URLSearchParams(query)));

    const headers = { ...req.headers };
    delete headers.host;
    delete headers.connection;
    // Never let a page-supplied principal through; only the harness may sign in.
    for (const k of Object.keys(headers)) {
      if (k.toLowerCase().startsWith("x-ms-client-principal")) delete headers[k];
    }
    const upstream = httpRequest(
      {
        host: "127.0.0.1",
        port,
        method,
        path: raw,
        headers: { ...headers, host: `127.0.0.1:${port}`, ...(user ? easyAuthHeaders(user) : {}) },
      },
      (up) => {
        res.writeHead(up.statusCode || 502, up.headers);
        up.pipe(res);
      }
    );
    upstream.on("error", (err) => {
      // A proxy that swallowed this would look like the directory answering
      // "not found", which is the mistranslation worth avoiding.
      res.writeHead(502, { "content-type": "text/plain" });
      res.end(`basilisk proxy failed: ${err.message}`);
    });
    req.pipe(upstream);
    return true;
  }

  return {
    origin,
    dataDir,
    routes,
    counts: () => ({ ...counts }),
    requests: () => requests.slice(),
    resetCounts: () => {
      counts = Object.create(null);
    },
    signIn: (u) => {
      user = u;
    },
    log: () => log,
    close: async () => {
      child.kill();
      await new Promise((r) => setTimeout(r, 100));
      await rm(dataDir, { recursive: true, force: true }).catch(() => {});
    },
  };
}

/**
 * @typedef {object} SeedOutcome
 * @property {string[]} approved   ids that were ingested and approved
 * @property {string[]} pending    ids ingested and deliberately left unapproved
 * @property {{ id: string, status: number, body: string }[]} refused
 *   ids the server would not accept, with its own words
 */

/**
 * Put a corpus into the directory through the server's real ingest path.
 *
 * `POST /pks/add` then `POST /api/v1/dev/approve`, which is exactly what
 * `tests/helpers/hkp_client.py` does for the Python e2e — the same two calls,
 * so both suites populate a directory the same way. Going through ingest means
 * the corpus is validated by the policy that runs in production; direct SQLite
 * writes would be faster and would skip that.
 *
 * Refusals are returned, not thrown: a key the server declines is a fact about
 * the server worth asserting, and `grace` is refused by design.
 *
 * @param {BasiliskServer} server
 * @param {import("./key-corpus.js").CorpusKey[]} keys
 * @returns {Promise<SeedOutcome>}
 */
export async function seedDirectory(server, keys) {
  /** @type {SeedOutcome} */
  const out = { approved: [], pending: [], refused: [] };
  for (const key of keys) {
    const add = await fetch(`${server.origin}/pks/add`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `keytext=${encodeURIComponent(key.armoredPublic)}`,
    });
    const body = (await add.text()).trim();
    if (!add.ok) {
      out.refused.push({ id: key.id, status: add.status, body });
      continue;
    }
    if (key.approvalState !== "approved") {
      out.pending.push(key.id);
      continue;
    }
    const approve = await fetch(`${server.origin}/api/v1/dev/approve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fingerprint: key.fingerprint, approved_uids: key.uids }),
    });
    if (!approve.ok) {
      out.refused.push({
        id: key.id,
        status: approve.status,
        body: (await approve.text()).trim(),
      });
      continue;
    }
    out.approved.push(key.id);
  }
  server.resetCounts();
  return out;
}
