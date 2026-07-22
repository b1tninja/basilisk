/**
 * Vite plugin: externalize vite-plugin-sri-gen inline import maps.
 *
 * Why: CSP is `script-src 'self'` (no unsafe-inline). An inline
 * `<script type="importmap">` is blocked, so production packaging used to
 * *strip* the map — which dropped integrity coverage for lazy chunks,
 * dynamic `import()`, and module workers. An external importmap at
 * `/importmaps/importmap-….json` is allowed by `'self'` and can itself carry
 * an `integrity=` attribute. The map’s `"integrity": { url: sha384-… }`
 * object is what the browser uses to refuse mismatched CDN bytes for the
 * rest of the module graph (cache skew or tampering).
 *
 * Paths are intentionally *outside* `/assets/` so Front Door’s long-lived
 * hashed-asset cache rule does not pin a stale integrity map for 7 days.
 *
 * Do not reintroduce stripping of import maps without replacing this path.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/HTML/Element/script/type/importmap
 * @see https://www.w3.org/TR/SRI/
 */
import { createHash } from "node:crypto";
import {
  readdirSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
} from "node:fs";
import { join } from "node:path";

const INLINE_IMPORTMAP =
  /<script type="importmap">(\{[\s\S]*?\})<\/script>/;

/**
 * @param {string} outDir  Absolute path to Vite outDir (e.g. …/web/dist)
 */
export function externalizeImportMapsInDist(outDir) {
  const mapDir = join(outDir, "importmaps");
  if (!existsSync(outDir)) return { rewritten: 0, files: [] };

  mkdirSync(mapDir, { recursive: true });
  /** @type {string[]} */
  const files = [];
  let rewritten = 0;

  for (const name of readdirSync(outDir)) {
    if (!name.endsWith(".html")) continue;
    const htmlPath = join(outDir, name);
    const text = readFileSync(htmlPath, "utf8");
    const match = INLINE_IMPORTMAP.exec(text);
    if (!match) continue;

    const jsonBody = match[1];
    // Round-trip through JSON.parse to reject truncated / malformed maps.
    JSON.parse(jsonBody);
    const raw = Buffer.from(jsonBody, "utf8");
    const digest = createHash("sha384").update(raw).digest();
    const integrity = `sha384-${digest.toString("base64")}`;
    const short = digest.subarray(0, 8).toString("hex");
    const assetName = `importmap-${short}.json`;
    writeFileSync(join(mapDir, assetName), raw);

    const tag =
      `<script type="importmap" src="/importmaps/${assetName}" ` +
      `integrity="${integrity}" crossorigin="anonymous"></script>`;
    writeFileSync(htmlPath, text.replace(INLINE_IMPORTMAP, tag), "utf8");
    files.push(assetName);
    rewritten += 1;
  }

  return { rewritten, files };
}

/**
 * @returns {import("vite").Plugin}
 */
export function basiliskExternalizeImportMaps() {
  let outDir = "dist";
  return {
    name: "basilisk-externalize-importmaps",
    apply: "build",
    enforce: "post",
    configResolved(config) {
      outDir = config.build.outDir;
      if (!outDir.startsWith("/") && !/^[A-Za-z]:/.test(outDir)) {
        outDir = join(config.root, outDir);
      }
    },
    closeBundle() {
      const { rewritten, files } = externalizeImportMapsInDist(outDir);
      if (rewritten) {
        console.info(
          `[sri] externalized ${rewritten} importmap(s): ${files.join(", ")}`
        );
      }
    },
  };
}
