/**
 * After SRI + importmap externalization, write /integrity/module-roots.json
 * and inject pin <meta> tags so the runtime POST can cross-check the live
 * Merkle root against an independently cacheable pin document (and optional
 * mirrors on other CDNs / origins).
 */
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { basename, join } from "node:path";
import {
  collectSriLeavesFromHtml,
  rootFromLeaves,
} from "../src/lib/module-integrity.js";

/**
 * @param {string} outDir
 * @param {{ mirrors?: string[] }} [opts]
 */
export async function writeModuleIntegrityPins(outDir, opts = {}) {
  if (!existsSync(outDir)) return { pages: 0, path: "" };

  const mirrors = (opts.mirrors || []).map((s) => s.trim()).filter(Boolean);
  /** @type {Record<string, { root: string, leafCount: number }>} */
  const pages = {};

  const htmlFiles = readdirSync(outDir).filter((n) => n.endsWith(".html"));
  for (const name of htmlFiles) {
    const htmlPath = join(outDir, name);
    let html = readFileSync(htmlPath, "utf8");
    const leaves = await collectSriLeavesFromHtml(html, (src) => {
      const rel = src.replace(/^\//, "");
      const path = join(outDir, rel);
      if (!existsSync(path)) return null;
      return readFileSync(path, "utf8");
    });
    const { root, leafCount } = await rootFromLeaves(leaves);
    pages[name] = { root, leafCount };

    const pinUrls = ["/integrity/module-roots.json", ...mirrors];
    const pinsMeta = `  <meta name="basilisk-integrity-pins" content="${pinUrls.join(" ")}">\n`;
    const pageMeta = `  <meta name="basilisk-integrity-page" content="${name}">\n`;

    // Replace prior injects if re-run.
    html = html
      .replace(/\s*<meta name="basilisk-integrity-pins"[^>]*>\s*/gi, "\n")
      .replace(/\s*<meta name="basilisk-integrity-page"[^>]*>\s*/gi, "\n");

    if (mirrors.length) {
      html = html.replace(
        /(connect-src\s+)([^;"]+)/i,
        (_, prefix, existing) => {
          const parts = new Set(existing.trim().split(/\s+/).filter(Boolean));
          for (const m of mirrors) {
            try {
              parts.add(new URL(m).origin);
            } catch {
              /* relative mirrors stay on 'self' */
            }
          }
          return `${prefix}${[...parts].join(" ")}`;
        }
      );
    }

    if (/<head[^>]*>/i.test(html)) {
      html = html.replace(/<head[^>]*>/i, (h) => `${h}\n${pinsMeta}${pageMeta}`);
    } else {
      html = pinsMeta + pageMeta + html;
    }
    writeFileSync(htmlPath, html, "utf8");
  }

  const doc = {
    version: 1,
    algorithm: "sha256-merkle-v1",
    builtAt: new Date().toISOString(),
    pages,
  };
  const integrityDir = join(outDir, "integrity");
  mkdirSync(integrityDir, { recursive: true });
  const body = `${JSON.stringify(doc, null, 2)}\n`;
  const path = join(integrityDir, "module-roots.json");
  writeFileSync(path, body, "utf8");

  // Content-addressed copy for operators mirroring to other CDNs.
  const digest = createHash("sha256").update(body).digest("hex").slice(0, 16);
  writeFileSync(join(integrityDir, `module-roots-${digest}.json`), body, "utf8");

  return { pages: Object.keys(pages).length, path: basename(path), digest };
}
