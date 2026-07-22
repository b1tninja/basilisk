/**
 * Externalize-importmaps helper (build packaging).
 */
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { externalizeImportMapsInDist } from "../../scripts/externalize-importmaps.js";

describe("externalizeImportMapsInDist", () => {
  it("rewrites inline importmap to an SRI’d external script", () => {
    const dir = mkdtempSync(join(tmpdir(), "basilisk-imap-"));
    try {
      const map = JSON.stringify({
        integrity: {
          "/assets/foo-abc.js": "sha384-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        },
      });
      writeFileSync(
        join(dir, "index.html"),
        `<!DOCTYPE html><html><head><script type="importmap">${map}</script>` +
          `<script type="module" src="/assets/index.js" integrity="sha384-x"></script></head></html>`,
        "utf8"
      );

      const result = externalizeImportMapsInDist(dir);
      expect(result.rewritten).toBe(1);
      expect(result.files).toHaveLength(1);

      const html = readFileSync(join(dir, "index.html"), "utf8");
      expect(html).not.toContain("<script type=\"importmap\">{");
      expect(html).toMatch(
        /<script type="importmap" src="\/importmaps\/importmap-[0-9a-f]+\.json" integrity="sha384-[A-Za-z0-9+/=]+" crossorigin="anonymous"><\/script>/
      );
      expect(html).toContain('integrity="sha384-x"');

      const file = result.files[0];
      const raw = readFileSync(join(dir, "importmaps", file));
      expect(raw.toString("utf8")).toBe(map);
      const expected =
        "sha384-" + createHash("sha384").update(raw).digest("base64");
      expect(html).toContain(`integrity="${expected}"`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
