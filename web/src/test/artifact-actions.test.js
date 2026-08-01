/**
 * Artifact actions: tiers, disabled reasons, and the mask (§33b/§33d/§34b).
 *
 * The tiers encode what happens if you click — local, durable, or outward and
 * possibly irreversible — so flattening them into equal buttons is how a
 * mis-click becomes unrecoverable. The reason strings are the feature, not an
 * afterthought, which makes both their wording and their *readability* worth
 * asserting.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ACTION_REASONS } from "../lib/toolkit/artifact-reasons.js";
import {
  ARTIFACT_ACTIONS,
  actionById,
  actionsFor,
  downloadMimeFor,
  downloadNameFor,
} from "../lib/toolkit/artifact-actions.js";
import { downloadArtifactFile } from "../lib/toolkit/download-service.js";
import "../lib/toolkit/registry.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";
import { ARTIFACT_KINDS, FALLBACK_KIND } from "../toolkit/artifact-kinds/registry.tsx";
import { resolveArtifactKind } from "../toolkit/artifact-kinds/resolve.ts";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const ACTION = read("../toolkit/widgets/ArtifactAction.tsx");
const SHELL = read("../toolkit/ToolkitShell.tsx");
const CSS = read("../css/toolkit.css");
const SRC = read("../lib/toolkit/artifact-actions.js");
const TOOLKIT_HTML = read("../../toolkit.html");
const DOWNLOAD = read("../lib/toolkit/download-service.js");

/**
 * Comments stripped before any assertion about an *absent* symbol.
 *
 * This has now cost this feature area four separate false passes: the prose
 * explaining why a symbol is absent sits next to the absence and satisfies the
 * naive grep. `activity-log.test.js` established the helper; this is the same
 * one.
 */
const stripComments = (t) =>
  t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

describe("a disabled action always carries a reason (§33d)", () => {
  it("derives disabled from the reason, so the two cannot drift apart", () => {
    // Not two independent props. "Disabled but no reason" should be
    // unrepresentable, because that state is the thing the rule forbids.
    expect(ACTION).toMatch(/const disabled = !!reason;/);
    expect(ACTION).toMatch(/disabled=\{disabled\}/);
  });

  it("exposes the reason to assistive tech, not only as a title", () => {
    // `title` is unreachable by keyboard and by touch, so a title-only reason
    // is a reason most affected users never get.
    expect(ACTION).toMatch(/aria-describedby=\{reasonId\}/);
    expect(ACTION).toMatch(/className="sr-only"/);
  });

  it("writes every reason as a sentence with a remedy where one exists", () => {
    for (const [key, text] of Object.entries(ACTION_REASONS)) {
      expect(text.length, key).toBeGreaterThan(30);
      expect(text, key).toMatch(/[.!]$/);
      // "Unavailable" restates the disabled attribute; it is not a reason.
      expect(text.toLowerCase(), key).not.toBe("unavailable");
    }
  });

  it("keeps the wording verbatim, because the wording is the feature", () => {
    expect(ACTION_REASONS.maskedButRevealable).toBe(
      "Reveal this value first — a masked value cannot be copied."
    );
    expect(ACTION_REASONS.neverAskedFor).toBe(
      "This value was not asked for. Add `out @label` to the recipe to see or copy it."
    );
    expect(ACTION_REASONS.noVault).toBe(
      "My Keys is unavailable in this browser (no IndexedDB)."
    );
    expect(ACTION_REASONS.offline).toBe(
      "Publishing needs a connection to this site's directory."
    );
  });
});

describe("disabled does not dim (§41d)", () => {
  it("holds full-strength muted text instead of halving opacity", () => {
    // The shipped `disabled:opacity-50` puts the reason at 2.20:1 in light.
    // A reason nobody can read is the same as no reason — the exact failure
    // §33d exists to prevent, and the same class of defect the last polish
    // pass found here at 1.97:1 and 1.59:1.
    const rule = CSS.match(/\.artifact-action:disabled\s*\{[^}]*\}/);
    expect(rule, ".artifact-action:disabled rule not found").toBeTruthy();
    expect(rule[0]).toMatch(/opacity:\s*1/);
    expect(rule[0]).toMatch(/color:\s*var\(--muted-foreground\)/);
    expect(rule[0]).toMatch(/cursor:\s*not-allowed/);
    // The affordance is what goes away: no fill, no border.
    expect(rule[0]).toMatch(/background:\s*transparent/);
    expect(rule[0]).toMatch(/border-color:\s*transparent/);
  });

  it("marks that a reason is attached, so it reads as explained not broken", () => {
    const rule = CSS.match(/\.artifact-action:disabled\s*\{[^}]*\}/);
    expect(rule[0]).toMatch(/text-decoration:\s*underline dotted/);
  });
});

describe("the three tiers are declared, not styled per call site (§33b)", () => {
  it("enumerates exactly inert, local and outward", () => {
    const tiers = [...CSS.matchAll(/\.artifact-action\[data-action-tier="([a-z]+)"\]/g)].map(
      (m) => m[1]
    );
    expect([...new Set(tiers)].sort()).toEqual(["inert", "local", "outward"]);
  });

  it("gives outward an outline rather than a fill", () => {
    // The shipped --warn *fill* measures 3.76:1 in light. The outline keeps
    // the promise the colour makes — "this leaves the machine" — without it.
    const outward = CSS.match(/\.artifact-action\[data-action-tier="outward"\]\s*\{[^}]*\}/);
    expect(outward[0]).toMatch(/background:\s*transparent/);
    expect(outward[0]).toMatch(/border-color:\s*color-mix\(in srgb, var\(--warn\)/);
  });

  it("runs its hover tint through the per-theme token", () => {
    expect(CSS).toMatch(
      /\.artifact-action\[data-action-tier="outward"\]:hover[^}]*var\(--tile-tint\)/
    );
  });
});

describe("in-flight is busy, not disabled (§41e)", () => {
  it("uses aria-busy so the accessible name survives", () => {
    // A disabled control loses its accessible name in some screen-reader
    // pairings at exactly the moment the user most wants to know what is
    // happening.
    expect(ACTION).toMatch(/aria-busy=\{busy \|\| undefined\}/);
    expect(ACTION).not.toMatch(/disabled=\{busy/);
  });

  it("slows the spinner under reduced motion rather than freezing it", () => {
    // A frozen spinner reads as a hang.
    const rm = CSS.match(/@media \(prefers-reduced-motion: reduce\)\s*\{[\s\S]*?artifact-action-spin[\s\S]*?\}\s*\}/);
    expect(rm, "reduced-motion rule not found").toBeTruthy();
    expect(rm[0]).toMatch(/animation-duration:\s*2\.4s/);
    expect(rm[0]).not.toMatch(/animation:\s*none/);
  });
});

describe("Copy is gated on the mask, never bypasses it (§34b)", () => {
  // Asserted against the table, which is where the decision lives now —
  // behaviourally, so a refactor of the tile cannot silently drop it.
  const copy = actionById("copy");

  it("is available on an unmasked artifact", () => {
    expect(copy.available({ artifact: { content: "x" }, masked: false })).toBe(true);
  });

  it("disables rather than revealing on the user's behalf", () => {
    const out = copy.available({
      artifact: { content: "secret", revealable: true },
      masked: true,
    });
    expect(out).not.toBe(true);
    expect(out.disabled).toBe(ACTION_REASONS.maskedButRevealable);
    // No code path may lift the mask from inside an action.
    expect(SRC).not.toMatch(/setRevealed|revealed\s*=\s*true/);
  });

  it("distinguishes 'reveal it first' from 'the recipe never asked'", () => {
    const revealable = copy.available({
      artifact: { content: "secret", revealable: true },
      masked: true,
    });
    const never = copy.available({
      artifact: { content: "secret", revealable: false },
      masked: true,
    });
    expect(revealable.disabled).toBe(ACTION_REASONS.maskedButRevealable);
    expect(never.disabled).toBe(ACTION_REASONS.neverAskedFor);
  });

  it("copies through the artifact's own handler, not a re-implementation", async () => {
    // The shipped handler fires the clipboard toast and knows this
    // artifact's serialization; the table exists to make gating uniform,
    // not to rewrite behaviour.
    let called = 0;
    await copy.run({ services: { copyArtifact: () => { called++; } } });
    expect(called).toBe(1);
  });
});

describe("Download is Copy's other destination, gated the same way (§34b)", () => {
  const download = actionById("download");

  it("is inert, like the tier doc has always said it would be", () => {
    // `ArtifactAction.tsx` has documented the inert tier as "(Copy, Download)"
    // since the tiers landed, while no download button existed anywhere. The
    // sentence is now true rather than aspirational, which is what makes it
    // worth pinning.
    expect(download.tier).toBe("inert");
    expect(download.label).toBe("Download");
    expect(ACTION).toMatch(/inert\s+— local, reversible, no state changes \(Copy, Download\)/);
  });

  it("is available on an unmasked artifact with a body", () => {
    expect(download.available({ artifact: { content: "x" }, masked: false })).toBe(true);
  });

  it("refuses a masked value in Copy's own words, not paraphrased", () => {
    // The same refusal, so the same two sentences: writing a masked secret to
    // disk is the same exfiltration as copying it, and revealing on the user's
    // behalf to permit it is the same mask bypass.
    for (const artifact of [
      { content: "secret", revealable: true },
      { content: "secret", revealable: false },
      { content: "" },
    ]) {
      expect(download.available({ artifact, masked: true })).toEqual(
        actionById("copy").available({ artifact, masked: true })
      );
    }
    expect(
      download.available({ artifact: { content: "s", revealable: true }, masked: true }).disabled
    ).toBe(ACTION_REASONS.maskedButRevealable);
    expect(
      download.available({ artifact: { content: "s", revealable: false }, masked: true }).disabled
    ).toBe(ACTION_REASONS.neverAskedFor);
  });

  it("does not invert the contrast with Add to My Keys", () => {
    // `keyring.add` is *enabled* while masked, deliberately: it moves the
    // secret into storage without ever displaying it. Download leaves, so it
    // is gated. Getting these two the same way round is the whole of §34b.
    const jwk = JSON.stringify({ kty: "OKP", crv: "Ed25519", x: "aa", d: "bb" });
    const artifact = { content: jwk, revealable: true };
    const vault = { add: async () => ({ fingerprint: "SHA256:x", already: false }) };
    expect(actionById("keyring.add").available({ artifact, masked: true, services: { vault } })).toBe(
      true
    );
    expect(download.available({ artifact, masked: true })).not.toBe(true);
  });

  it("refuses an empty body rather than writing a 0-byte file", () => {
    // A 0-byte download that looks like a successful key export is the outcome
    // worth refusing — Copy can silently write "" to the clipboard and nobody
    // keeps it; a file gets kept.
    expect(download.available({ artifact: { content: "" }, masked: false })).toEqual({
      disabled: ACTION_REASONS.nothingToSave,
    });
    expect(ACTION_REASONS.nothingToSave).toBe(
      "This artifact has no body to save — the step that produced it emitted nothing."
    );
  });

  it("asks nothing first — §34c's banner is for what leaves the machine", () => {
    // A confirmation on every save would teach that the banner is decorative,
    // which is the one thing that would make the Publish banner worthless.
    expect(download.confirm).toBeUndefined();
  });

  it("reports the filename, so the Activity log can name where it went", async () => {
    const calls = [];
    const res = await download.run({
      artifact: { content: "body", filename: "public.asc", mime: "application/pgp-keys" },
      kind: FALLBACK_KIND,
      services: { download: (f) => calls.push(f) },
    });
    expect(res).toEqual({ receipt: "Downloaded", detail: "public.asc" });
    expect(calls).toEqual([
      { name: "public.asc", content: "body", mime: "application/pgp-keys" },
    ]);
  });

  it("reaches no browser surface of its own — the service is injected", () => {
    const code = stripComments(SRC);
    expect(code).not.toMatch(/document\./);
    expect(code).not.toMatch(/createObjectURL/);
    expect(code).not.toMatch(/new Blob/);
    expect(code).toMatch(/services\.download\(/);
  });
});

describe("the filename is the feature: one namer, corrected per kind", () => {
  /** Run a recipe and pair every artifact with the kind that claims it. */
  const tiles = async (src, bindings = {}) => {
    const { ast } = compileRecipe(src);
    const arts = await runRecipe(ast, bindings);
    return arts.map((a) => ({
      artifact: a,
      kind: resolveArtifactKind(a, ARTIFACT_KINDS, FALLBACK_KIND),
    }));
  };
  const nameOf = (rows, kindId) => {
    const row = rows.find((r) => r.kind.id === kindId);
    expect(row, `no ${kindId} tile in this run`).toBeTruthy();
    return downloadNameFor(row.artifact, row.kind);
  };

  it("uses the engine's own name rather than a second scheme", () => {
    // `materializeOutArtifacts` already computes `filename` for everything it
    // emits. Two namers that can disagree about the same object is the failure
    // mode; the stem is always the engine's.
    expect(SRC).toMatch(/artifact\?\.filename/);
    expect(downloadNameFor({ filename: "kp-private.jwk.json" })).toBe("kp-private.jwk.json");
    // Multi-part extensions are the whole extension, not a dotted stem.
    expect(downloadNameFor({ filename: "msg.bin.b64" })).toBe("msg.bin.b64");
    expect(downloadNameFor({ filename: "peek.inspect.txt" })).toBe("peek.inspect.txt");
  });

  it("names an OpenPGP pair public.asc and k.asc, as the engine did", async () => {
    const rows = await tiles('gpg.genkey email="a@b.c" | out @k');
    expect(nameOf(rows, "openpgp-public")).toBe("public.asc");
    expect(nameOf(rows, "openpgp-private")).toBe("k.asc");
  });

  it("keeps a JWK a .jwk.json on both halves", async () => {
    const rows = await tiles("genkey ed25519 | out @kp");
    expect(nameOf(rows, "keypair-private")).toBe("kp-private.jwk.json");
    expect(nameOf(rows, "keypair-public")).toBe("kp-public.jwk.json");
  });

  it("corrects an sshsig block from .txt to .sig, which is the point", async () => {
    // An sshsig block is `text` on the wire, so `out` can only call it
    // `sig.txt`. `ssh-keygen -Y verify` wants a `.sig` beside the file it
    // signed — the rename this action exists to save.
    const rows = await tiles(
      'genkey ed25519 | tee\n  - :public | ssh.encode | out @pub\n| out @id\n\n"msg" | ssh.sign key=@id namespace=git | out @sig'
    );
    expect(nameOf(rows, "sshsig")).toBe("sig.sig");
    expect(ARTIFACT_KINDS.find((k) => k.id === "sshsig").download).toEqual({ ext: "sig" });
  });

  it("gives a QR an .svg and the SVG content type", async () => {
    const rows = await tiles('"hello" | qr');
    expect(nameOf(rows, "qr")).toBe("artifact.svg");
    const row = rows.find((r) => r.kind.id === "qr");
    expect(downloadMimeFor(row.artifact, row.kind)).toBe("image/svg+xml");
  });

  it("leaves a receipt .txt, because a signed one is not JSON", async () => {
    // `run.receipt` is JSON; `run.receipt | gpg.sign` is a clearsigned block,
    // and both are role `receipt`. A declared `.json` would be wrong for the
    // half the ceremony actually produces — which is why `download` on a kind
    // is a correction and not a naming scheme.
    const rows = await tiles('"hi" | out @msg\nrun.receipt | out @receipt');
    expect(nameOf(rows, "receipt")).toBe("receipt.txt");
    expect(ARTIFACT_KINDS.find((k) => k.id === "receipt").download).toBeUndefined();
  });

  it("names ordinary text and an inspect dump after the slot that asked", async () => {
    expect(nameOf(await tiles('"hi" | out @msg'), "text")).toBe("msg.txt");
    expect(nameOf(await tiles('"hi" | inspect'), "inspect-snapshot")).toBe("inspect.txt");
  });

  it("falls back to the label, never to a bare 'artifact.txt', where it can", () => {
    // Catalog fixtures and any future emit site that forgets a filename.
    expect(downloadNameFor({ label: "kp · private JWK" })).toBe("kp-private-jwk.txt");
    expect(downloadNameFor({})).toBe("artifact.txt");
    // A kind's extension still applies to the fallback stem.
    expect(downloadNameFor({ label: "sig" }, { download: { ext: "sig" } })).toBe("sig.sig");
  });

  it("keeps a path out of the download name", () => {
    // `sanitizeFilename` is the existing helper, not a fourth one.
    expect(downloadNameFor({ filename: "../../etc/passwd" })).not.toContain("/");
    expect(downloadNameFor({ label: "a/b\\c" })).toBe("a-b-c.txt");
  });

  it("takes the content type from the engine, corrected only where the name is", () => {
    expect(downloadMimeFor({ mime: "application/pgp-keys" })).toBe("application/pgp-keys");
    expect(downloadMimeFor({})).toBe("text/plain; charset=utf-8");
    expect(downloadMimeFor({ mime: "text/plain" }, { download: { ext: "svg", mime: "image/svg+xml" } })).toBe(
      "image/svg+xml"
    );
  });

  it("declares an extension only where it is true of the whole kind", () => {
    // Not a pile of special cases: every other kind's bodies are named
    // correctly by the pipeline already.
    const withExt = ARTIFACT_KINDS.filter((k) => k.download).map((k) => k.id);
    expect(withExt.sort()).toEqual(["qr", "sshsig"]);
  });
});

describe("the download mechanism: a blob, a click, and a revoke", () => {
  afterEach(async () => {
    // Drain the pending revoke before tearing the stubs down: the revoke is
    // deliberately on the next turn (it races the download start in Chromium
    // otherwise), so without this it lands in the *next* test's spy.
    await new Promise((r) => setTimeout(r, 1));
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  /** A `document`/`window`/`URL` triple, the `file-ops.test.js` shape. */
  function fakeDom() {
    const created = [];
    const attached = [];
    const saves = [];
    const revoked = [];
    vi.stubGlobal("document", {
      createElement: (tag) => {
        const el = {
          tagName: tag.toUpperCase(),
          clicked: 0,
          removed: false,
          click() {
            el.clicked++;
          },
          remove() {
            el.removed = true;
            const i = attached.indexOf(el);
            if (i >= 0) attached.splice(i, 1);
          },
        };
        created.push(el);
        return el;
      },
      body: { appendChild: (el) => attached.push(el) },
    });
    vi.stubGlobal("window", {
      dispatchEvent(ev) {
        if (ev?.type === "basilisk:file-saved") saves.push(ev.detail);
        return true;
      },
    });
    vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:stub");
    vi.spyOn(URL, "revokeObjectURL").mockImplementation((u) => revoked.push(u));
    return { created, attached, saves, revoked, last: () => created[created.length - 1] };
  }

  it("clicks an anchor with the name on it and detaches it again", async () => {
    const dom = fakeDom();
    await downloadArtifactFile({ name: "public.asc", content: "armor", mime: "application/pgp-keys" });
    const a = dom.last();
    expect(a.tagName).toBe("A");
    expect(a.download).toBe("public.asc");
    expect(a.href).toBe("blob:stub");
    expect(a.clicked).toBe(1);
    expect(a.removed).toBe(true);
    expect(dom.attached).toEqual([]);
  });

  it("revokes the object URL, because a leaked one is a live handle", async () => {
    // An un-revoked blob: URL to a private key is readable for the lifetime of
    // the document by anything that can reach the href.
    const dom = fakeDom();
    await downloadArtifactFile({ name: "kp-private.jwk.json", content: '{"d":"x"}' });
    await new Promise((r) => setTimeout(r, 1));
    expect(dom.revoked).toEqual(["blob:stub"]);
  });

  it("revokes even when the click throws", async () => {
    const dom = fakeDom();
    vi.stubGlobal("document", {
      createElement: () => ({
        click() {
          throw new Error("blocked");
        },
        remove() {},
      }),
      body: { appendChild: () => {} },
    });
    await expect(downloadArtifactFile({ name: "a.txt", content: "x" })).rejects.toThrow("blocked");
    await new Promise((r) => setTimeout(r, 1));
    expect(dom.revoked).toEqual(["blob:stub"]);
  });

  it("announces on file.save's channel rather than inventing a third weight", async () => {
    // The browser draws its own download UI, so the app's part is the same
    // light toast `file.save` uses — a modal would restate what just happened.
    const dom = fakeDom();
    await downloadArtifactFile({ name: "msg.txt", content: "hello" });
    expect(dom.saves).toEqual([{ name: "msg.txt", bytes: 5 }]);
    expect(SHELL).toMatch(/basilisk:file-saved/);
    expect(stripComments(DOWNLOAD)).not.toMatch(/basilisk:(?!file-saved)[a-z-]+/);
  });

  it("did not buy itself a CSP exemption", () => {
    // A `download` anchor starts a download, which no fetch directive governs
    // — so `default-src 'none'` stands and no `blob:` grant was needed. If a
    // future change makes one look necessary, that is the moment to stop.
    const policy = (TOOLKIT_HTML.match(/Content-Security-Policy"\s+content="([^"]+)"/) || [
      "",
      "",
    ])[1];
    expect(policy).toContain("default-src 'none'");
    expect(policy).not.toContain("blob:");
    expect(policy).not.toContain("sha256-");
  });
});

describe("the two user-visible promises of Download are now kept", () => {
  const TILE = read("../toolkit/widgets/ArtifactTile.tsx");

  it("backs the Activity panel's empty state with an action that exists", () => {
    // "Nothing yet. Copying, downloading or publishing an artifact records it
    // here." That sentence shipped before any download existed — a promise of
    // a feature that was not there. Both halves are asserted together so
    // neither can be edited into agreement with the other by deleting it.
    expect(SHELL).toMatch(/Copying, downloading or publishing an\s*\n?\s*artifact records it here/);
    const declared = new Set(ARTIFACT_KINDS.flatMap((k) => k.actions || []));
    expect(declared.has("download")).toBe(true);
    expect(actionById("download")).toBeTruthy();
    // And the logging it promises is the runner's, in one place, for every
    // action — nothing in the table logs for itself.
    expect(stripComments(SRC)).not.toMatch(/recordActivity/);
    expect((stripComments(TILE).match(/recordActivity\(/g) || []).length).toBe(1);
  });

  it("carries the engine's filename through both of the shell's mappings", () => {
    // This projection copies named fields, so a field it does not list is
    // dropped silently — which is exactly how `role`/`tags` went missing and
    // every tile resolved to the fallback in the live UI while the tests
    // passed. The tray and the cell list are both mappings.
    expect((SHELL.match(/filename: a\.filename,/g) || []).length).toBe(2);
    expect((SHELL.match(/mime: a\.mime,/g) || []).length).toBe(2);
    expect(read("../toolkit/useNotebook.ts")).toMatch(/filename: a\.filename,/);
    // And the tile type has to admit them, or TypeScript drops them again.
    expect(TILE).toMatch(/filename\?: string;/);
    expect(TILE).toMatch(/mime\?: string;/);
  });

  it("says nowhere that Download is still a tile-level affordance", () => {
    // Three comments in the kind table claimed it was, in a codebase where no
    // download button existed anywhere. Comments stripped is not the move
    // here — the false sentence *is* a comment, so this reads the raw file.
    const REGISTRY = read("../toolkit/artifact-kinds/registry.tsx");
    expect(REGISTRY).not.toMatch(/Expand and Download remain tile-level affordances/);
    expect(REGISTRY).not.toMatch(/It goes when\s*\n?\s*\* Download lands/);
    // The Expand half was accurate and stays.
    expect(REGISTRY).toMatch(/Expand remains a tile-level affordance/);
  });
});

describe("both panes badge an artifact the same way (§33a)", () => {
  it("uses one mapping expression, not two", () => {
    const mappings = [
      ...SHELL.matchAll(/kind: a\.role === "diagnostic" \? "diag" : a\.role \|\| "text"/g),
    ];
    // The cell list and the tray Outputs tab. Previously the cell list added
    // `publishable ? "key"` and collapsed the rest to "text", so the same
    // artifact wore two different badges depending on the pane.
    expect(mappings.length).toBe(2);
  });

  it("no longer re-derives publishability for the badge", () => {
    // `role` already says "public-key"; the ternary was re-deriving it and
    // disagreeing with the other pane.
    expect(SHELL).not.toMatch(/\? "share"[\s\S]{0,120}publishable\s*\n?\s*\? "key"/);
  });
});

describe("the table is the single definition (§33c)", () => {
  it("never returns a bare false — unavailable always carries a sentence", () => {
    // An action that cannot say why it is unavailable should not have been
    // declared by the kind at all; that is the kind's question, not this one's.
    for (const action of ARTIFACT_ACTIONS) {
      const out = action.available({ artifact: {}, masked: false });
      expect(out === true || typeof out?.disabled === "string", action.id).toBe(true);
      if (out !== true) expect(out.disabled.length, action.id).toBeGreaterThan(20);
    }
  });

  it("declares a tier for every action", () => {
    for (const a of ARTIFACT_ACTIONS) {
      expect(["inert", "local", "outward"], a.id).toContain(a.tier);
    }
  });

  it("imports no clipboard, vault, network or filesystem of its own", () => {
    // Services are injected so the table is testable with stubs and cannot
    // acquire a hidden dependency on a browser surface.
    expect(SRC).not.toMatch(/from "\.\.\/vault/);
    expect(SRC).not.toMatch(/navigator\./);
    expect(SRC).not.toMatch(/fetch\(/);
    expect(SRC).not.toMatch(/indexedDB/);
  });

  it("resolves every id a kind names", () => {
    // A kind naming an action with no definition is a silently missing
    // button — the tile must not be where that is discovered.
    for (const kind of ARTIFACT_KINDS) {
      for (const id of kind.actions || []) {
        expect(actionById(id), `${kind.id} names unknown action "${id}"`).toBeTruthy();
      }
      expect(actionsFor(kind).length).toBe((kind.actions || []).length);
    }
  });

  it("offers the key actions on key kinds and nowhere else", () => {
    const withPublicLine = ARTIFACT_KINDS.filter((k) =>
      (k.actions || []).includes("key.copyPublicLine")
    ).map((k) => k.id);
    // Absent on the private tile: the public half is one tile over, and on
    // non-key kinds entirely — SSH has no key type for a token or an sdp.
    expect(withPublicLine.sort()).toEqual(["key", "keypair-public"]);
  });
});

describe("the key actions against a real artifact", () => {
  /** The public half of a real generated keypair, as the engine emits it. */
  const publicHalf = async (alg) => {
    const { ast } = compileRecipe(`genkey ${alg} | out @kp`);
    const arts = await runRecipe(ast, {});
    return arts.find((a) => /public/.test(a.label));
  };

  it("copies a public line that is a real ssh-ed25519 line", async () => {
    const art = await publicHalf("ed25519");
    const action = actionById("key.copyPublicLine");
    expect(action.available({ artifact: art, masked: false })).toBe(true);
    let written = "";
    const res = await action.run({
      artifact: art,
      services: { clipboard: { write: (t) => { written = t; } } },
    });
    expect(written).toMatch(/^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5/);
    expect(res.receipt).toBe("Public line copied");
  });

  it("copies a fingerprint in ssh-keygen's own shape", async () => {
    const art = await publicHalf("ed25519");
    let written = "";
    await actionById("key.copyFingerprint").run({
      artifact: art,
      services: { clipboard: { write: (t) => { written = t; } } },
    });
    // SHA256: + 43 chars of unpadded base64 — comparable against a server's
    // log line character for character (§28a).
    expect(written).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
  });

  it("refuses a public line for an algorithm SSH has no key type for", async () => {
    // x25519 does ECDH; SSH user keys sign. The action explains that rather
    // than emitting something that would not work.
    const art = await publicHalf("x25519");
    await expect(
      actionById("key.copyPublicLine").run({
        artifact: art,
        services: { clipboard: { write: () => {} } },
      })
    ).rejects.toThrow(/SSH has no key type for this algorithm/);
  });

  it("still fingerprints while the private half is masked", async () => {
    // The fingerprint is a public fact; masking it would be theatre (§34b).
    const { ast } = compileRecipe("genkey ed25519 | out @kp");
    const arts = await runRecipe(ast, {});
    const priv = arts.find((a) => /private/.test(a.label));
    expect(priv.sensitive).toBe(true);
    expect(actionById("key.copyFingerprint").available({ artifact: priv, masked: true })).toBe(
      true
    );
  });
});

describe("outward confirmation shares §27's shell (§34c/§43a/§43b)", () => {
  const GATE = read("../toolkit/widgets/GateBanner.tsx");
  const CONSEQUENCE = read("../toolkit/widgets/ConsequenceBanner.tsx");
  const APPROVAL = read("../toolkit/widgets/ApprovalBanner.tsx");
  const TILE = read("../toolkit/widgets/ArtifactTile.tsx");

  it("draws both banners from one shell, so neither can drift", () => {
    // A second confirmation grammar teaches that confirmations are
    // decorative, which is the failure mode that makes every confirmation in
    // the product worthless.
    expect(APPROVAL).toMatch(/from "\.\/GateBanner"/);
    expect(CONSEQUENCE).toMatch(/from "\.\/GateBanner"/);
    // The chrome is declared once, in the shell, and nowhere else.
    for (const [name, src] of [
      ["ApprovalBanner", APPROVAL],
      ["ConsequenceBanner", CONSEQUENCE],
    ]) {
      expect(src, name).not.toMatch(/border-l-2/);
      expect(src, name).not.toMatch(/grid-cols-\[68px/);
      expect(src, name).not.toMatch(/role="alertdialog"/);
    }
    expect(GATE).toMatch(/border-l-2 border-\[var\(--border\)\] border-l-\[var\(--warn\)\]/);
    expect(GATE).toMatch(/bg-\[color-mix\(in_srgb,var\(--warn\)_8%,transparent\)\]/);
    expect(GATE).toMatch(/grid-cols-\[68px_minmax\(0,1fr\)\]/);
    expect(GATE).toMatch(/role="alertdialog"/);
  });

  it("gives the publish banner no session grant, no batch, no counter (§43b)", () => {
    // The absences *are* the semantic difference, and they read as decisions
    // only because the shell around them is identical.
    expect(CONSEQUENCE).not.toMatch(/type="checkbox"/);
    expect(CONSEQUENCE).not.toMatch(/for this session/);
    expect(CONSEQUENCE).not.toMatch(/remaining/);
    expect(CONSEQUENCE).not.toMatch(/meta=/);
    // Still present on the approval banner, which did not change.
    expect(APPROVAL).toMatch(/type="checkbox"/);
    expect(APPROVAL).toMatch(/meta=\{/);
  });

  it("leaves the approval banner without focus theft or an Escape binding", () => {
    // §33g claims the approval banner already moves focus and resolves
    // Escape. It never has, and unit 4.4's contract is that its behaviour
    // does not change — so both are opt-in on the shell and this one does not
    // opt in. A keystroke that used to do nothing must not start denying a
    // signing request as a side effect of a refactor.
    expect(APPROVAL).not.toMatch(/onEscape/);
    expect(APPROVAL).not.toMatch(/\.focus\(\)/);
    expect(CONSEQUENCE).toMatch(/onEscape=/);
    expect(CONSEQUENCE).toMatch(/cancelRef\.current\?\.focus\(\)/);
  });

  it("puts neither banner button in --warn (§43c)", () => {
    // On the warn-8% ground, --warn text measures 4.39:1 in light. Amber
    // marks the decision *point*: on the tile that is the button, inside the
    // banner it is the banner, and the buttons are its answer.
    const actions = CONSEQUENCE.match(/actions=\{[\s\S]*?\n {6}\}/);
    expect(actions, "actions block not found").toBeTruthy();
    expect(actions[0]).not.toMatch(/--warn/);
    expect(actions[0]).toMatch(/variant="ghost"[\s\S]*?variant="secondary"/);
  });

  it("renders inline in the tile, never as a floating layer (§43d)", () => {
    // A layer dismissed by clicking away trains dismissal, and the context —
    // which tile, which artifact — is what the question is about.
    expect(TILE).toMatch(/<ConsequenceBanner/);
    expect(TILE).not.toMatch(/absolute right-2 top-full/);
    expect(TILE).not.toMatch(/publishConfirmLabel/);
  });
});

describe("Add to My Keys is local, masked-safe, and refuses by default (§34a/§34d)", () => {
  const add = actionById("keyring.add");
  const KEYRING = read("../lib/toolkit/keyring-service.js");
  // `stripComments` is the file-level helper: the absence of `onConflict` is
  // explained in prose right beside the call it is absent from, so a naive
  // grep finds the explanation and calls it the bug.
  const privateJwk = JSON.stringify({ kty: "OKP", crv: "Ed25519", x: "aa", d: "bb" });
  const publicJwk = JSON.stringify({ kty: "OKP", crv: "Ed25519", x: "aa" });
  const vault = {
    add: async () => ({ fingerprint: "SHA256:Ur1hXXXXXXXXXXXX", kind: "ssh", already: false }),
  };

  it("is a local action, named for the vault the rest of the app names", () => {
    // The id keeps the table's vocabulary; the label uses the user's. Both
    // already diverge elsewhere (`key.publish` → "Publish").
    expect(add.id).toBe("keyring.add");
    expect(add.tier).toBe("local");
    expect(add.label).toBe("Add to My Keys");
  });

  it("stays enabled while masked, where Copy is not", () => {
    // §34b disables Copy on a masked value because copying is how a secret
    // leaves the notebook. This is the opposite motion — it moves the secret
    // into storage without ever displaying it — and since private-key tiles
    // are masked by default, a reveal gate would disable the button in
    // exactly the case it exists for.
    const artifact = { content: privateJwk, revealable: true };
    expect(add.available({ artifact, masked: true, services: { vault } })).toBe(true);
    expect(actionById("copy").available({ artifact, masked: true })).not.toBe(true);
  });

  it("disables with the environment's reason when no vault is injected", () => {
    expect(add.available({ artifact: { content: privateJwk }, services: {} })).toEqual({
      disabled: ACTION_REASONS.noVault,
    });
  });

  it("names the remedy when the tile has no body to store", () => {
    expect(add.available({ artifact: { content: "" }, services: { vault } })).toEqual({
      disabled: ACTION_REASONS.noKeyBody,
    });
  });

  it("answers the least-specific kind's runtime question with a sentence (§33d)", () => {
    // `key` cannot know which half it holds — that is what makes it least
    // specific — so the question is answered here, with a reason, rather than
    // by the kind refusing to declare the action.
    const disabled = { disabled: ACTION_REASONS.noPrivateHalf };
    expect(add.available({ artifact: { content: publicJwk }, services: { vault } })).toEqual(
      disabled
    );
    expect(
      add.available({
        artifact: { content: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxx\n" },
        services: { vault },
      })
    ).toEqual(disabled);
    for (const armor of [
      "-----BEGIN PGP PRIVATE KEY BLOCK-----\nxx\n",
      "-----BEGIN OPENSSH PRIVATE KEY-----\nxx\n",
    ]) {
      expect(add.available({ artifact: { content: armor }, services: { vault } })).toBe(true);
    }
  });

  it("is declared on the private key kinds and on no public one", () => {
    const kinds = ARTIFACT_KINDS.filter((k) => (k.actions || []).includes("keyring.add")).map(
      (k) => k.id
    );
    expect(kinds.sort()).toEqual(["key", "keypair-private", "openpgp-private"]);
    // Omission, not a disabled state (§33d): a dead button on a public-key
    // tile would teach that public keys belong in My Keys.
    for (const id of ["keypair-public", "openpgp-public"]) {
      expect(ARTIFACT_KINDS.find((k) => k.id === id).actions, id).not.toContain("keyring.add");
    }
  });

  it("states where it lands, how weakly it is protected, and that it undoes", () => {
    const spec = add.confirm({ artifact: { label: "kp · private JWK", traits: {} } });
    const fact = (t) => spec.facts.find((f) => f.term === t);
    expect(spec.confirmLabel).toBe("Add to My Keys");
    expect(fact("Where").detail).toBe("My Keys, in this browser");
    expect(fact("Where").sub).toMatch(/not synced anywhere/);
    // What device protection *means* for someone with the browser profile,
    // plus the remedy — a reason with no way forward just gets clicked again.
    expect(fact("Protection").detail).toMatch(/no passkey, no passphrase/);
    expect(fact("Protection").detail).toMatch(/without being asked for anything/);
    expect(fact("Protection").sub).toMatch(/Enrol a passkey from My Keys/);
    expect(fact("Protection").sub).toMatch(/agent\.save protection=passkey/);
    // The contrast with Publish's "Permanent" is the useful information.
    expect(fact("Reversible").detail).toMatch(/Deleting the key from My Keys removes it/);
    const publishTerms = actionById("key.publish")
      .confirm({
        artifact: { label: "p", traits: {} },
        services: { directory: { host: "h", publish: () => {} } },
      })
      .facts.map((f) => f.term);
    expect(publishTerms).toContain("Permanent");
    expect(spec.facts.map((f) => f.term)).not.toContain("Permanent");
  });

  it("shows an OpenPGP fingerprint in display shape on the Key line", () => {
    const spec = add.confirm({
      artifact: {
        label: "k",
        traits: { fingerprint: "3F2AB19C4D7E0518A2B6C93D4E7F0A1B2C3D4E5F" },
      },
    });
    expect(spec.facts.find((f) => f.term === "Key").sub).toBe(
      "3F2A B19C 4D7E 0518 A2B6 C93D 4E7F 0A1B 2C3D 4E5F"
    );
    // A JWK key's id is derived asynchronously and already sits in the key
    // card two lines above the banner; a second derivation here could
    // disagree with the first.
    expect(
      add.confirm({ artifact: { label: "kp", traits: { alg: "ed25519" } } }).facts.find(
        (f) => f.term === "Key"
      ).sub
    ).toBeUndefined();
  });

  it("passes no onConflict, so the vault's default refusal stands", () => {
    // `agent.save` passes "replace" because a recipe said it out loud with
    // the fingerprint in front of it. A button click is the single click the
    // default exists for — and the asymmetry is explained in a comment right
    // beside the call, which is why this reads the stripped source.
    const code = stripComments(SRC);
    expect(code).toMatch(/services\.vault\.add\(/);
    expect(code).not.toMatch(/onConflict/);
    expect(stripComments(KEYRING)).not.toMatch(/onConflict/);
  });

  it("reports the destination the Activity log prints on its own line", async () => {
    const res = await add.run({ artifact: { content: privateJwk }, services: { vault } });
    expect(res.receipt).toBe("Added to My Keys");
    expect(res.detail).toMatch(/^My Keys SHA256:/);
  });

  it("says 'already' rather than 'added' when the row was already there", async () => {
    const res = await add.run({
      artifact: { content: privateJwk },
      services: {
        vault: { add: async () => ({ fingerprint: "SHA256:x", kind: "ssh", already: true }) },
      },
    });
    expect(res.receipt).toBe("Already in My Keys");
  });
});

describe("Publish is outward, declared once, and states its consequences (§34a/§38b)", () => {
  const publish = actionById("key.publish");

  it("is the one outward action, on the one kind that can be published", () => {
    const outward = ARTIFACT_ACTIONS.filter((a) => a.tier === "outward").map((a) => a.id);
    expect(outward).toEqual(["key.publish"]);
    const kinds = ARTIFACT_KINDS.filter((k) => (k.actions || []).includes("key.publish")).map(
      (k) => k.id
    );
    // `publishArtifact` throws on any role but public-key; the registry and
    // the function now agree in two places instead of one.
    expect(kinds).toEqual(["openpgp-public"]);
    expect(ARTIFACT_KINDS.find((k) => k.id === "openpgp-public").match.role).toBe("public-key");
  });

  it("disables with a reason when there is no route to the directory", () => {
    expect(publish.available({ artifact: {}, services: {} })).toEqual({
      disabled: ACTION_REASONS.offline,
    });
    expect(publish.available({ artifact: {}, services: { directory: { publish: () => {} } } })).toBe(
      true
    );
  });

  it("names this site and never a keyserver on the Where line", () => {
    // `upstream-hkp.js` is lookup-only; there is no upstream write path at
    // all, so wording that could name a keyserver would be a lie about where
    // the key went.
    const spec = publish.confirm({
      artifact: { label: "dana.pub.asc", traits: { fingerprint: "3F2AB19C4D7E0518" } },
      services: { directory: { host: "keys.example.com", publish: () => {} } },
    });
    const where = spec.facts.find((f) => f.term === "Where");
    expect(where.detail).toBe("keys.example.com");
    expect(where.sub).toBe("this site's directory — not an upstream keyserver");
    expect(JSON.stringify(spec)).not.toMatch(/keys\.openpgp\.org|keys\.mailvelope\.com/);
  });

  it("says what becomes public and what permanent means, verbatim", () => {
    // The email addresses are the consequence people are surprised by, and
    // "you can add a tombstone, you cannot delete" is the accurate model — a
    // user who thinks revocation is deletion will make the wrong call.
    const spec = publish.confirm({
      artifact: { label: "dana.pub.asc", traits: {} },
      services: { directory: { host: "h", publish: () => {} } },
    });
    expect(spec.facts.find((f) => f.term === "Becomes public").detail).toBe(
      "The key, its user IDs, and every signature on it — readable by anyone with directory access, including the email addresses in its user IDs."
    );
    expect(spec.facts.find((f) => f.term === "Permanent").detail).toBe(
      "A published key cannot be withdrawn. You can publish a revocation later; you cannot make this copy go away."
    );
    expect(spec.confirmLabel).toBe("Publish");
  });

  it("shows the fingerprint in display shape, not normalized hex", () => {
    const spec = publish.confirm({
      artifact: {
        label: "dana.pub.asc",
        traits: { fingerprint: "3F2AB19C4D7E0518A2B6C93D4E7F0A1B2C3D4E5F" },
      },
      services: { directory: { host: "h", publish: () => {} } },
    });
    expect(spec.facts.find((f) => f.term === "Key").sub).toBe(
      "3F2A B19C 4D7E 0518 A2B6 C93D 4E7F 0A1B 2C3D 4E5F"
    );
  });

  it("reports where the key went, so the Activity log can name it", async () => {
    const res = await publish.run({
      services: {
        directory: {
          publish: async () => ({ fingerprint: "ABC", directoryUrl: "https://x/pks/lookup" }),
        },
      },
    });
    expect(res.receipt).toBe("Published");
    expect(res.detail).toBe("https://x/pks/lookup");
  });
});
