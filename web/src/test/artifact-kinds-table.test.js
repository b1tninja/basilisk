/**
 * The artifact-kind table (§32e/§32f, design_handoff_artifact_actions).
 *
 * The resolver's semantics are pinned in `artifact-kinds.test.js`; this file
 * is about the table itself — that it is unambiguous, that it claims the roles
 * it says it claims, and that folding the three existing renderers in did not
 * require changing them.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import "../lib/toolkit/registry.js";
import { ARTIFACT_ROLES, artifactMetaFromType } from "../lib/toolkit/types.js";
import {
  ARTIFACT_KINDS,
  FALLBACK_KIND,
} from "../toolkit/artifact-kinds/registry.tsx";
import {
  ambiguousPairs,
  badgeNameFor,
  resolveArtifactKind,
} from "../toolkit/artifact-kinds/resolve.ts";
import { actionsFor } from "../lib/toolkit/artifact-actions.js";
import {
  KEY_BADGE_KINDS,
  KEY_GLYPH_TIERS,
  KIND_GLYPHS,
  badgeFamily,
  glyphExists,
} from "../toolkit/widgets/kind-glyphs.tsx";
import { compileRecipe } from "../lib/toolkit/recipe.js";
import { runRecipe } from "../lib/toolkit/engine.js";

const TABLE_SRC = readFileSync(
  fileURLToPath(new URL("../toolkit/artifact-kinds/registry.tsx", import.meta.url)),
  "utf8"
);
/** Source with comments removed, for assertions about what the code *does*. */
const CODE_ONLY = TABLE_SRC.replace(/\/\*[\s\S]*?\*\//g, "").replace(
  /\/\/[^\n]*/g,
  ""
);

/**
 * Roles with no kind entry yet. This list may only ever shrink: §35 and §37
 * of the design fill it in, and until then an honest test records the gap
 * rather than asserting a coverage that does not exist. A role added without
 * a kind fails here, which is the point.
 *
 * Empty since §37 — every role in the vocabulary is claimed. The constant
 * stays because it is the shape of the gate: a role added to ARTIFACT_ROLES
 * without a kind lands here as a failure, and a future role that is
 * deliberately unclaimed has somewhere to be written down with its reason.
 */
const UNCLAIMED_ROLES = [];

/**
 * The catalog page, for the coverage gate below.
 *
 * Read as source rather than imported: `toolkit-widgets.tsx` mounts itself at
 * module scope (`createRoot(host).render(…)`), so importing it in a node test
 * throws before a single fixture is reachable.
 */
const CATALOG_SRC = readFileSync(
  fileURLToPath(new URL("../pages/toolkit-widgets.tsx", import.meta.url)),
  "utf8"
).replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

/**
 * Kinds whose catalog row takes its `role` and `tags` from
 * `artifactMetaFromType` rather than from literals, so the row-scan gate below
 * cannot see them and a second assertion checks them properly instead.
 *
 * Both are here for the same reason: **no shipped step emits either shape**.
 * The keypair emit sites tag `keypair`, so `keypair-public` always outscores
 * `public-key`; PEM/DER exports keep the emit site's `text`/`secret` because
 * `key` is not in `TYPE_OWNED_ROLES`. Writing those shapes by hand would be
 * writing a claim about the engine that nothing checks — the exact failure the
 * §37 fixtures' header warns about — so the catalog calls the projection.
 */
const PROJECTION_BUILT = ["key", "public-key"];

describe("the table is unambiguous", () => {
  it("has no two entries that could both claim the same artifact", () => {
    expect(ambiguousPairs(ARTIFACT_KINDS)).toEqual([]);
  });

  it("gives every entry a stable id, a label and an empty-state sentence", () => {
    const ids = new Set();
    for (const kind of ARTIFACT_KINDS) {
      expect(kind.id, "id").toBeTruthy();
      expect(ids.has(kind.id), `duplicate id ${kind.id}`).toBe(false);
      ids.add(kind.id);
      expect(typeof kind.view, `${kind.id} view`).toBe("function");
      // An empty state is a sentence explaining what is missing and what would
      // produce it — never "N/A", which tells the reader nothing.
      expect(kind.empty.length, `${kind.id} empty`).toBeGreaterThan(20);
      expect(kind.empty, `${kind.id} empty`).not.toMatch(/^N\/A|^none$/i);
    }
  });

  it("names only glyphs that exist", () => {
    // §32d: omitting a glyph renders none rather than a guess. A name with no
    // entry would render nothing while looking declared — the worst of both.
    //
    // `glyphExists` spans both vocabularies, because a kind's glyph may name a
    // `KIND_GLYPHS` key or a `GLYPH_PATHS` id and the key kinds now name the
    // latter. Conflating the two namespaces is part of how the defect below
    // survived: while every key kind pointed at one lucide icon there was
    // nothing to notice.
    for (const kind of ARTIFACT_KINDS) {
      if (!kind.glyph) continue;
      expect(glyphExists(kind.glyph), `${kind.id} names glyph "${kind.glyph}"`).toBe(true);
    }
  });

  /**
   * The defect this exists for, found while splitting the glyph channel:
   * `openpgp-public` and `openpgp-private` both declared `glyph: "openpgp-key"`,
   * and `keypair-public`, `public-key`, `keypair-private`, `secret-key` and
   * `key` all declared `glyph: "key"`. A card labelled "Public key" and a card
   * labelled "Private key" named the same pictogram — the colour defect from
   * one commit ago, in the other channel, and invisible for the same reason:
   * nothing compared the two declarations.
   */
  it("never draws a secret kind and a public kind with the same glyph", () => {
    const byGlyph = new Map();
    for (const kind of ARTIFACT_KINDS) {
      if (!kind.glyph || !kind.sensitivity) continue;
      const seen = byGlyph.get(kind.glyph);
      expect(
        seen === undefined || seen.sensitivity === kind.sensitivity,
        `${kind.id} (${kind.sensitivity}) and ${seen?.id} (${seen?.sensitivity}) both draw "${kind.glyph}"`
      ).toBe(true);
      byGlyph.set(kind.glyph, kind);
    }
    // And a kind that *declares* a side must draw that side's bow, so nothing
    // can be tinted secret while wearing the hollow one.
    //
    // Undeclared is skipped rather than failed, and `key` is the whole reason:
    // it declines to say which half it holds, so its tier is the engine's
    // `sensitive` flag at runtime. Its glyph still has to pick a side at build
    // time, and it picks `key-secret` — asserted below, where the argument for
    // over-warning lives.
    for (const kind of ARTIFACT_KINDS) {
      const tier = KEY_GLYPH_TIERS[kind.glyph];
      if (!tier || !kind.sensitivity) continue;
      expect(kind.sensitivity, `${kind.id} draws ${kind.glyph}`).toBe(tier);
    }
  });

  it("badges a one-time code as what it is, from the trait that knows", () => {
    // The user's report: "to label this more advanced TOTP artifact as TEXT is
    // not wrong, but i think TOTP is a more useful label". `match` can only be
    // `role: "text"` here — the engine's role ternary turns on secrecy and a
    // code that exists to be typed never is — so the tag claims the kind and
    // the role was what the chip rendered.
    const otp = ARTIFACT_KINDS.find((k) => k.id === "otp-code");
    expect(otp.match).toEqual({ role: "text", tags: ["otp-code"] });
    expect(badgeNameFor(otp, { traits: { otpMode: "totp" } }, "text")).toBe("TOTP");
    expect(badgeNameFor(otp, { traits: { otpMode: "hotp" } }, "text")).toBe("HOTP");
    // No trait at all still beats TEXT: TOTP is the overwhelmingly common
    // shape and `OtpCodeCard` already treats a missing mode the same way.
    expect(badgeNameFor(otp, {}, "text")).toBe("TOTP");
  });

  it("keeps every badge name short enough not to eat the row", () => {
    // Measured on the built page: a 320px panel beside a real engine filename
    // truncates the filename once the chip passes ~100px, which the prose
    // `label` does ("OpenPGP public key" is 124px) and the role does not
    // ("public-key" is 79px, the widest key role). So a declared badge is a
    // *short* name, not the label — 12 characters is the role vocabulary's
    // own longest (`ssh-private`) plus one.
    for (const kind of ARTIFACT_KINDS) {
      if (typeof kind.badge !== "string") continue;
      expect(kind.badge.length, `${kind.id} badge "${kind.badge}"`).toBeLessThanOrEqual(12);
    }
  });

  it("only claims roles that exist in the vocabulary", () => {
    for (const kind of ARTIFACT_KINDS) {
      expect(ARTIFACT_ROLES, kind.id).toContain(kind.match.role);
    }
  });
});

describe("the key badge family", () => {
  /**
   * The check that could not exist while the answer lived in a ternary inside
   * `ArtifactTile`.
   *
   * Six roles wear a key badge, added over six commits by as many briefs, and
   * two of them landed in the tint condition while four did not — so
   * `PUBLIC-KEY`, `SECRET-KEY`, `SSH-PUBLIC` and `SSH-PRIVATE` rendered in the
   * same `--caret` as `TEXT` and `RECEIPT` while carrying the same `KeyRound`
   * glyph as `KEY` and `KEYPAIR`. The glyph map asserted one family and the
   * colour asserted two, and nothing could compare them.
   *
   * These two directions are the comparison. A role added to one and forgotten
   * in the other now fails here rather than in a screenshot nobody takes.
   */
  it("tints every key-glyphed role as a key", () => {
    for (const [kind, glyph] of Object.entries(KIND_GLYPHS)) {
      if (!KEY_GLYPH_TIERS[glyph]) continue;
      expect(badgeFamily(kind), `${kind} wears a key glyph`).toBe("key");
    }
  });

  it("claims no role that is not key material", () => {
    for (const kind of KEY_BADGE_KINDS) {
      expect(ARTIFACT_ROLES, `${kind} is a badge string, so it is a role`).toContain(
        kind
      );
      expect(KEY_GLYPH_TIERS[KIND_GLYPHS[kind]], `${kind} draws a key`).toBeTruthy();
    }
  });

  /**
   * The two channels have to agree, and this is where they are compared.
   *
   * Colour and glyph now both carry sensitivity, from two different sources —
   * `sensitivity` on the kind table, and the bow on the asset. A role whose
   * badge is tinted secret while its glyph is the hollow public bow would be
   * two marks contradicting each other on the same 63px chip, which is worse
   * than either channel alone.
   *
   * `key` is the interesting row: it declares no `sensitivity` (it does not
   * know which half it holds), so its tier comes from the engine's flag at
   * runtime — but its *glyph* is fixed at build time and must pick a side.
   * It draws `key-secret`, because the role means "private, or unknown", and
   * unknown over-warns.
   */
  it("draws the same side of the axis the tint paints", () => {
    for (const role of KEY_BADGE_KINDS) {
      const tier = KEY_GLYPH_TIERS[KIND_GLYPHS[role]];
      // A role whose *kind* declares a sensitivity must match its glyph.
      const kinds = ARTIFACT_KINDS.filter((k) => k.match.role === role && k.sensitivity);
      for (const k of kinds) {
        expect(k.sensitivity, `role ${role} → kind ${k.id} vs glyph ${KIND_GLYPHS[role]}`).toBe(
          tier
        );
      }
    }
    // And nothing public may be drawn with a filled bow, in either direction.
    expect(KEY_GLYPH_TIERS[KIND_GLYPHS["public-key"]]).toBe("public");
    expect(KEY_GLYPH_TIERS[KIND_GLYPHS["ssh-public"]]).toBe("public");
    expect(KEY_GLYPH_TIERS[KIND_GLYPHS["secret-key"]]).toBe("secret");
    expect(KEY_GLYPH_TIERS[KIND_GLYPHS["ssh-private"]]).toBe("secret");
    expect(KEY_GLYPH_TIERS[KIND_GLYPHS["keypair"]]).toBe("secret");
    expect(KEY_GLYPH_TIERS[KIND_GLYPHS["key"]]).toBe("secret");
  });

  it("keeps the vocabulary closed, so one rule set covers it", () => {
    // Three values, matching the enumerated `.artifact-badge[data-badge-family]`
    // rules in toolkit.css. A fourth would render untinted rather than fall
    // back, which is the failure a stylesheet cannot report.
    for (const role of [...ARTIFACT_ROLES, "diag", "something-later"]) {
      expect(["key", "diag", "plain"], role).toContain(badgeFamily(role));
    }
  });
});

describe("the keypair's withheld line, verbatim", () => {
  /**
   * The one sentence on a key tile that no test held.
   *
   * `ACTION_REASONS` is asserted word for word in `artifact-actions.test.js`
   * because wording is the feature; this line says the same *thing* as
   * `neverAskedFor` — the value was never asked for, here is the edit — and
   * had none of that protection, because it is a caption rather than a
   * refusal and so is not in that module. The polish pass tried moving it
   * there and the module's own contract rejected it: every reason is a
   * capitalised, full-stopped sentence spoken by a control, and this is a
   * lowercase fragment in the register of the captions beside it. So it stays
   * where it is rendered, and is pinned where it is rendered.
   */
  it("names the recipe edit, in the card's caption register", () => {
    const kp = ARTIFACT_KINDS.find((k) => k.id === "keypair");
    const withheld = kp.view({ artifact: { traits: {} }, masked: false }).props.withheld;
    expect(withheld).toBe(
      "private half not shown — add `out @kp` to the recipe to write both halves"
    );
    // Lowercase and unpunctuated, matching "public + private halves" and
    // "symmetric — no public half" on the same card — which is exactly what
    // makes it a caption and not an `ACTION_REASONS` entry.
    expect(withheld[0]).toBe(withheld[0].toLowerCase());
    expect(withheld).not.toMatch(/[.!]$/);
    // The remedy is named, which is the half of §33d a caption still owes.
    expect(withheld).toMatch(/out @kp/);
  });

  it("is rendered by the keypair kind in both mask states", () => {
    // `view` and `publicView` are the same function on purpose — a tile with
    // no body has nothing a reveal could add — so the sentence cannot go
    // missing in one of them.
    const kp = ARTIFACT_KINDS.find((k) => k.id === "keypair");
    expect(kp.publicView).toBe(kp.view);
  });
});

describe("role coverage", () => {
  const claimed = new Set(ARTIFACT_KINDS.map((k) => k.match.role));

  it("claims netvalue, inspect and token", () => {
    for (const role of ["netvalue", "inspect", "token"]) {
      expect(claimed.has(role), role).toBe(true);
    }
  });

  it("records exactly the roles still without a kind", () => {
    // Shrinks as §35/§37 land. If it needs to *grow*, a role was added
    // without a kind and this is where that is caught.
    const unclaimed = ARTIFACT_ROLES.filter((r) => !claimed.has(r));
    expect([...unclaimed].sort()).toEqual([...UNCLAIMED_ROLES].sort());
  });

  /**
   * **Every kind gets a row on the design surface (D7).**
   *
   * A role gate already existed and a kind gate did not, and the difference
   * cost a real finding: `#artifacttiles` and `#keyartifacts` between them
   * rendered 19 of 24 kinds, and two of the five missing ones —
   * `network-value` and `jose-token` — had sections that mount their widget
   * **bare**, outside a tile. So `JwtArtifact`, the most complete read-out in
   * the codebase, had never been seen inside the thing that masks it: `jose.sign`
   * emits `sensitive: true`, the kind declares no `publicView`, and the card is
   * therefore behind a Reveal that the list re-masks after fifteen seconds.
   * That is invisible in a section that renders the card directly, and it is
   * the class of thing this page exists to make visible.
   *
   * **What this gate is and is not.** It is a *source* check — the catalog
   * cannot be imported (see `CATALOG_SRC`), so this asserts that a fixture
   * carrying each kind's `match` exists in the file, not that it resolves. What
   * proves resolution is the built page, where every tile carries
   * `data-artifact-kind`; a row whose tags are wrong reads `fallback` there.
   * Both are needed and neither substitutes: nine defects this session passed
   * the whole suite while broken in the page.
   */
  it("puts a fixture for every kind on the catalog", () => {
    // Per *row*, not per file. A whole-file scan passes as soon as some other
    // fixture happens to mention the role and some third one happens to
    // mention the tag, which is a gate that cannot fail.
    const rows = CATALOG_SRC.split(/\brow\(\{/).slice(1);
    const covered = (kind) =>
      rows.some(
        (r) =>
          r.includes(`role: "${kind.match.role}"`) &&
          (kind.match.tags || []).every((t) => r.includes(`"${t}"`))
      );
    const missing = ARTIFACT_KINDS.filter(
      (k) => !PROJECTION_BUILT.includes(k.id) && !covered(k)
    ).map((k) => k.id);
    expect(missing).toEqual([]);
  });

  /**
   * The two rows whose identity is computed rather than written, checked by
   * running the same computation.
   *
   * This is the stronger half of the gate and the reason the exemption above
   * is not a hole: it does not look at the catalog's text at all, it calls the
   * projection with the arguments the catalog calls it with and resolves the
   * result. If `artifactMetaFromType` ever stops producing a shape these kinds
   * claim, the rows stop rendering them and this fails — which a source scan
   * for a literal could never notice.
   */
  it("resolves the projection-built rows to the kinds they exist for", () => {
    const kindOf = (t) =>
      resolveArtifactKind(artifactMetaFromType(t), ARTIFACT_KINDS, FALLBACK_KIND).id;
    expect(kindOf({ base: "openpgp-key", which: "public" })).toBe("key");
    expect(kindOf({ base: "key", which: "public" })).toBe("public-key");
    for (const id of PROJECTION_BUILT) {
      expect(CATALOG_SRC).toContain(`...artifactMetaFromType(`);
      expect(ARTIFACT_KINDS.some((k) => k.id === id)).toBe(true);
    }
  });

  it("declares Download on every kind, because every body is a file", () => {
    // A kind that declares no actions renders no buttons. That is correct for
    // a kind's *own* actions and wrong for a universal one — omitting Copy
    // once already took it off the majority of tiles the moment the bespoke
    // button was replaced by the table. Download is universal by the same
    // test: §33d's "is this meaningful for this object" is yes for any body.
    for (const kind of ARTIFACT_KINDS) {
      expect(kind.actions, kind.id).toContain("download");
    }
  });

  it("declares Copy everywhere but on the QR, whose source nobody wants", () => {
    // §37b called this and deferred it until there was a second affordance to
    // leave behind: nobody reads a QR by reading its path data, but a tile
    // with no button at all is worse than one with an odd button. Download
    // landed, so Copy went — as an omission, not a disabled state.
    const withoutCopy = ARTIFACT_KINDS.filter((k) => !(k.actions || []).includes("copy"));
    expect(withoutCopy.map((k) => k.id)).toEqual(["qr"]);
  });
});

describe("§37 pruned the actions it was offered", () => {
  const declared = new Set(ARTIFACT_KINDS.flatMap((k) => k.actions || []));

  it("declares no action that would compute a new value (§37a)", () => {
    // "A button may move an artifact. It may never compute a new one."
    // Decrypt with…, Verify threshold, Trust…, Send to peer and Save as group
    // all produce a value or a verdict that would exist in the notebook with
    // no derivation behind it, no type, and no place in the recipe or the
    // receipt — a value the CLI cannot reproduce.
    for (const id of [
      "ciphertext.decrypt",
      "share.verifyThreshold",
      "recipients.saveGroup",
      "netvalue.send",
      "sshsig.verify",
      "receipt.verify",
    ]) {
      expect(declared.has(id), id).toBe(false);
    }
  });

  it("names no action the table does not define", () => {
    // A kind naming an action with no definition renders one fewer button and
    // says nothing about it. The tile must not be where that is discovered.
    for (const kind of ARTIFACT_KINDS) {
      expect(actionsFor(kind).length, kind.id).toBe(kind.actions.length);
    }
  });

  it("keeps Publish on exactly one kind (§38b)", () => {
    const withPublish = ARTIFACT_KINDS.filter((k) =>
      (k.actions || []).includes("key.publish")
    );
    expect(withPublish.length).toBeLessThanOrEqual(1);
    for (const k of withPublish) expect(k.match.role).toBe("public-key");
  });
});

describe("§37 kinds show a read-out where there is one, and say so where there is not", () => {
  const kindById = (id) => ARTIFACT_KINDS.find((k) => k.id === id);

  it("gives share the identity line as a publicView, and no view", () => {
    // The share's value *is* its own words, and the tile renders words with a
    // format bar, a Hide button and the auto-hide timer. A widget redrawing
    // the body would have removed all three to add nothing. What was missing
    // is which share this is — public, and therefore drawable while masked.
    const share = kindById("share");
    expect(share.view({ artifact: { content: "away manual" }, masked: false })).toBeNull();
    expect(typeof share.publicView).toBe("function");
  });

  it("gives text and secret no view at all, and an honest sentence instead", () => {
    for (const id of ["text", "secret"]) {
      const kind = kindById(id);
      expect(kind.view({ artifact: { content: "x" }, masked: false }), id).toBeNull();
      expect(kind.empty.length, id).toBeGreaterThan(20);
    }
    // A secret has no public half to draw — unlike a keypair, whose algorithm
    // and fingerprint are facts about the public side. Inventing a line would
    // mean deriving it from the masked material.
    expect(kindById("secret").publicView).toBeUndefined();
  });

  it("never draws a QR while it is masked", () => {
    // A QR *is* the secret, in a form a camera across the room can read.
    expect(kindById("qr").publicView).toBeUndefined();
  });

  it("draws ciphertext and envelope through the same packet read-out", () => {
    // Same body, different artifact: the envelope keeps its "required for
    // recovery (not a share)" label, which the engine already writes.
    for (const id of ["ciphertext", "envelope"]) {
      expect(typeof kindById(id).view, id).toBe("function");
    }
  });
});

describe("the fallback is a kind, not a crash (§32f)", () => {
  it("claims nothing, so it is only ever reached by falling through", () => {
    expect(ARTIFACT_ROLES).not.toContain(FALLBACK_KIND.match.role);
  });

  it("still offers Copy — every artifact can be copied", () => {
    // The fallback claims most artifacts. Without this, replacing the
    // bespoke Copy button with the action table silently removed Copy from
    // the majority of tiles.
    expect(FALLBACK_KIND.actions).toContain("copy");
  });

  it("renders no view of its own, leaving the raw body to show", () => {
    // Deliberately not an error tile and not a warning: the value is real and
    // correct, and only our description of it is missing. Converting an engine
    // metadata omission into a user-visible failure inverts the severity.
    expect(FALLBACK_KIND.view({ artifact: { content: "x" }, masked: false })).toBeNull();
  });

  it("catches an artifact the table does not know about", () => {
    // Since §37 every role in the vocabulary is claimed, so the fallback is
    // reached only by an artifact whose role is outside it — a role-less tile
    // from a path that has not been through `attachPipeMeta`, or a word from a
    // future build. Both must still render their content.
    const kind = resolveArtifactKind(
      { role: "something-later" },
      ARTIFACT_KINDS,
      FALLBACK_KIND
    );
    expect(kind.id).toBe("fallback");
    expect(resolveArtifactKind({}, ARTIFACT_KINDS, FALLBACK_KIND).id).toBe("fallback");
  });
});

describe("the existing renderers were folded in, not rewritten (§32e)", () => {
  it("imports all three unmodified", () => {
    expect(TABLE_SRC).toMatch(/import \{ NetworkArtifact \} from "\.\.\/widgets\/NetworkArtifact"/);
    expect(TABLE_SRC).toMatch(
      /import \{ InspectorArtifact \} from "\.\.\/widgets\/InspectorArtifact"/
    );
    expect(TABLE_SRC).toMatch(
      /import \{ JwtArtifact, hasJoseRenderer \} from "\.\.\/widgets\/JwtArtifact"/
    );
  });

  it("no longer keys the render path off hasNetworkRenderer", () => {
    // The seven network bases are now the definition of role "netvalue" in the
    // type projection, so the list of renderable network types lives with the
    // types instead of being duplicated in a widget.
    // Asserted against the source with comments stripped: the header explains
    // why the predicate is gone, in prose that names and calls it. Forbidding
    // the word outright would delete the explanation along with the thing it
    // explains — the same trap the threat-model and ScrollArea tests hit.
    expect(CODE_ONLY).not.toMatch(/hasNetworkRenderer/);
  });

  it("demotes hasJoseRenderer to a body check inside a view", () => {
    // It answers "is this body shaped like a token body", which is the right
    // question for it — but it is no longer what decides the kind.
    const jose = ARTIFACT_KINDS.find((k) => k.id === "jose-token");
    expect(jose.match.role).toBe("token");
    expect(TABLE_SRC).toMatch(/view: \(\{ artifact \}\) =>\s*hasJoseRenderer/);
  });

  it("renders the empty state rather than a different kind when a body is missing", () => {
    // The if/else chain would have fallen through to raw text here, silently
    // treating a token as untyped. The kind is matched from identity, so a
    // token with no decoded body is still a token.
    const jose = ARTIFACT_KINDS.find((k) => k.id === "jose-token");
    expect(jose.view({ artifact: { content: "eyJ…", jose: undefined }, masked: false })).toBeNull();
    expect(jose.empty).toMatch(/jose\.verify/);
  });
});

describe("real engine artifacts resolve to the right kind", () => {
  /** Run a recipe and resolve every artifact it emits. */
  const kindsFor = async (src) => {
    const { ast, validation } = compileRecipe(src);
    expect(validation.ok, (validation.errors || []).map((e) => e.message).join(" · ")).toBe(
      true
    );
    const arts = await runRecipe(ast, {});
    return arts.map((a) => ({
      label: a.label,
      role: a.role,
      kind: resolveArtifactKind(a, ARTIFACT_KINDS, FALLBACK_KIND).id,
    }));
  };

  it("matches an inspect snapshot by identity, not by body presence", async () => {
    // The old chain asked "is there an inspectSnapshot field". This asks what
    // the artifact *is*, so a sensitive value — for which the engine
    // deliberately withholds the snapshot — is still an inspect artifact and
    // shows the kind's empty sentence rather than silently becoming raw text.
    const rows = await kindsFor('"hello" | utf8 | inspect');
    const snap = rows.find((r) => r.role === "inspect");
    expect(snap, `no inspect artifact in ${JSON.stringify(rows)}`).toBeTruthy();
    expect(snap.kind).toBe("inspect-snapshot");
  });

  it("claims a plain text artifact, and still draws no widget for it", async () => {
    // §37: `text` is claimed rather than left to the fallback, but with no
    // view of its own — the raw body, its format bar and its reveal gate are
    // already the right rendering of an opaque value. What changed is that the
    // table now says so instead of shrugging.
    const rows = await kindsFor('"plain" | utf8 | out @msg');
    expect(rows.every((r) => r.kind === "text")).toBe(true);
    const text = ARTIFACT_KINDS.find((k) => k.id === "text");
    expect(text.view({ artifact: { content: "plain" }, masked: false })).toBeNull();
  });

  it("resolves the §37 roles the engine really emits", async () => {
    // The design's description of emitted metadata has been wrong before, so
    // these are asserted against a run rather than against the prose. Each one
    // was checked by printing role/tags off `runRecipe` first.
    const shares = await kindsFor("random 32 | sss.split threshold=2 shares=3 | out @s");
    expect(shares.every((r) => r.role === "share" && r.kind === "share")).toBe(true);

    const qr = await kindsFor('"hello" | qr');
    expect(qr.find((r) => r.role === "qr").kind).toBe("qr");

    const env = await kindsFor(
      '"secret data" | utf8 | gpg.symencrypt mode=passphrase passphrase="hunter2"'
    );
    expect(env.find((r) => r.role === "envelope").kind).toBe("envelope");

    const receipt = await kindsFor('run.receipt label="ceremony" | out @r');
    expect(receipt.find((r) => r.role === "receipt").kind).toBe("receipt");
  }, 60_000);

  it("resolves an sshsig block as one, now that the engine says so", async () => {
    // It did not before: the `out` text branch stamped `text`/`secret` from
    // sensitivity, which outranked the type projection, so `role: "sshsig"`
    // sat in the vocabulary with nothing able to claim it (§32c/§37).
    const rows = await kindsFor(
      'genkey ed25519 | out @id\n\n"msg" | utf8 | ssh.sign key=@id namespace=file | out @sig'
    );
    const sig = rows.find((r) => r.label === "sig");
    expect(sig.role).toBe("sshsig");
    expect(sig.kind).toBe("sshsig");
  }, 60_000);

  it("resolves a JOSE token as one, which makes the shipped kind reachable", async () => {
    // Same cause, and the visible symptom was worse: `jose-token` matched
    // `role: "token"`, nothing emitted it, and the JWT reader was unreachable
    // from a notebook while every test passed.
    const rows = await kindsFor(
      'genkey ec/p256 | out @k\n\n"hello" | utf8 | jose.sign key=@k | out @tok'
    );
    const tok = rows.find((r) => r.label === "tok");
    expect(tok.role).toBe("token");
    expect(tok.kind).toBe("jose-token");
  }, 60_000);

  it("never throws on anything the engine emits", async () => {
    // Ambiguity is a build error by design; this is the guard that no real
    // artifact trips it.
    const rows = await kindsFor(`genkey ed25519 | out @kp

"x" | utf8 | inspect

"y" | utf8 | out @t`);
    expect(rows.length).toBeGreaterThan(3);
  });
});

describe("key artifacts resolve to the right card (§35)", () => {
  it("splits a keypair into public and private kinds", async () => {
    const { ast } = compileRecipe("genkey ed25519 | out @kp");
    const arts = await runRecipe(ast, {});
    const kinds = arts.map((a) => ({
      label: a.label,
      kind: resolveArtifactKind(a, ARTIFACT_KINDS, FALLBACK_KIND).id,
      alg: a.traits?.alg,
    }));
    const priv = kinds.find((k) => /private/.test(k.label));
    const pub = kinds.find((k) => /public/.test(k.label));
    expect(priv.kind).toBe("keypair-private");
    expect(pub.kind).toBe("keypair-public");
    // traits.alg is what KeyCard shows as the algorithm — the tag the recipe
    // named, not a value re-derived from the JWK.
    expect(priv.alg).toBe("ed25519");
    expect(pub.alg).toBe("ed25519");
  });

  it("gives the private half a publicView so a masked tile is not blank", () => {
    const priv = ARTIFACT_KINDS.find((k) => k.id === "keypair-private");
    expect(typeof priv.publicView).toBe("function");
    // The full view must never be the masked renderer.
    expect(priv.publicView).not.toBe(priv.view);
  });

  it("falls to the general key kind when no half is declared", () => {
    // The auto-emitted pipeline tip carries role "key" with no keypair tags.
    expect(
      resolveArtifactKind({ role: "key" }, ARTIFACT_KINDS, FALLBACK_KIND).id
    ).toBe("key");
    // …and the tagged halves still win, regardless of declaration order.
    // The public half's role is `public-key` now — the badge is the role, and
    // a public key badged KEY beside a private one badged KEY told the reader
    // nothing.
    expect(
      resolveArtifactKind(
        { role: "public-key", tags: ["keypair", "public"] },
        ARTIFACT_KINDS,
        FALLBACK_KIND
      ).id
    ).toBe("keypair-public");
  });

  it("orders the three public-key kinds by specificity, not declaration", () => {
    // One role, three producers. OpenPGP armor and a paired WebCrypto half
    // each carry a tag that narrows them; a lone public key (an `import spki`
    // tip, a projected `:public`) carries neither and must still land on a
    // key card rather than on the OpenPGP one or the fallback.
    const id = (a) => resolveArtifactKind(a, ARTIFACT_KINDS, FALLBACK_KIND).id;
    expect(id({ role: "public-key", tags: ["openpgp", "public-key"] })).toBe(
      "openpgp-public"
    );
    expect(id({ role: "public-key", tags: ["keypair", "public"] })).toBe(
      "keypair-public"
    );
    expect(id({ role: "public-key", tags: ["public"] })).toBe("public-key");
    expect(id({ role: "public-key" })).toBe("public-key");
  });

  it("gives a symmetric key its own kind, with no public-material actions", () => {
    // A secret key has no public half, so a fingerprint and a public line are
    // not "disabled" for it — they do not exist (§33d).
    const kind = resolveArtifactKind(
      { role: "secret-key", tags: ["secret"] },
      ARTIFACT_KINDS,
      FALLBACK_KIND
    );
    expect(kind.id).toBe("secret-key");
    expect(kind.actions).not.toContain("key.copyPublicLine");
    expect(kind.actions).not.toContain("key.copyFingerprint");
    expect(kind.actions).not.toContain("keyring.add");
  });
});

describe("OpenPGP keys resolve to their own kinds (§35e)", () => {
  it("splits gpg.genkey into openpgp-public and openpgp-private", async () => {
    const { ast } = compileRecipe('gpg.genkey email="k@example.com" | out @priv');
    const arts = await runRecipe(ast, {});
    const byKind = arts.map((a) => ({
      label: a.label,
      kind: resolveArtifactKind(a, ARTIFACT_KINDS, FALLBACK_KIND).id,
      sensitive: a.sensitive,
    }));
    const pub = byKind.find((k) => /public key/i.test(k.label));
    const priv = byKind.find((k) => k.label === "priv");
    expect(pub.kind).toBe("openpgp-public");
    expect(pub.sensitive).toBe(false);
    // The private half must NOT fall through to the generic key kind, whose
    // card parses JWK and would render an empty read-out for armor.
    expect(priv.kind).toBe("openpgp-private");
    expect(priv.sensitive).toBe(true);
  }, 60_000);

  it("never offers Publish on a private key", () => {
    // Not declared, so there is no button and nothing to reason about at
    // runtime — the strongest form of "this cannot happen".
    const priv = ARTIFACT_KINDS.find((k) => k.id === "openpgp-private");
    expect(priv.actions).not.toContain("key.publish");
    expect(priv.actions).not.toContain("keyring.publish");
  });

  it("gives the private half a publicView, so masked is not blank", () => {
    const priv = ARTIFACT_KINDS.find((k) => k.id === "openpgp-private");
    expect(typeof priv.publicView).toBe("function");
    expect(priv.publicView).not.toBe(priv.view);
  });
});

/**
 * The catalog's own expiry states (§48b/D5, and D3's lesson applied).
 *
 * D3 is the precedent that makes this a gate rather than a preference: the OTP
 * row hard-coded a step number that was current on the day it was written, so
 * the one section that exists to show a live countdown read **expired** for the
 * life of the repo. The certificate row had the same shape — an absolute ISO
 * date — and the verdict it now carries is exactly the kind of thing that
 * silently rots into a single permanent state.
 */
describe("the certificate rows show both verdicts, and cannot rot into one", () => {
  const certs = [...CATALOG_SRC.matchAll(/netType="certificate"[\s\S]*?expires:\s*([^,\n]+)/g)].map(
    (m) => m[1].trim()
  );

  it("draws two, because the verdict has two tones", () => {
    expect(certs.length).toBe(2);
  });

  it("dates them relative to now, never to the day the fixture was written", () => {
    // `RTCCertificate.expires` is about thirty days out by default, so a
    // relative date is the *truer* fixture as well as the durable one — a real
    // certificate is never a fixed calendar day.
    for (const c of certs) expect(c, c).toMatch(/Date\.now\(\)/);
    for (const c of certs) expect(c, c).not.toMatch(/20\d\d-\d\d-\d\d/);
    // One inside a month and one inside a week, so both tones are on the page.
    expect(certs.join(" ")).toMatch(/20 \* 86_400_000/);
    expect(certs.join(" ")).toMatch(/3 \* 86_400_000/);
  });
});
