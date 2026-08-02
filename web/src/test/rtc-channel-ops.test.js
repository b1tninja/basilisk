/**
 * `rtc.send` / `rtc.recv` — the channel ops split out of `quorum.*`.
 *
 * The boundary being tested: `quorum.*` owns the exchange (room, roster,
 * lifecycle); `rtc.*` owns connection primitives, including reading and
 * writing a data channel. Renaming was not cosmetic — it lets these work on
 * any channel rather than only inside a quorum room.
 */
import { describe, expect, it } from "vitest";
import { getStep, listSteps } from "../lib/toolkit/registry.js";
import { legacyRemovalHint, migrateRecipe } from "../lib/toolkit/step-names.js";
import { inferSourceType, formatType } from "../lib/toolkit/types.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";

describe("prefix boundary", () => {
  it("leaves quorum.* holding only session lifecycle", () => {
    const quorum = listSteps()
      .filter((s) => s.name.startsWith("quorum."))
      .map((s) => s.name)
      .sort();
    expect(quorum).toEqual(["quorum.close", "quorum.join", "quorum.offer"]);
  });

  it("puts channel traffic under rtc.*, beside the channel diagnostics", () => {
    for (const name of ["rtc.send", "rtc.recv", "rtc.stats"]) {
      expect(getStep(name)?.shelf, name).toBe("channel");
    }
    // The old names are retired from live parse, like every other rename here.
    expect(getStep("quorum.send")).toBeFalsy();
    expect(getStep("quorum.recv")).toBeFalsy();
  });

  it("migrates old recipes", () => {
    expect(migrateRecipe("quorum.offer | input | quorum.send").recipe).toBe(
      "quorum.offer | input | rtc.send"
    );
    expect(migrateRecipe("quorum.recv | quorum.close").recipe).toBe(
      "rtc.recv | quorum.close"
    );
  });
});

describe("rtc.recv output shape follows count (§30c)", () => {
  const recv = () => getStep("rtc.recv");

  it("stays text for a single message, so two-party reads are unchanged", () => {
    expect(recv().effectiveIo({ count: "1" }).output).toBe("text");
    expect(recv().effectiveIo({}).output).toBe("text");
    expect(formatType(inferSourceType("rtc.recv", { count: "1" }))).toBe("text/opaque");
  });

  it("becomes a bundle for several, because a mesh has no single next message", () => {
    for (const count of ["3", "all"]) {
      expect(recv().effectiveIo({ count }).output, count).toBe("bundle");
      expect(formatType(inferSourceType("rtc.recv", { count })), count).toMatch(/^bundle/);
    }
  });

  it("agrees between effectiveIo and inferSourceType", () => {
    // These are consulted by different layers — the caret uses one, the type
    // walker the other. Disagreeing would let `gpg.verify` be offered after a
    // read that actually produced a collection.
    for (const count of ["1", "2", "all", undefined]) {
      const io = recv().effectiveIo({ count });
      const inferred = inferSourceType("rtc.recv", { count });
      expect(inferred.base, String(count)).toBe(io.output);
    }
  });

  it("counts bundle elements, not bytes", () => {
    // `bundle/3B` would claim three bytes; it is three messages.
    expect(formatType(inferSourceType("rtc.recv", { count: "3" }))).toBe("bundle/×3");
  });

  it("lets foreach consume a multi-message read", () => {
    const { validation } = compileRecipe(
      "quorum.offer | rtc.recv count=all | foreach\n  - out @msg"
    );
    expect(validation.errors.map((e) => e.message)).toEqual([]);
  });
});

describe("rtc.send addressing", () => {
  it("takes an optional peer target, defaulting to the exchange's broadcast", () => {
    const to = getStep("rtc.send").params.find((p) => p.name === "to");
    expect(to).toBeTruthy();
    expect(to.default).toBe("");
    expect(to.positional).toBe(true);
  });

  it("parses both forms", () => {
    expect(compileRecipe("quorum.offer | input | rtc.send").validation.ok).toBe(true);
    const addressed = compileRecipe("quorum.offer | input | rtc.send AABBCCDD");
    expect(addressed.validation.ok).toBe(true);
    expect(addressed.ast.chains[0].steps[2].params.to).toBe("AABBCCDD");
  });
});

describe("48a naming audit — camelCase rtc ops renamed, not aliased", () => {
  // The audit found six; rtc.statsReport was a seventh with the same defect.
  const RENAMES = {
    "rtc.gatherCandidates": "rtc.gather",
    "rtc.checkConnectivity": "rtc.check",
    "rtc.connectionState": "rtc.state",
    "rtc.dataChannelStats": "rtc.stats",
    // These two retarget past the names they used to migrate to: `rtc.offer`
    // and `rtc.answer` are themselves retired now (§55c), and this table is
    // applied in a single pass, so migrating one dead name to another would
    // leave a recipe that still does not parse.
    "rtc.createOffer": "peer.offer",
    "rtc.createAnswer": "peer.answer",
    "rtc.statsReport": "rtc.quality",
  };

  it("registers each new name and retires the old one", () => {
    for (const [oldName, newName] of Object.entries(RENAMES)) {
      expect(getStep(newName), newName).toBeTruthy();
      expect(getStep(oldName), oldName).toBeFalsy();
    }
  });

  it("migrates old recipes, camelCase included", () => {
    expect(
      migrateRecipe("rtc.gatherCandidates ice=@ice | out @cands").recipe
    ).toBe("rtc.gather ice=@ice | out @cands");
    expect(migrateRecipe("rtc.createOffer | rtc.createAnswer | out @a").recipe).toBe(
      "peer.offer | peer.answer | out @a"
    );
    // And the one-hop rename lands in the same place, so a notebook saved at
    // either vintage upgrades to a recipe that parses.
    expect(migrateRecipe("rtc.offer | rtc.answer | out @a").recipe).toBe(
      "peer.offer | peer.answer | out @a"
    );
    expect(migrateRecipe("rtc.statsReport | out @q").recipe).toBe(
      "rtc.quality | out @q"
    );
  });

  it("hints the replacement when the old token is typed", () => {
    expect(legacyRemovalHint("rtc.connectionState")).toContain("rtc.state");
    expect(legacyRemovalHint("rtc.dataChannelStats")).toContain("rtc.stats");
  });

  it("enforces the convention for every namespaced op, so this cannot regress", () => {
    // Every real namespaced op is namespace.singlelowercaseword — gpg.encrypt,
    // hkp.get, webauthn.prf. A new camelCase or multi-dot name fails here.
    for (const s of listSteps()) {
      if (!s.name.includes(".")) continue;
      expect(s.name, s.name).toMatch(/^[a-z0-9]+\.[a-z0-9]+$/);
    }
  });
});
