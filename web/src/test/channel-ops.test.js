/**
 * The data-channel shelf, and two boundaries that are easy to conflate.
 *
 * **The namespace boundary**: an op lives in the namespace that owns the key it
 * uses. `quorum.send`/`quorum.recv` encrypt and decrypt under the pairwise
 * session key `derivePairwiseSessionKey` mints, so they are `quorum.*`;
 * `peer.send`/`peer.recv` write raw bytes to a managed channel protected by
 * DTLS alone, so they are `peer.*`; and `rtc.*` keeps the primitives that need
 * neither — ICE, certificates, stats.
 *
 * These two were briefly `rtc.send`/`rtc.recv`, on the argument that channel
 * traffic is a transport primitive, and this file used to assert that position.
 * It did not hold: both dispatch to `execQuorumSend`/`execQuorumRecv`, which
 * refuse without a live exchange, address peers by PGP fingerprint, and encrypt
 * under a key `lib/notebook/` derives. The payoff claimed for the move — "works
 * on any data channel" — is delivered by `peer.send`/`peer.recv` instead.
 *
 * **The toolbox boundary**, which is a different question with a different
 * answer: which drawer category an op is filed under. The test there is
 * whether it is a WebRTC built-in. It is not, for every `quorum.*` op — the
 * room comes from an OpenPGP audience, the invite from a relay — so the five
 * of them are their own toolbox, sitting on top of WebRTC rather than inside
 * it. Nothing about that touches their names.
 *
 * Conflating the two is how the wrong lesson gets re-derived. "Do not re-split
 * the channel ops out of `quorum.*`" is about the **name** and still holds
 * absolutely; `quorum.send` is not becoming `rtc.send` again. Moving it out of
 * the `webrtc` **toolbox** is not that move, and does not weaken it.
 */
import { describe, expect, it } from "vitest";
import { getStep, listSteps } from "../lib/toolkit/registry.js";
import {
  LEGACY_STEP_MIGRATE,
  legacyRemovalHint,
  migrateRecipe,
} from "../lib/toolkit/step-names.js";
import { inferSourceType, formatType } from "../lib/toolkit/types.js";
import { compileRecipe } from "../lib/toolkit/recipe.js";

describe("prefix boundary", () => {
  it("gives quorum.* the exchange and the traffic encrypted under its keys", () => {
    const quorum = listSteps()
      .filter((s) => s.name.startsWith("quorum."))
      .map((s) => s.name)
      .sort();
    expect(quorum).toEqual([
      "quorum.close",
      "quorum.join",
      "quorum.offer",
      "quorum.recv",
      "quorum.send",
    ]);
  });

  it("leaves rtc.* holding only what needs no session key", () => {
    // Every surviving `rtc.*` op is ICE, DTLS or a stats read. None of them
    // reads `peer.sessionKey`, and none is meaningless without a `quorum.*`
    // exchange — which is exactly what `rtc.send`/`rtc.recv` were not.
    const rtc = listSteps()
      .filter((s) => s.name.startsWith("rtc."))
      .map((s) => s.name)
      .sort();
    expect(rtc).toEqual([
      "rtc.certificate",
      "rtc.check",
      "rtc.gather",
      "rtc.ice",
      "rtc.quality",
      "rtc.restart",
      "rtc.state",
      "rtc.stats",
    ]);
  });

  it("keeps both send/recv pairs on the Data channel shelf", () => {
    // The shelf names the phase of the errand — getting bytes across a channel
    // — not the namespace, and both pairs are still on it. The shelf key is
    // what `glyphIdFor` resolves through (op → shelf → toolbox), so keeping it
    // means `quorum.send` and `peer.send` carry the identical two-arrow mark
    // under an identical "Data channel" header even though the drawer now
    // files them one category apart. That parallel is free: SHELF_META is a
    // global map while the drawer's grouping is per-toolbox.
    for (const name of [
      "quorum.send",
      "quorum.recv",
      "peer.send",
      "peer.recv",
      "rtc.stats",
    ]) {
      expect(getStep(name)?.shelf, name).toBe("channel");
    }
  });

  it("files the exchange in its own toolbox, and leaves the shelf alone", () => {
    // The toolbox answers a different question from the shelf and from the
    // namespace. `quorum.send` owns its *name* because it owns the key
    // (4fe3322, and the header comment above) — that is not in question here
    // and did not change. What changed is which drawer it is filed in: the
    // `webrtc` category is for WebRTC built-ins, and a room derived from an
    // OpenPGP audience is not one.
    for (const name of ["quorum.offer", "quorum.join", "quorum.close"]) {
      expect(getStep(name)?.toolbox, name).toBe("quorum");
      expect(getStep(name)?.shelf, name).toBe("exchange");
    }
    for (const name of ["quorum.send", "quorum.recv"]) {
      expect(getStep(name)?.toolbox, name).toBe("quorum");
    }
    for (const name of ["peer.send", "peer.recv", "rtc.stats"]) {
      expect(getStep(name)?.toolbox, name).toBe("webrtc");
    }
  });

  it("admits only WebRTC built-ins to the WebRTC toolbox", () => {
    // The criterion, asserted rather than described: every op in the `webrtc`
    // toolbox wraps something a browser ships. `rtc.*` is the specification's
    // own prefix (`RTCPeerConnection`, `RTCCertificate`, `RTCDataChannel`),
    // `peer.*` names that central object, and `stun.check` is a gather against
    // a STUN server. Nothing else may be filed here — the previous occupants
    // were five `quorum.*` ops and `dkg.run`, and `WEBRTC-TOOLBOX.md` §8 had
    // already called that group "not an MDN section".
    const webrtc = listSteps()
      .filter((s) => s.toolbox === "webrtc")
      .map((s) => s.name)
      .sort();
    expect(webrtc).toEqual([
      "peer.accept",
      "peer.answer",
      "peer.close",
      "peer.offer",
      "peer.recv",
      "peer.send",
      "peer.wait",
      "rtc.certificate",
      "rtc.check",
      "rtc.gather",
      "rtc.ice",
      "rtc.quality",
      "rtc.restart",
      "rtc.state",
      "rtc.stats",
      "stun.check",
    ]);
    for (const name of webrtc) {
      expect(name, `${name} is not in a WebRTC namespace`).toMatch(
        /^(rtc|peer|stun)\./
      );
    }
  });

  it("files dkg.run with the VSS family whose scheme it runs", () => {
    // It was on the WebRTC toolbox's `peer` shelf because a live exchange is
    // its transport. Transport is not a filing rule anywhere else here —
    // `rtc.check`, `rtc.state`, `rtc.stats`, `rtc.quality` and `rtc.restart`
    // all need one too. What it *is* is Feldman VSS over P-256, which is what
    // the four `vss.*` ops are, and it was already wearing their mark.
    const dkg = getStep("dkg.run");
    expect(dkg?.toolbox).toBe("sss");
    expect(dkg?.shelf).toBe("split");
    expect(dkg?.glyph).toBe(getStep("vss.split")?.glyph);
  });

  it("retires the transport-layer names rather than aliasing them", () => {
    expect(getStep("rtc.send")).toBeFalsy();
    expect(getStep("rtc.recv")).toBeFalsy();
    expect(legacyRemovalHint("rtc.send")).toContain("quorum.send");
    expect(legacyRemovalHint("rtc.recv")).toContain("quorum.recv");
    expect(legacyRemovalHint("rtc.send")).toContain("Upgrade recipe");
  });

  it("migrates old recipes", () => {
    expect(migrateRecipe("quorum.offer | input | rtc.send").recipe).toBe(
      "quorum.offer | input | quorum.send"
    );
    expect(migrateRecipe("rtc.recv | quorum.close").recipe).toBe(
      "quorum.recv | quorum.close"
    );
    // Addressed and parameterised forms keep their arguments.
    expect(migrateRecipe("rtc.send AABBCCDD | out @sent").recipe).toBe(
      "quorum.send AABBCCDD | out @sent"
    );
    expect(migrateRecipe("rtc.recv count=all wait=5000").recipe).toBe(
      "quorum.recv count=all wait=5000"
    );
  });

  it("does not oscillate: the inverse entries are gone, not kept beside these", () => {
    // `migrateRecipe` applies its table in a single pass over the keys, longest
    // first. While `quorum.send → rtc.send` also existed it would fire *before*
    // `rtc.send → quorum.send` and rewrite a correct recipe out and back —
    // reporting two migrations that cancel, and one dropped entry away from
    // silently retiring a name that parses. So: a current recipe is a fixed
    // point with no reported changes, and a migrated one is too.
    const current = "quorum.offer | input | quorum.send\n\nquorum.recv | quorum.close";
    expect(migrateRecipe(current).recipe).toBe(current);
    expect(migrateRecipe(current).changes).toEqual([]);

    const once = migrateRecipe("quorum.offer | input | rtc.send\n\nrtc.recv | quorum.close");
    expect(once.recipe).toBe(current);
    expect(migrateRecipe(once.recipe).recipe).toBe(once.recipe);
    expect(migrateRecipe(once.recipe).changes).toEqual([]);
    expect(once.changes.map((c) => `${c.from}→${c.to}`).sort()).toEqual([
      "rtc.recv→quorum.recv",
      "rtc.send→quorum.send",
    ]);
    // And what the migration produced is what the parser accepts.
    expect(compileRecipe(once.recipe).validation.ok).toBe(true);
  });

  it("never migrates a name onto one this table also retires", () => {
    // The single-pass rule stated once for the whole table, rather than per
    // rename. A target that is itself a key only survives if it happens to sort
    // later, which is not a property anyone should have to reason about — and
    // `send`/`recv` are the pair that made it worth pinning, having been on
    // both sides of this table at different times.
    const keys = new Set(Object.keys(LEGACY_STEP_MIGRATE));
    for (const [from, to] of Object.entries(LEGACY_STEP_MIGRATE)) {
      expect(keys.has(to), `${from} → ${to}, which is itself retired`).toBe(false);
    }
  });
});

describe("quorum.recv output shape follows count (§30c)", () => {
  const recv = () => getStep("quorum.recv");

  it("stays text for a single message, so two-party reads are unchanged", () => {
    expect(recv().effectiveIo({ count: "1" }).output).toBe("text");
    expect(recv().effectiveIo({}).output).toBe("text");
    expect(formatType(inferSourceType("quorum.recv", { count: "1" }))).toBe("text/opaque");
  });

  it("becomes a bundle for several, because a mesh has no single next message", () => {
    for (const count of ["3", "all"]) {
      expect(recv().effectiveIo({ count }).output, count).toBe("bundle");
      expect(formatType(inferSourceType("quorum.recv", { count })), count).toMatch(/^bundle/);
    }
  });

  it("agrees between effectiveIo and inferSourceType", () => {
    // These are consulted by different layers — the caret uses one, the type
    // walker the other. Disagreeing would let `gpg.verify` be offered after a
    // read that actually produced a collection.
    for (const count of ["1", "2", "all", undefined]) {
      const io = recv().effectiveIo({ count });
      const inferred = inferSourceType("quorum.recv", { count });
      expect(inferred.base, String(count)).toBe(io.output);
    }
  });

  it("counts bundle elements, not bytes", () => {
    // `bundle/3B` would claim three bytes; it is three messages.
    expect(formatType(inferSourceType("quorum.recv", { count: "3" }))).toBe("bundle/×3");
  });

  it("lets foreach consume a multi-message read", () => {
    const { validation } = compileRecipe(
      "quorum.offer | quorum.recv count=all | foreach\n  - out @msg"
    );
    expect(validation.errors.map((e) => e.message)).toEqual([]);
  });
});

describe("quorum.send addressing", () => {
  it("takes an optional peer target, defaulting to the exchange's broadcast", () => {
    const to = getStep("quorum.send").params.find((p) => p.name === "to");
    expect(to).toBeTruthy();
    expect(to.default).toBe("");
    expect(to.positional).toBe(true);
  });

  it("parses both forms", () => {
    expect(compileRecipe("quorum.offer | input | quorum.send").validation.ok).toBe(true);
    const addressed = compileRecipe("quorum.offer | input | quorum.send AABBCCDD");
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
