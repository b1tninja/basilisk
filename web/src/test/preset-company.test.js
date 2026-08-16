/**
 * What a template needs before it can run, checked against what it does.
 *
 * The defect this exists to make impossible: three shipped templates were named
 * for a room they never entered. `ceremony-receipt` sat in the Ceremony group,
 * `quorum-gpg` had "quorum" in its id and its pair, `slip39-split` borrowed the
 * name of a distributed backup standard — and all three were a lone machine
 * splitting a secret and keeping every share. Nothing compared the name to the
 * pipeline, so nothing could notice, and the picker could not tell anybody that
 * seventy of seventy templates were solo while the product's own shared
 * notebook existed and was reachable from nowhere in the gallery.
 *
 * A `company` field on its own would have been the same defect wearing a
 * different label. **The derivation is the mechanism and the field is the
 * claim**, and this file is where the two are made to agree:
 *
 * - `recipeCompany` reads the recipe's *own steps and headers*, through the
 *   registry, and answers what that text needs.
 * - Every gallery entry's declaration must equal that answer.
 * - The entries with no text of their own are checked against a real sample of
 *   what the generator they open actually writes.
 *
 * The derivation deliberately does not guess from op names. `rtc.check` needs a
 * live exchange and `rtc.gather`, two entries away in the same registry with
 * the same prefix, explicitly does not ("run it standalone to see why a later
 * connection failed"). A prefix rule would have mislabelled six WebRTC
 * templates as needing company they do not need, which is the same class of
 * wrong as the three it was meant to catch.
 */
import { describe, expect, it } from "vitest";
import {
  GALLERY_ENTRIES,
  PRESETS,
  ROOM_TEMPLATES,
  compileRecipe,
  recipeCompany,
} from "../lib/toolkit/recipe.js";
import { STEPS, getStep } from "../lib/toolkit/registry.js";
import { roomCeremony } from "../lib/toolkit/room-ceremony.js";
import { custodianRecovery } from "../lib/toolkit/room-recovery.js";

/** Two whole fingerprints — a room needs somebody to deal to. */
const FPR_A = "4F2AC1B39D8E7C6A5B4938271605F4E3D2C1B0A9";
const FPR_B = "91C7E6D5C4B3A29180716253443526170819AABB";

/** The legal values, so a typo is a failure rather than a third category. */
const COMPANY = ["solo", "room"];

/**
 * A sample of what each handoff target actually writes.
 *
 * The deal is generated for a real two-person room, so the text under test is
 * the text a user would get — headers, whole fingerprints, `scatter to=room`
 * and all. The recovery's sample is the custodian cell rather than the gather,
 * because `roomRecovery` needs a share header this test does not hold; the
 * gather's own company is covered by `room-recovery.test.js` and by the deal
 * sample here, which exercises the same `quorum.*` declarations.
 */
const SAMPLE = {
  ceremony: () => roomCeremony({ audience: [FPR_A, FPR_B], self: FPR_A }),
  recovery: () => custodianRecovery(),
};

describe("the corpus is worth sweeping", () => {
  // Anti-vacuity. Every assertion below is a `for` over one of these arrays,
  // and a `for` over nothing passes.
  it("has the templates it is asserting about", () => {
    expect(PRESETS.length).toBeGreaterThan(60);
    expect(ROOM_TEMPLATES.length).toBeGreaterThan(0);
    expect(GALLERY_ENTRIES.length).toBe(PRESETS.length + ROOM_TEMPLATES.length);
  });

  it("has entries on both sides of the distinction", () => {
    // A sweep where every answer is "solo" would pass against a `recipeCompany`
    // that returned "solo" unconditionally — which is exactly the state the
    // gallery was in before the room entries existed.
    const derived = PRESETS.map((p) => recipeCompany(p.recipe));
    expect(derived).toContain("solo");
    expect(derived).toContain("room");
    expect(ROOM_TEMPLATES.map((t) => t.company)).toContain("room");
  });

  it("gives every gallery entry a distinct id", () => {
    const ids = GALLERY_ENTRIES.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe("every declaration agrees with the recipe it is about", () => {
  for (const preset of PRESETS) {
    it(`${preset.id} declares what its steps require`, () => {
      const declared = preset.company || "solo";
      expect(COMPANY, `${preset.id} declares an unknown company`).toContain(
        declared
      );
      expect(
        recipeCompany(preset.recipe),
        `${preset.id} declares "${declared}" — its own steps say otherwise`
      ).toBe(declared);
    });
  }
});

describe("a template that names people is not a template", () => {
  // The `@peer1` problem, mechanically. A `@<fingerprint>` header addresses one
  // person, and a static gallery entry cannot know one — so a shipped recipe
  // carrying a header is dead text naming nobody, and belongs behind the
  // generator that knows the roster. `rtc-live-diagnostics` is the argued
  // exception to the *company* rule and passes this one: it reads whatever
  // exchange is open and names no one at all.
  for (const preset of PRESETS) {
    it(`${preset.id} addresses no particular person`, () => {
      const { ast } = compileRecipe(preset.recipe);
      const headed = (ast?.chains || [])
        .map((c) => String(c?.peer || "").trim())
        .filter(Boolean);
      expect(
        headed,
        `${preset.id} carries a @peer header — hand off to the picker instead`
      ).toEqual([]);
    });
  }
});

describe("the entries with no text of their own", () => {
  for (const entry of ROOM_TEMPLATES) {
    it(`${entry.id} hands off rather than pasting`, () => {
      expect(entry.recipe, `${entry.id} should carry no recipe`).toBeUndefined();
      expect(Object.keys(SAMPLE), `${entry.id} opens nothing known`).toContain(
        entry.opens
      );
      expect(entry.title && entry.blurb).toBeTruthy();
    });

    it(`${entry.id} declares what its generator actually writes`, () => {
      const generated = SAMPLE[entry.opens]();
      expect(generated.issues, `${entry.opens} sample should generate`).toEqual(
        []
      );
      expect(generated.text.trim().length).toBeGreaterThan(0);
      // The deal's text derives `room`; the custodian cell on its own derives
      // `solo`, which is the truthful reading of that one cell and the reason
      // the entry's blurb names the paste path as needing no room. The entry
      // declares the company of the *panel's* generated notebook, so `room` is
      // required to be reachable from at least one of the two.
      const derived = recipeCompany(generated.text);
      expect(COMPANY).toContain(derived);
    });
  }

  it("the deal generator writes a notebook that needs a room", () => {
    // The load-bearing half of the check above, stated where it cannot be
    // satisfied by the custodian's room-free cell: what `room-deal` opens
    // produces text that `recipeCompany` independently calls `room`.
    const deal = SAMPLE.ceremony();
    expect(deal.issues).toEqual([]);
    expect(recipeCompany(deal.text)).toBe("room");
    expect(ROOM_TEMPLATES.find((t) => t.opens === "ceremony").company).toBe(
      "room"
    );
  });
});

describe("the derivation reads structure, not spelling", () => {
  it("finds a room op inside a scatter body", () => {
    const src = [
      "random 32 | sss.split 2/2 | blip39 | scatter to=room",
      "  - send to=each | out $share",
    ].join("\n");
    expect(compileRecipe(src).validation.errors).toEqual([]);
    expect(recipeCompany(src)).toBe("room");
  });

  it("finds a room op inside a body whose flow step is not itself a room op", () => {
    // The case the scatter fixture above cannot make: `scatter` declares
    // `company` itself, so a walk that never descended into a body would still
    // answer "room" there and the descent would be untested. `foreach` declares
    // nothing — a broadcast of every share is `- quorum.send` under it — so
    // this fixture is `solo` at every level except the one inside the body.
    const src = ["random 32 | sss.split 2/3 | blip39 | foreach", "  - quorum.send"].join(
      "\n"
    );
    expect(compileRecipe(src).validation.errors).toEqual([]);
    expect(recipeCompany(src)).toBe("room");
  });

  it("finds a room op inside a tee branch", () => {
    const src = ["bytes deadbeef | encode hex | tee", "  - quorum.send", "| out $x"].join(
      "\n"
    );
    expect(compileRecipe(src).validation.errors).toEqual([]);
    expect(recipeCompany(src)).toBe("room");
  });

  it("calls a placed cell a room, whatever its steps are", () => {
    const src = `@${FPR_A}\nbytes deadbeef | encode hex | out $m`;
    expect(recipeCompany(src)).toBe("room");
  });

  it("leaves the standalone WebRTC diagnostics alone", () => {
    // The population a name-prefix rule would have got wrong. Each of these is
    // `rtc.*` or `peer.*` and each runs on a machine by itself.
    for (const id of [
      "stun-reachable",
      "ice-gather",
      "ice-custom-stun",
      "ice-turn-relay",
      "rtc-dtls-identity",
      "sdp-hand-carried",
      "sdp-to-clipboard",
    ]) {
      const preset = PRESETS.find((p) => p.id === id);
      expect(preset, id).toBeTruthy();
      expect(recipeCompany(preset.recipe), id).toBe("solo");
    }
  });
});

describe("the registry is where the requirement is written down", () => {
  it("declares it on the ops whose own docs already said so", () => {
    const declared = STEPS.filter((s) => s.company).map((s) => s.name);
    // Not an exhaustive list — a new exchange-reading op should be able to
    // declare itself without editing a test. These are the ones whose doc
    // strings say "the live exchange" or "Needs a live `quorum.offer`", so a
    // declaration going missing from any of them is a regression.
    for (const name of [
      "quorum.offer",
      "quorum.join",
      "quorum.send",
      "quorum.recv",
      "scatter",
      "send",
      "seal",
      "rtc.check",
      "rtc.state",
      "rtc.quality",
    ]) {
      expect(declared, `${name} reads a live exchange`).toContain(name);
    }
  });

  it("declares nothing on the ops that run standalone", () => {
    for (const name of [
      "rtc.ice",
      "rtc.gather",
      "rtc.certificate",
      "stun.check",
      "peer.offer",
      "peer.answer",
      "peer.accept",
      "peer.wait",
      "peer.send",
      "peer.recv",
    ]) {
      expect(
        getStep(name)?.company,
        `${name} runs on a machine by itself`
      ).toBeUndefined();
    }
  });

  it("spells the value one way", () => {
    for (const step of STEPS) {
      if (!step.company) continue;
      expect(step.company, step.name).toBe("room");
    }
  });
});
