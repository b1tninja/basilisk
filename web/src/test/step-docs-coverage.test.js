/**
 * An op with no reference has a reason, and the reason is written down.
 *
 * `step-docs.js` maps op names to the standard that defines them, and the tool
 * card renders one quiet link from it. 132 ops, 103 of them cited when this
 * file was written — and the other 29 were simply absent, indistinguishable
 * from 29 oversights.
 *
 * They are not one thing. `hkp.filter` has no external spec because filtering a
 * recipient list is not a protocol; `foreach` has none because there is no RFC
 * for a recipe language and never will be; `agent.sign` has none because it
 * emits an OpenPGP signature *or* an sshsig depending on the key, and no one
 * document covers both. Three different arguments, and none of them was
 * recoverable from the map, which said nothing about any of them.
 *
 * ## Why the fix is a list and not a coverage number
 *
 * The tempting version of this test is "every op must be cited". That closes by
 * pointing `foreach` at something loosely related, and a reference that does not
 * define the behaviour is a claim the code does not hold — the defect class this
 * repo cares most about, dressed as documentation. So the pin runs the other
 * way: an op may be uncited, but only by name, and only with a reason.
 *
 * The list may only shrink. Four things fail:
 *
 * - an op with no citation that is not on the list (a *new* gap must be argued,
 *   not quietly joined to a crowd);
 * - a listed op that has since been cited (the entry stopped being true);
 * - a listed name that is no longer an op (the entry outlived its subject);
 * - a reference for a name that is not an op (the mirror image — this is how
 *   `rtc.offer` and `rtc.answer` sat in the map for a release after
 *   `step-names.js` started migrating both away at parse time).
 *
 * `glyph-shadowing.test.js` and `dead-css-producers.test.js` hold their
 * exemptions on the same terms, and this file follows them deliberately.
 */
import { describe, expect, it } from "vitest";
import { getStep, listSteps } from "../lib/toolkit/registry.js";
import { docsUrlFor, listStepDocs } from "../lib/toolkit/step-docs.js";

/**
 * Ops with no reference, and why each one has none.
 *
 * The reason is the point. An entry whose reason is "Basilisk-specific" is
 * doing no work — the next reader has to re-derive whether that is true, which
 * is the state this file was written to end. Say what the op does and what
 * document would have to exist for it to be citable.
 *
 * This list may only shrink.
 *
 * @type {Record<string, string>}
 */
const UNCITED = {
  // ── The recipe language. There is no RFC for `foreach`, and the absence is
  //    permanent rather than pending: these ops describe how a Basilisk
  //    notebook is written, not what any two machines agree on the wire.
  foreach:
    "maps a body over a `shares` collection and yields a `bundle` of per-iteration tips; " +
    "both the loop form and `bundle` are this app's recipe grammar",
  scatter:
    "deals share i to member i in the canonical audience order both machines derive and " +
    "neither chooses; nothing external defines that ordering",
  lit: "the parser's own spelling for a stem literal (`\"hello\"`, `0xff`, `true`) — never written as an op at all",
  in: "loads a live `$slot` a prior `out` registered; slots exist only for the duration of a notebook run",
  select:
    "projects a member of the pipeline value (`public` / `private` / `:key`), so it is defined " +
    "over this app's tip types rather than over any format",
  as:
    "casts the tip. Two of its nine targets (`key`, `keypair`) do call WebCrypto, but the other " +
    "seven — `master`, `scalar`, `opaque`, `public`, `private`, `int`, `bool` — are retags in " +
    "Basilisk's type lattice, so citing importKey would describe a fifth of the op",
  inspect: "an openssl-style human dump of the current value; a rendering, not a format",
  tee: "forks a side chain on a clone and leaves the stem unchanged; pure recipe control flow",
  peek: "a side inspect snapshot — `tee` with `inspect` in it, and uncited for the same reason",

  // ── Ports and tiles. These are how a value enters or leaves the notebook UI.
  input: "free-form text pasted or dropped at run time; the paste is the whole of it",
  text: "emits a message tile in the notebook. A UI act, with no bytes of its own",
  out: "emits a file tile and registers a live `$slot`; the slot registry is Basilisk's",
  publish:
    "marks the one place a recipe says a value may leave the machine, and `planRun` reads it to " +
    "decide what a handoff may carry — a boundary declaration in this app's model, not a transport",

  // ── The vault. `agent.*` keeps the private key inside and hands the pipeline
  //    the result, which is a Basilisk arrangement whatever the key is.
  "agent.sign":
    "`format=auto` emits an OpenPGP signature for a PGP key and an sshsig for an SSH key, chosen " +
    "at run time. RFC 9580 would be a false claim on the sshsig branch and PROTOCOL.sshsig a false " +
    "claim on the other, and no document covers both",
  "agent.unlock":
    "exports the stored private key into the run; what it emits depends on the stored kind " +
    "(`openpgp-key`, or a live WebCrypto keypair). The vault, not a format",
  "agent.pub":
    "returns the `publicArmored` string the vault already holds for a fingerprint. A lookup — it " +
    "produces no bytes, so there is nothing for a spec to define",
  "agent.list":
    "lists vault metadata as JSON; the shape (fingerprint, uid, protection, lastUsedAt) is this app's record",
  "agent.save": "writes into the keyring of whoever runs the recipe. The store is Basilisk's",

  // ── Collection plumbing. The *contents* are specified — BIP-39 mnemonics,
  //    RFC 9580 fingerprints — and the ops that make them cite it. Assembling,
  //    indexing, filtering and merging a list are not those ops.
  shares:
    "assembles a `shares` set out of the pipe, `with=$slot` and the Inputs tray. The mnemonics " +
    "inside are BIP-39 and `blip39` cites it; the precedence rules and `tray=merge` are this app's",
  at:
    "a 1-based index or slice into a `shares` collection, compile-checked against the share count " +
    "`sss.split` stamped on the type. A selector over a Basilisk type",
  "hkp.filter":
    "filters a `recipients` list by approval state and encrypt capability. Nothing crosses the " +
    "wire; the approval model is Basilisk's. `hkp.get`/`hkp.search`, which do speak the protocol, " +
    "cite draft-shaw-openpgp-hkp-00",
  "recipients.merge":
    "merges two recipient lists, deduping by fingerprint. The fingerprint is RFC 9580's; the merge is a list operation",
  "hkp.cache":
    "lists or clears the device pubkey cache. The store is IndexedDB, but this is not an IndexedDB " +
    "call the way `clipboard.read` is a clipboard call: the record shape, the 30-day TTL, the " +
    "500-key LRU and the origin taxonomy all live in `lib/pubkey-cache.js`, and MDN's IndexedDB " +
    "page defines none of them",

  // ── The room's own ceremonies.
  "entropy.pool":
    "commit-then-reveal randomness across a live room. Commit-and-reveal is a named primitive and " +
    "Wikipedia would take the link the way `dkg.run` and `vss.*` do — but what a reader needs is " +
    "the pool value's definition, and that is `entropy-pool.js`'s: the participant id bound into " +
    "the commitment preimage, the reveals sorted by id so arrival order is not an input, the " +
    "`basilisk.run-manifest/entropy-pool/v1` domain prefix, and the rule that a missing reveal " +
    "stalls the round rather than shrinking the pool. A commitment-scheme page defines none of " +
    "those four, and they are the whole protocol",

  // ── Open, and recorded as open rather than settled.
  //
  // These four are the ones a later pass may well cite, and the reason they are
  // not cited *here* is not that the argument fails. `glyph-shadowing.test.js`
  // keeps an `Activity` row on the same terms: an entry can record a decision
  // nobody has made yet, as long as it says so.
  //
  // The blocker is ownership, not doubt: `toolkit-type-registry.test.js` already
  // asserts `docsUrlFor` returns null for all four, and citing one without
  // editing that file in the same change turns a documentation improvement into
  // a red suite.
  "run.manifest":
    "OPEN — same family as `run.receipt`, which cites RFC 8785 on the argument that what is " +
    "normative about a receipt is the deterministic serialization its digest and signature are " +
    "taken over. `manifest.js` uses `receipt.js`'s own `canonicalJson` and says in its header that " +
    "a second one would be a second answer; by the receipt's own reasoning this is citable",
  "run.attest":
    "OPEN — `attest.js` serializes through the same `canonicalJson` and digests the manifest with " +
    "`manifestDigest`. Same argument as `run.manifest`, same RFC 8785",
  playbook:
    "OPEN — `playbook.js` serializes through the same `canonicalJson`. Same argument again; the " +
    "content is recipe text and prose, but the digest that makes it checkable is the canonical form",
  "agent.decrypt":
    "OPEN — unlike `agent.sign` this one is not polymorphic: it refuses every non-PGP key by name, " +
    "reads an armored OpenPGP message and calls openpgp's `decrypt`. The bytes are RFC 9580's and " +
    "the vault only decides where the key came from, which is the same shape as `seal` inheriting " +
    "`gpg.encrypt`'s reference",
};

describe("every op without a reference has a written reason", () => {
  const steps = listSteps();
  const docs = listStepDocs();
  const stepNames = new Set(steps.map((s) => s.name));

  it("is measuring the real registry and the real map", () => {
    // An empty sweep passes every assertion below it.
    expect(steps.length, "listSteps() returned almost nothing").toBeGreaterThan(100);
    expect(Object.keys(docs).length, "STEP_DOCS is empty").toBeGreaterThan(80);
    expect(docsUrlFor("genkey")?.url, "a known citation stopped resolving").toContain("generateKey");
    expect(Object.keys(UNCITED).length, "the exemption list is empty").toBeGreaterThan(20);
  });

  it("cites every op that is not written down here", () => {
    const unexplained = steps
      .filter((s) => !docsUrlFor(s) && !(s.name in UNCITED))
      .map((s) => `${s.name} (${s.toolbox})`)
      .sort();
    expect(
      unexplained,
      "these ops have no reference and no reason. Add the reference if a standard genuinely " +
        "defines what the op does — or add the op to UNCITED with the argument for why none " +
        "does. Do not pick something adjacent to close the gap:\n" +
        unexplained.join("\n")
    ).toEqual([]);
  });

  it("keeps no exemption for an op that has since been cited", () => {
    // The list is evidence that nothing defines these ops. The moment one is
    // cited the entry is a false statement sitting next to a true link.
    const nowCited = Object.keys(UNCITED)
      .filter((name) => docsUrlFor(name))
      .map((name) => `${name} → ${docsUrlFor(name)?.label}`);
    expect(
      nowCited,
      `these are cited now, so their exemption is no longer true and must be deleted: ${nowCited.join(", ")}`
    ).toEqual([]);
  });

  it("keeps no exemption for a name that has stopped being an op", () => {
    const gone = Object.keys(UNCITED).filter((name) => !getStep(name));
    expect(
      gone,
      `these are exempted from citation but are not ops any more, so the exemption has ` +
        `outlived what it was about: ${gone.join(", ")}`
    ).toEqual([]);
  });

  it("gives every exemption a reason that says something", () => {
    // "Basilisk-specific" is not a reason — it is the conclusion, and it leaves
    // the next reader to re-derive the argument this list exists to preserve.
    const thin = Object.entries(UNCITED)
      .filter(([, why]) => typeof why !== "string" || why.trim().length < 40)
      .map(([name]) => name);
    expect(thin, `these exemptions have no usable reason: ${thin.join(", ")}`).toEqual([]);
  });

  it("keeps no reference for a name that is not an op", () => {
    // The other direction, and the one that actually happened: `rtc.offer` and
    // `rtc.answer` kept their entries after §55c retired them, while
    // `step-names.js` migrated every occurrence to `peer.offer`/`peer.answer`
    // at parse time — so no name `docsUrlFor` ever saw could reach either row.
    const orphans = Object.keys(docs).filter((name) => !stepNames.has(name));
    expect(
      orphans,
      `these references are for names no step carries, so nothing can ever render them — ` +
        `either the op was renamed and the entry did not follow, or it was retired and the ` +
        `entry outlived it: ${orphans.join(", ")}`
    ).toEqual([]);
  });

  it("gives the source form of `import` the same reference as `import`", () => {
    // `keypair` delegates to the very same `importKey` call, so a differing
    // reference — or a missing one, which is where it sat — would describe a
    // difference in what WebCrypto is handed that does not exist. Pinned the
    // way the `seal`/`send` delegations already are.
    expect(docsUrlFor("keypair")).toEqual(docsUrlFor("import"));
    expect(docsUrlFor("keypair")?.url).toBe(
      "https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey"
    );
  });
});
