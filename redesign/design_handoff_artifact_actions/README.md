# Handoff: Artifacts that know what they are

Design pass for the capability in [BRIEF.md](./BRIEF.md): one declared
artifact-kind registry replacing `OutputList`'s if/else renderer chain, a common
tile anatomy, and dispositions (Add to keyring, Publish, Print cards) as tile
actions rather than pipeline steps. **Design only** — nothing under `web/` was
touched; implementation happens from these documents.

## Reading order

1. **[BRIEF.md](./BRIEF.md)** — the capability brief. Binding on facts; its
   design suggestions are answered, and two are argued against (see below).
2. **[ARTIFACT-ACTIONS-DESIGN.md](./ARTIFACT-ACTIONS-DESIGN.md)** — the
   decisions, §32–§38:
   - **§32** the kind registry: why the real problem is that
     `artifactMetaFromType` is dead code and the role vocabulary is two
     disagreeing vocabularies; matching on `(role, tags)`; the projection as
     floor and the emit-site declaration as override; normative `ArtifactKind`
     shape; the three existing renderers as entries; the honest no-match
     fallback.
   - **§33** the common base: tile anatomy, the three-group action row, the
     global action table with injected services, the absent-vs-disabled rule,
     masking, receipt weights, keyboard and focus.
   - **§34** tiers and confirmation: inert / local / outward, why Publish stops
     being brand-filled, what Copy does on a masked private key and the general
     mask rule that decides it, §27's banner grammar reused minus its grants,
     and the one local confirmation (the vault's silent overwrite).
   - **§35** the key artifacts: what a keypair renders as today and why,
     two-good-tiles over one merged tile, the key card, the masked private tile
     that is no longer blank, Add to keyring against the real multi-kind vault.
   - **§36** auditability: accept the split, with an Activity log carrying the
     receipt's digest discipline. Run receipts and promote-to-recipe both
     rejected, with reasons.
   - **§37** the rest of the inventory, pruned by one rule: a button may move an
     artifact, never compute a new one. Twelve actions total.
   - **§38** migration: `agent.save` stays (for different reasons than the
     charter gave), no publish op, the receipt-digest break and its version
     bump, and why saved workspaces need no migration.
3. **[IMPLEMENTATION-STATUS.md](./IMPLEMENTATION-STATUS.md)** — build plan in
   dependency order with per-unit acceptance criteria. Everything is
   *not started*. Engine/registry capabilities that do not exist yet are marked
   ⚙ so they are not discovered mid-build.
4. **[artifact-actions-reference.html](./artifact-actions-reference.html)** —
   static visual reference (open in a browser): the keypair card, the masked
   private-key tile, the publish confirmation, and two other kinds side by side.
   It is a document, not app code — its inline CSS is fine and nothing in it
   binds where it disagrees with the design doc (the `.md` wins).

## Decided vs. open

**Decided** (each fork argued in the doc, with the rejected option recorded):

- Match on `(role, tags)` over matching on the refined type structure or on
  data-field presence (§32b).
- `artifactMetaFromType` becomes the *default* stamper inside `attachPipeMeta`;
  an emit site that declares a role wins, because role is a property of the
  artifact and not of the value (§32c).
- No-match renders the existing raw-text path as a real kind, with a test — not
  a warning, not a crash (§32f).
- Outward actions render `--warn` outline, never brand fill, and always last in
  DOM/tab order (§34a/§33b).
- Copy on a masked value is **disabled**, not reveal-then-copy; Download is
  allowed. The rule: mask-gate an action iff what it emits derives from the
  masked material (§34b).
- Outward confirmations reuse §27's banner grammar with the session grant and
  batch affordances removed (§34c).
- Two key tiles, not one merged keypair tile — a merged tile would put a private
  JWK back on the artifact record, which the engine deliberately withholds
  (§35b).
- Auditability: accept the split + an Activity log. **Promote-to-recipe
  rejected** — it re-creates the exact hazard the capability removes (§36c).
- No `hkp.publish` op; publish stays a UI path to this site's directory (§38b).

**Corrections to the brief and the charter**, both load-bearing:

- The brief's "the type system can already drive it" is aspirational, not
  current: `artifactMetaFromType` has zero callers, and the engine hand-writes
  roles at 24 push sites in a vocabulary the projection cannot produce (§32a).
- The charter's "`agent.save` must stay, for CLI runs" is false today —
  `basilisk run` refuses the whole `agent` toolbox at pre-flight, exit 4. It
  stays for three other reasons (§38a).

**Open / deferred**: publishing to an upstream keyserver (no write path exists;
`upstream-hkp.js` is lookup-only — DESIGN-ITERATION-PROMPT open question 5);
per-recipient trust editing from a recipients tile (it is policy, not a
disposition); a persistent activity record surviving a session (deliberately
not built — it would name key ids in storage XSS can read).

## Conventions

Sections are cited as `§32`–`§38` (this handoff's series, continuing §18–§31).

**Numbering collision, read this before editing `OutputList.tsx`:** that file
already carries comments citing `§32c`, `§35` and `§36a` from the **design v2**
series — a different numbering line that reached the same integers. An
unqualified `§` in these documents means the handoff series; design v2 is always
cited in full (`design v2 §20h`). When touching those comments, re-cite them as
`design v2 §…`.
