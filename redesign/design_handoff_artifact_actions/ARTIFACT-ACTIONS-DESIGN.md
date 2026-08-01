# Artifact kinds + actions — design (§32–§38)

Design sections for the capability in [BRIEF.md](./BRIEF.md): artifacts that
know what they are, and that offer what you can do with them. Numbered §32
onward per the project convention so code comments can cite them (`§33b`
style), continuing the handoff series that runs §18–§31.

**A numbering warning, because this one will bite someone.** `OutputList.tsx`
already carries comments citing `§32c`, `§35` and `§36a`. Those are the
**design v2** series (the Claude Design document), a different numbering line
that happens to have reached the same integers. An unqualified `§` in *this*
document means this handoff series; a citation of the design v2 series is
written `design v2 §20h` in full. When implementing, the safest move is to
re-cite the comments you touch in `OutputList.tsx` as `design v2 §…` so the
collision stops propagating.

Every claim about the current code was checked against source on 2026-07-31,
at commit `7ec8cf8`. Where a design needs something the engine does not have,
it is named in [IMPLEMENTATION-STATUS.md](./IMPLEMENTATION-STATUS.md) with a ⚙
rather than assumed into existence.

---

## §32 The artifact-kind registry

### §32a What is actually broken, stated precisely

The brief describes the if/else chain in `OutputList` and it is real, but the
chain is a symptom. Three deeper facts came out of reading the code, and the
design is shaped by all three:

**1. `artifactMetaFromType` is dead code.** `types.js:1577` exports the
role/tags projection the brief calls "the natural key", and a repo-wide grep
finds **zero** callers. It is a correct idea that was written and never wired.
Meanwhile the engine hand-writes `role:` at twenty-four `artifacts.push` sites
in string literals.

**2. There are therefore two role vocabularies, and they disagree.** The engine
emits `share`, `key`, `public-key`, `secret`, `text`, `envelope`, `ciphertext`,
`qr`, `inspect`, `diagnostic`, `receipt`. The projection can produce `share`,
`secret`, `key`, `recipients`, `text` — it has never heard of `public-key`
(which is the one the shipped Publish button keys off, `ToolkitShell.tsx:1793`)
and the engine has never emitted `recipients` (it stamps recipients tiles as
`role: "text"`, `engine.js:4294`). A registry keyed off either vocabulary alone
is keyed off half the artifacts.

**3. The refined type is already on every artifact, and the UI throws it away.**
`execStep` stamps `result.meta.type = resolved.output` on every value whose
type resolves (`engine.js:702`), and `attachPipeMeta` copies it onto the
artifact as `pipeType` (`engine.js:4117`). But `useNotebook`'s `cellOutputs`
projection copies named fields — and `pipeType` is not one of them, so it never
reaches a widget. This is precisely the trap HANDOFF names ("anything the
engine adds is silently dropped until it is listed there"), and it is why the
UI grew `netType`, `jose` and `inspectSnapshot` as three parallel discriminator
fields: the real discriminator was already there and unreachable.

So the abstraction is not "add a table in front of the if/else". It is: make
the type system's projection the thing that stamps roles, reconcile the two
vocabularies into one, and key one table off the result.

### §32b The match key: `(role, tags)`, and nothing else

**Decision: a kind matches on the artifact's `role` plus a required subset of
its `tags`. No other key.**

Not on `pipeType` directly, even though it is richer. Two reasons. The refined
type is a structure (`{ base, kind, which, alg, … }`) and matching on it means
every kind entry embeds a type-matching mini-language, which is a second
`matchOverload` living in the widget layer. And role/tags is the projection
that *already exists* for exactly this purpose; using the structure instead
would leave the projection dead a second time.

Not on `netType` / `jose` / `inspectSnapshot` presence, which is how the
current chain works. Those are data-shaped, not identity-shaped: `hasJoseRenderer`
asks "did an op leave a JOSE body here", which conflates "this artifact is a
token" with "we happen to have parsed it". Under this design the *kind* is
matched from the type projection and the *view* reads the body — an artifact
of kind `jose-token` whose `jose` body is missing renders the kind's `empty`
state, not a different kind.

Concretely:

```js
/**
 * @typedef {object} ArtifactMatch
 * @property {string} role   Exact match against artifact.role
 * @property {string[]} [tags]  Every listed tag must be present on the artifact
 */
```

Specificity: the resolver picks the entry with the **most matched tags**; a tie
is a build error, not a first-wins race. `artifact-kinds.test.js` asserts no two
entries in the table can both match any `(role, tags)` combination the engine
can emit — the `toolbox-dot-css.test.js` precedent of guarding a duplication
mechanically instead of remembering it.

### §32c Where roles come from: projection as the floor, declaration as the override

**Decision: `attachPipeMeta` stamps `role`/`tags` from `artifactMetaFromType(value.meta.type)`
when the emit site did not set them; an emit site that sets them wins.** One
line in one function, and `artifactMetaFromType` becomes live code.

The alternative — make the projection authoritative everywhere and delete the
hand-written roles — is wrong, and it is worth saying why, because it looks
tidier. **Role is a property of the artifact, not of the value.** The same
`text` value emitted by `inspect` and by `out @msg` are the same type and
different artifacts: one is a read-out the user asked to see, one is a named
file. `role: "receipt"` comes from `value.meta.runReceipt`; `role: "diagnostic"`
from `value.meta.stunCheck`. No projection of a type can know those, because
they are facts about *why the artifact exists*. The projection is the floor so
that a newly typed value is never role-less; the declaration is the override so
that intent survives.

What this buys immediately: a `keypair` value emitted by `out` currently gets
`role: "text"` or `role: "secret"` (`engine.js:2130-2140`, the `if (!a.role)`
fallback) because the keypair branch of `materializeOutArtifacts` sets no role
at all. Under the projection floor it becomes `role: "key"`, `tags: ["keypair"]`
for free. That single change is what makes §35 possible.

The reconciled vocabulary lives in **one** exported frozen list in `types.js`:

```js
/** Every role an artifact may carry. The kind registry matches on these. */
export const ARTIFACT_ROLES = Object.freeze([
  "text",        // anything with no better description
  "secret",      // sensitive bytes with no richer identity (scalars, masters)
  "key",         // keypair / key / openpgp-key, public or private
  "public-key",  // an armored OpenPGP *public* key — the publishable one
  "share",       // one share of a split
  "recipients",  // a recipient list
  "ciphertext",  // an encrypted message
  "envelope",    // the recovery envelope of a ceremony (not a share)
  "sshsig",      // an sshsig signature block
  "token",       // JOSE: jws / jwe
  "netvalue",    // candidate / sdp / stats / connstate / endpoint / certificate / session
  "diagnostic",  // stun.check and friends — a read-out with a verdict
  "inspect",     // an explicit `inspect` snapshot
  "receipt",     // a run receipt
  "qr",          // an SVG QR rendering of another artifact
]);
```

Four of these (`sshsig`, `token`, `netvalue`, and a corrected `recipients`)
require `artifactMetaFromType` to grow branches for types it currently falls
through — `text/sshsig`, `text/jws`, the seven network bases, and the
`recipients` base whose emit sites must stop saying `"text"`. That is a
types.js change, flagged ⚙, and it belongs there: the projection being
incomplete is exactly what forced the parallel fields.

### §32d What a kind definition contains

Normative shape, written the way §26f and §29d write registry entries:

```js
/**
 * @typedef {object} ArtifactKind
 * @property {string} id            Stable; rides `data-artifact-kind` and the catalog
 * @property {ArtifactMatch} match  §32b
 * @property {string} label         Human name for the kind badge ("Keypair", "Token")
 * @property {string} [glyph]       KIND_GLYPHS key; omitted renders no glyph, never a guess
 * @property {ArtifactView} view    ({ artifact, masked, services }) => ReactNode | null
 * @property {string} empty         Shown when `view` returns null — a sentence, not "N/A"
 * @property {(err: Error) => string} [failed]  Shown when `view` throws
 * @property {string[]} actions     Action ids, resolved against the action table (§33c)
 * @property {boolean} [expandable] Offer the Sheet; defaults to the §32f size rule
 */
```

`view` returning `null` is the ordinary "I have no body to draw" path and must
not be a crash: a `jose-token` with no `jose` body, a `netvalue` whose `netData`
did not survive, a `qr` with unparseable SVG. `empty` is a sentence explaining
what is missing and what would produce it, in the register the repo already
uses for honest absence ("Passphrase protection for SSH keys needs an
encryption this browser build does not ship yet…").

`failed` exists because a view is parsing data the engine handed it, and a
malformed body must degrade to the raw text body rather than blanking a cell.
The tile catches, renders `failed(err)` in `--error` tone above the raw body,
and does not re-throw. React error boundaries are the mechanism; the per-kind
string is the copy.

### §32e The three existing renderers, as entries

They become entries with no behavioural change. This is the acceptance test for
the abstraction: if landing it requires editing `NetworkArtifact`,
`InspectorArtifact` or `JwtArtifact` internals, the abstraction is wrong.

```js
export const ARTIFACT_KINDS = [
  {
    id: "network-value",
    match: { role: "netvalue" },
    label: "Network",
    // No glyph: kind-glyphs.tsx deliberately leaves candidate/session/connstate
    // abstract, because a pictogram asserts a real-world reading a negotiating
    // connection has not earned. That decision is respected, not re-litigated.
    view: ({ artifact }) => (
      <NetworkArtifact
        netType={artifact.netType}
        netKind={artifact.netKind}
        data={artifact.netData}
        content={artifact.content}
        onConfigureTurn={artifact.onConfigureTurn}
      />
    ),
    empty: "No structured body for this value — showing the raw text.",
    actions: ["copy", "download", "expand"],
    expandable: true,
  },
  {
    id: "inspect-snapshot",
    match: { role: "inspect" },
    label: "Inspect",
    glyph: "inspect",
    view: ({ artifact }) =>
      artifact.inspectSnapshot ? (
        <InspectorArtifact snapshot={artifact.inspectSnapshot} />
      ) : null,
    // The absence is a decision, not a gap (HANDOFF): a snapshot of a sensitive
    // value would retain raw private JWK fields the masked dump does not.
    empty:
      "This value is sensitive, so no structured snapshot was kept — the text dump is below.",
    actions: ["copy", "download", "expand"],
    expandable: true,
  },
  {
    id: "jose-token",
    match: { role: "token" },
    label: "Token",
    glyph: "signature",
    view: ({ artifact }) =>
      hasJoseRenderer(artifact.jose) ? <JwtArtifact data={artifact.jose} /> : null,
    empty: "No decoded token body — run jose.decode or jose.verify to read it.",
    actions: ["copy", "download", "expand"],
    expandable: true,
  },
  // … §35 and §37 entries …
];
```

Note what disappeared: `hasNetworkRenderer(netType)` as a *predicate on the
render path*. The seven network bases are now the definition of `role: "netvalue"`
in `artifactMetaFromType`, so the list of renderable network types lives with
the types instead of being duplicated in a widget. `hasNetworkRenderer` stays
as an exported helper only if something else needs it; nothing does.

`hasJoseRenderer` survives, demoted: it is now a *body* check inside the view,
not a kind check. That is the right job for it — it answers "is this body
shaped like a token body", which is what it actually tests.

### §32f No match: the fallback is a kind, not a crash

**Decision: an artifact matching no entry renders through a built-in
`FALLBACK_KIND` that is exactly today's raw-text path — `FormatBar`, the
`max-h-24` scrolling `<code>` body, Copy, Download, Expand-if-large — with the
kind badge showing `artifact.role` verbatim.**

No "unknown type" warning to the user. A user who wrote a recipe and got a
correct value should not be told the UI is confused; the value is fine and the
raw view is a perfectly good view (it is, after all, what every artifact gets
today). The tile carries `data-artifact-kind="fallback"` so a test can find it
and the catalog can show it.

The place the gap is made visible is a test, not a toast:
`artifact-kinds.test.js` enumerates every role in `ARTIFACT_ROLES` and asserts
each is claimed by at least one entry, so adding a role without a kind fails CI
— the `recipe-verbs.test.js` discipline applied to a second registry. Roles are
a closed list precisely so this test can exist.

Rejected: throwing, and rendering an error tile. Both convert an engine
metadata omission into a user-visible failure of a computation that succeeded,
which inverts the severity. The value is real; only our description of it is
missing.

### §32g Where the table lives

`web/src/toolkit/artifact-kinds/` — `registry.tsx` (the table), one file per
non-trivial view, `resolve.ts` (matcher + fallback), `actions.ts` (§33c). The
views that already exist stay where they are and are imported.

It is a UI registry, not an op registry, so it does not go in
`lib/toolkit/registry.js`: it holds JSX and it is meaningless headlessly. But
the *vocabulary* it matches on (`ARTIFACT_ROLES`) lives in `lib/toolkit/types.js`
with the projection, and the CLI already prints `role=` (`cli/main.js:252`), so
the two halves stay honest about each other.

---

## §33 The common base

This is the section that stops the churn. Two people building two different
kinds must produce tiles that read as siblings, and the way to get that is for
the tile to own everything except the body and the action *list*.

### §33a Anatomy, top to bottom

One component, `ArtifactTile`, replacing the per-row body of `OutputList`.
Measured against the shipped tile on `/toolkit-widgets` (row padding `8px 10px`,
row gap `4px`, list radius `10px`, 1px `--border` on `--surface`) — these hold;
the redesign is not a re-skin.

```
┌─────────────────────────────────────────────────────────────────┐
│ [KEY] keypair.pub          sensitive          1.2 KB            │  identity
├─────────────────────────────────────────────────────────────────┤
│ <the kind's view, or the masked substitute>                     │  body
├─────────────────────────────────────────────────────────────────┤
│ raw hex b64 …   Copy  Download │ Add to keyring │      Publish   │  actions
├─────────────────────────────────────────────────────────────────┤
│ Added to My Keys · SHA256:Ur1h…                       ⧉         │  receipt
└─────────────────────────────────────────────────────────────────┘
```

1. **Identity line** — kind glyph + badge, label, `sensitive` badge, size.
   Unchanged from today except that the badge text is the *kind's* `label`
   rather than a four-way ternary on role computed at the call site
   (`ToolkitShell.tsx:1812-1820`). The tray's Outputs tab currently computes a
   *different* mapping for the same artifacts (`role || "text"`,
   `ToolkitShell.tsx:2277`), which is the churn in its purest form: the same
   artifact wears two different badges depending on which pane you are looking
   at. One component, fed by the registry, ends that by construction.
2. **Body** — `kind.view(...)`, or the masked substitute (§33e), or `empty`.
3. **Action row** — §33b.
4. **Receipt line** — §33f. Absent until something has happened.

### §33b The action row: grouping, order, and the tier gap

Left to right, in three groups separated by a visible gap:

| Group | Contents | Weight |
|---|---|---|
| **View** | `FormatBar` (when the body is raw text), `Expand` | inline, not buttons |
| **Inert** | Copy, Download, Copy public line, Show QR | `variant="secondary"`, `size="sm"` |
| **Local** | Add to keyring, Import to key cache, Print cards | `variant="secondary"` + `data-action-tier="local"` |
| **Outward** | Publish | `variant="outline"` + `data-action-tier="outward"` |

Order within a group is the order the kind declared. **Outward-facing actions
are always last**, which makes them last in DOM order, which makes them last in
tab order and never the default-focused control — the brief's requirement
satisfied structurally rather than by remembering to set `autoFocus` elsewhere.

Overflow: more than five visible actions collapses everything past the fourth
inert action into the existing `MenuPopover` ("More ▸"), preserving tier order
inside the menu. Local and outward actions are never collapsed — an action with
consequences does not hide behind a chevron.

`data-action-tier` is a closed three-value vocabulary with enumerated CSS in
`toolkit.css`; no continuous values, so `css-vars.js` is not involved and no
inline style is needed.

### §33c The action table

Actions are declared once, globally, and referenced by id from kinds. This is
the other half of the anti-churn machinery: "Copy" must mean the same thing,
look the same, and gate the same way on every tile.

```js
/**
 * @typedef {object} ArtifactAction
 * @property {string} id
 * @property {string} label
 * @property {"inert"|"local"|"outward"} tier            §34
 * @property {string} [glyph]
 * @property {(ctx: ActionContext) => Availability} available
 * @property {(ctx: ActionContext) => ConfirmSpec|null} [confirm]   §34c
 * @property {(ctx: ActionContext) => Promise<ActionResult>} run
 */

/**
 * @typedef {true | { disabled: string }} Availability
 *   `true`, or a *reason string* rendered as the button's title and
 *   aria-description. There is no bare `false`: an action that cannot say why
 *   it is unavailable should not have been declared by the kind.
 */

/**
 * @typedef {object} ActionContext
 * @property {ToolkitArtifact} artifact
 * @property {ArtifactKind} kind
 * @property {number} cellIndex
 * @property {number} outputIndex
 * @property {boolean} masked        True when sensitive and not revealed
 * @property {ActionServices} services
 */

/**
 * Injected, never imported by the table — so the table is unit-testable with
 * no IndexedDB, no clipboard, and no network. Same shape of decision as
 * `setApprovalGate` / `setClipboardReadGate`.
 * @typedef {object} ActionServices
 * @property {{ list(): Promise<VaultKeyMeta[]>, save(opts): Promise<VaultKeyMeta> }} vault
 * @property {{ publish(armored: string): Promise<{fingerprint, directoryUrl}> }} directory
 * @property {{ write(text: string): Promise<void> }} clipboard
 * @property {{ save(bytes: Uint8Array, name: string, mime: string): Promise<void> }} files
 * @property {{ put(rec): Promise<void> }} pubkeyCache
 */

/** @typedef {{ receipt: string, detail?: string, copyable?: string }} ActionResult */
```

### §33d Disabled: the rule that decides absent vs. dead

Two questions, and they have different answers:

- **"Is this action meaningful for this object?"** No → the kind does not
  declare it. There is no *Copy public line* on an x25519 keypair because SSH
  has no key type for x25519; a disabled button there would be teaching a
  falsehood about the artifact.
- **"Is this action possible here, now?"** No → declared, rendered disabled,
  with the reason in `title` and `aria-describedby`. *Add to keyring* on a
  browser with no IndexedDB; *Publish* while offline; *Copy* on a masked value.

The distinction is the whole content of "a dead button with no reason is worse
than no button". The first case is about the artifact and is static — it
belongs in the table. The second is about the environment and is dynamic — it
belongs in `available()`, which must return a sentence.

Reason strings are written as sentences with a remedy where one exists, and are
asserted verbatim in tests (the `share-check.js` precedent — wording is the
feature):

- `"Reveal this value first — a masked value cannot leave the notebook."`
- `"This value was not asked for. Add `out @label` to the recipe to see or copy it."`
- `"My Keys is unavailable in this browser (no IndexedDB)."`
- `"Publishing needs a connection to this site's directory."`

### §33e Sensitive and masked

The existing gate is unchanged and this design does not soften it. Restating it
as tile behaviour, because it now has to compose with actions:

- `sensitive && !revealed` → the body is the masked substitute
  (`sensitive — value not shown`), and the kind's view does **not** run. A view
  is a rendering of the value; a masked value has no rendering.
- `revealable` (set by the engine only for `out` / `text` / `inspect`) adds the
  Reveal button. Without it there is no Reveal, and the tile says so through the
  disabled Copy reason above rather than by silently offering nothing.
- Revealing starts the existing 15s `REVEAL_TIMEOUT_MS` auto-hide, refreshed by
  interaction. Unchanged.
- **One addition:** a kind may declare `publicView` — a body that renders
  *while masked* because it is derived only from public material. The keypair
  kind uses it (§35b) to show algorithm, fingerprint and public line on a tile
  whose private half is masked. This is not a hole: the rule is stated once and
  enforced in one place — **a masked tile may render only what does not derive
  from the masked material** — and `publicView` is where a kind asserts it, in
  code review, per kind, rather than by each tile deciding.

### §33f Receipts and weight

Three weights, matched to what happened, reusing what exists:

- **Inert actions → the notebook toast strip.** The line already rendered under
  the RunBar with `data-clipboard-wrote` / `data-file-saved`
  (`ToolkitShell.tsx:956-972`), auto-dismissing. Copy and Download route through
  the existing `basilisk:clipboard-wrote` / `basilisk:file-saved` events, so
  they get the same confirmation whether they came from an op or a button.
  Nothing new to build.
- **Local mutations → a persistent line in the tile.** "Added to My Keys ·
  SHA256:Ur1h…", `--muted-foreground`, with a copy affordance for the id. It
  persists for the life of the tile because the thing that changed is durable;
  a toast that vanishes is the wrong record for a keyring write.
- **Outward actions → the button is replaced by its result.** Exactly the
  shipped `publishedAs` behaviour (`OutputList.tsx:294-311`): the Publish button
  becomes `@a1b2c3d4` plus a link that copies `directoryUrl`. That pattern is
  correct and stays; it is the only one of the three that makes re-firing an
  irreversible action structurally impossible.

Errors from any tier render in the tile in `--error` tone with the thrown
message verbatim, and the action stays enabled — a failed publish is retryable,
a failed keyring write is retryable, and swallowing the message to show
"something went wrong" would be the one thing worse than the failure.

### §33g Keyboard and focus

- Every action is a real `<button>`; the tile is not a click target and has no
  `onClick`. Nothing about a tile is reachable only by hover — the shipped
  `title={a.preview}` on the identity row is a *supplement*, and the preview is
  also rendered visibly (which matters here specifically, because this repo has
  hit sessions where the browser pane reported a 0×0 viewport and hover was
  untestable).
- The action row is `role="group"` with `aria-label={`${label} actions`}`.
- Tab order = DOM order = View, Inert, Local, Outward. §33b's ordering is what
  makes this safe.
- `Expand` opens the existing `Sheet`; Radix returns focus to the trigger on
  close. The Sheet renders **the same kind view**, never a second rendering of
  the value — the current code already holds this line and it must survive the
  refactor (`OutputList.tsx:470-495`).
- A confirmation banner (§34c) is `role="alertdialog"` with focus moved to its
  first control on open, and Escape resolving as cancel — matching
  `ApprovalBanner`.
- Reveal, Hide, and the `FormatBar` tabs keep their current semantics
  (`role="tablist"` on the format bar is already correct).

---

## §34 Action tiers and confirmation

### §34a The three tiers, and what distinguishes them

| Tier | Test | Examples | Weight | Confirm |
|---|---|---|---|---|
| **Inert** | Produces a copy of what you already have, changes nothing | Copy, Download, Copy public line, Copy fingerprint, Show QR, Reformat | `variant="secondary"` | none |
| **Local mutation** | Changes durable state on this device | Add to keyring, Import to key cache, Print cards | `secondary` + `data-action-tier="local"` | only when it would overwrite (§34d) |
| **Outward** | Emits to somewhere you cannot reach back into | Publish to the directory | `variant="outline"`, `--warn` border and text | always (§34c) |

The tier is a property of the *action*, not of the artifact, and it is declared
once in the action table. A kind cannot promote or demote one.

**Publish stops being brand-filled.** Today it is
`bg-[var(--brand)] … font-bold text-[var(--on-brand)]` — the most visually
prominent control in the row, sitting next to a plain secondary Copy. That is
exactly backwards: brand fill is the codebase's "this is the thing to do", and
the one action in the row that cannot be undone should not be the one the eye
lands on. Outward actions render as an outline button in `--warn`, which reads
as "deliberate" rather than "recommended". Rejected: `--error` tone — this
codebase reserves `--error` for things that failed (§26c makes the same call
about the exposure underline), and an amber-vs-red distinction that has to hold
across the whole app is worth more than the extra emphasis here.

### §34b What Copy does on a masked private key

**Decision: Copy is disabled, with the reason `"Reveal this value first — a
masked value cannot leave the notebook."`** It does not reveal-then-copy.

(The sentence named Copy alone until Download landed and took the same branch,
at which point a user clicking a disabled *Download* was told the value "cannot
be copied" — a sentence about a button they had not pressed. It now names
neither action, because one condition may not acquire two explanations. The
axis it gates on is *leaving*, which is also why `keyring.add` stays enabled
while masked and these two do not.)

The argument is short. The reveal gate exists so that cleartext appears on
screen deliberately, under a 15-second timer, in a place the user is looking. A
Copy that quietly unmasks puts the same cleartext somewhere with no timer, no
visual, and a much longer life — the clipboard survives the tab. Making Copy
the *second* click after Reveal costs one click and preserves the invariant
that a secret is seen before it is spread. And for the incidental tiles that
carry no `revealable` flag at all, disabling is the only option consistent with
HANDOFF's standing instruction: "Reveal is gated. Do not 'fix' this by
revealing everything."

Rejected: reveal-on-copy with a confirmation. It is a confirmation dialog whose
honest text is "are you sure you want to defeat the mask", which is a question
with one answer and therefore a click-through trainer.

**Download of a masked artifact is allowed.** This is not an inconsistency and
the rule that reconciles them is worth stating as the general form:

> An action is mask-gated **iff what it emits derives from the masked
> material**, and lands somewhere the mask does not govern.

Download's bytes never appear on screen, and the browser's own file picker is
the consent — the same reasoning `file.read` already ships with ("no permission
gate, because the browser's picker *is* the consent", HANDOFF). Refusing it
would push people to reveal-then-copy-then-paste-into-an-editor, which is
strictly worse for the same secret. A downloaded private key carries the §29f
unencrypted-export warning row on the tile, as `ssh.encode format=private`
already does.

The same rule makes *Copy public line* and *Copy fingerprint* available on a
masked keypair tile: what they emit is derived from the public half, and the
public half was never masked.

### §34c Outward confirmation: §27's banner, minus the grants

**Decision: outward actions confirm through the same banner grammar as §27,
rendered inline in the tile under the action row — not the popover
`OutputList` uses today.**

`ApprovalBanner` and this share one presentational shell: `border-l-2` in
`--warn`, warn-tinted background, `role="alertdialog"`, a `<dl>` of facts,
ghost cancel and secondary confirm. The implementation extracts that shell
(`GateBanner`) and re-expresses `ApprovalBanner` over it — a refactor with no
behavioural change, guarded by `ApprovalBanner`'s existing catalog states.

Why the same grammar rather than a second one: a user who has learned that "a
warn-bordered inline panel with a facts table means something consequential is
about to happen, and I have to choose" should not have to learn a second visual
language for the same sentence. §27a's reasons for inline-over-modal transfer
verbatim — the context (which tile, which artifact) must stay visible, and
modals train dismissal.

What is deliberately **absent** compared to §27:

- **No session grant.** There is no defensible "don't ask again" for publishing;
  each publish is its own irreversible act, and a five-minute window in which
  the tile publishes without asking is a bug wearing a checkbox.
- **No per-run batch.** Nothing loops here.
- **No request counter.** There is no run in progress.

Contents for Publish (every line is data held at the moment of the click):

```
▌ Publish this key to the directory
▌
▌ Key        Justin Capella <justin@…> · OpenPGP
▌            AABB CCDD EEFF 0011 2233 4455 6677 8899 AABB CCDD
▌ Where      keys.example.com  (this site's directory)
▌ Becomes    The key, its user IDs, and every signature on it — readable by
▌ public     anyone with directory access, including the email addresses in
▌            its user IDs.
▌ Permanent  A published key cannot be withdrawn. You can publish a revocation
▌            later; you cannot make this copy go away.
▌
▌            [ Cancel ]                            [ Publish ]
```

The "Becomes public" line names the *email addresses in the user IDs*
specifically, because that is the consequence people are surprised by and it is
data we hold. The "Permanent" line states the revocation asymmetry rather than
just saying "irreversible" — the accurate mental model is "you can add a
tombstone, you cannot delete", and a user who thinks revocation is deletion
will make the wrong call.

**Local mutations do not confirm** — with one exception, §34d. A keyring write
is undoable (the key can be deleted, from a UI that already exists), so a
confirmation would be ceremony. That asymmetry is the point of having tiers at
all.

### §34d The one local-mutation confirmation: overwrite

`vault.saveKey` writes with `store.put(record)` against a `keyPath` of
`fingerprint` (`vault.js:80, 645`). Saving a key that is already in the vault
therefore **silently replaces the record**, resetting `created`, clearing
`lastUsedAt`, and — the one that matters — re-wrapping under whatever
protection the caller passed, which for a tile button defaults to `device`. A
passkey-protected key can be downgraded to device protection by a single
unconfirmed click on a tile.

So *Add to keyring* checks first, and when the id is present renders a
ConsequenceBanner:

```
▌ This key is already in My Keys
▌
▌ In the vault   Justin Capella <justin@…> · added 2026-04-02 · passkey
▌ Replacing      re-wraps it with device protection and clears its usage
▌                history. Its passkey binding is discarded; you would enrol
▌                a new one to restore passkey protection.
▌
▌            [ Cancel ]                          [ Replace ]
```

⚙ The clean fix underneath is `saveKey({ onConflict })` — `"refuse"` for the UI
path (so the check-then-write cannot race), `"replace"` for `agent.save`, whose
current clobbering behaviour must not change because recipes depend on it. Both
are in IMPLEMENTATION-STATUS.

Rejected: making the tile action always refuse on conflict with a "already
saved" note. It is honest but it strands the real case — a key re-generated
under the same fingerprint after an expiry change — with no path forward except
deleting from another screen.

---

## §35 The key artifacts

This is the case that motivated the request, so it gets the most detail.

### §35a What happens today, exactly

`out @kp` on a keypair reaches the keypair branch of `materializeOutArtifacts`
(`engine.js:4387-4440`). It exports both halves as JWK and pushes **two**
artifacts: `kp · private JWK` (sensitive) and `kp · public JWK` (not). Neither
sets `role` or `tags`, so the `out` case's fallback (`engine.js:2130-2140`)
stamps `role: "secret"` or `role: "text"` from the value's sensitivity. The
result is two JSON blobs, one of them masked, both wearing a `text`/`secret`
badge, with a single Copy button between them. The tile does not know it is
looking at a key. Everything the brief asks for is downstream of that.

### §35b The decision: two artifacts, two good tiles — not one merged tile

The tempting move is to emit one artifact for the keypair and render a single
card with both halves. **Rejected**, for two reasons that are each sufficient:

1. It would put a private JWK on the artifact record (as content or as a
   trait), and the engine deliberately withholds exactly that today: HANDOFF
   records that `inspectSnapshot` is suppressed for sensitive values *because a
   snapshot retains raw private JWK fields the masked text dump does not*. A
   merged tile re-introduces the retention that decision removed.
2. It changes the artifact count for an unchanged recipe, which the CLI prints
   and `--json` emits, and which `receipt.js` digests. "Nothing may change what
   a recipe computes" is about values, but changing how many artifacts a recipe
   yields is close enough to the line that it needs a better reason than
   aesthetics.

So: **emission is unchanged in content and count. What changes is metadata, and
what changes a lot is the tiles.** The two halves become two kinds.

⚙ The emit sites gain `role: "key"` and `tags: ["keypair", "public"|"private"]`
plus `traits: { alg }`. The `role` comes free from §32c's projection floor
(`artifactMetaFromType` on base `keypair` yields `{ role: "key", tags: ["keypair"] }`);
the public/private tag and the algorithm must be added at the two sites in
`materializeOutArtifacts`, which already know which half they are building.

### §35c The public-key card

```js
{
  id: "keypair-public",
  match: { role: "key", tags: ["keypair", "public"] },
  label: "Public key",
  glyph: "key",
  view: KeyCard,
  empty: "No exportable public half.",
  actions: [
    "copy",                 // the JWK, as today
    "key.copyPublicLine",   // ssh-ed25519 AAAA… comment
    "key.copyFingerprint",
    "download",
    "artifact.showQr",
    "keyring.add",
    "key.publish",          // openpgp public keys only — see §35f
  ],
}
```

`KeyCard` is a read-out, not a JSON dump. Four lines:

```
ed25519                                              public half
SHA256:Ur1hPKBrJC3zF0Qw9pLmXaYd8vN2sQ4tR6wE1cB7gH0   ⧉
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH8k…  justin@workstation   ⧉
{ "kty": "OKP", "crv": "Ed25519", … }                [ raw ]
```

- **Algorithm** from `traits.alg` (the `genkey`-style tag: `ed25519`,
  `ec/p256`, `rsa/3072`). Not re-derived from the JWK — the value the recipe
  named is the value to show.
- **Fingerprint in kind shape**, per §28a and for the same reason: an SSH key
  shows `SHA256:` + unpadded base64 exactly as `ssh-keygen -lf` prints it, so a
  user can compare it against their server's log line character for character;
  an OpenPGP key shows grouped hex via the existing `nb.formatFingerprint`; a
  raw key shows `spki:SHA256:…`. The copy affordance copies the id in its
  display format, never a normalized variant.
- **Public line** for SSH-mappable algorithms, computed by the shipped codec
  (`lib/ssh/wire.js`'s `buildPublicBlob` + `formatPublicLine`) — no new crypto,
  no new op, the same bytes `ssh.encode` would emit. For x25519 / AES / HMAC the
  row and its action are **absent**, per §33d: SSH has no key type for them, and
  a disabled button would imply one exists.
- **Raw** toggles the JWK body, which is what the tile shows today. Nothing is
  taken away; it stops being the only thing offered.

### §35d The private-key tile

```js
{
  id: "keypair-private",
  match: { role: "key", tags: ["keypair", "private"] },
  label: "Private key",
  glyph: "key",
  publicView: KeyCardPublicOnly,   // §33e — renders while masked
  view: KeyCard,
  empty: "No exportable private half.",
  actions: ["copy", "key.copyFingerprint", "download", "keyring.add"],
}
```

Masked by default, as today. What is new is that a masked private-key tile is
no longer blank: `publicView` renders the algorithm, the fingerprint and the
public line, because none of those derive from the masked material (§34b's
rule). The masked line stays exactly as it is, under them.

Actions while masked: Copy **disabled** with §34b's reason; Copy fingerprint
and Download **enabled**; Add to keyring **enabled** — the vault is the one
destination whose whole job is to hold the value without showing it, and
requiring a reveal before a keyring save would force the secret onto the screen
in order to put it somewhere safe. That is the clearest case in the design for
the mask rule being about *where it lands*, not about *how sensitive it is*.

Download carries the §29f unencrypted-private-material warning row.

`copy` is declared rather than omitted here on purpose: it is meaningful for
the artifact (the JWK is copyable once revealed) and impossible right now — the
§33d test lands on "disabled with a reason".

### §35e `openpgp-key` and `key`

- `{ role: "public-key" }` — the armored OpenPGP public key `gpg.genkey` emits
  (`engine.js:831-841`, with `traits.fingerprint`). Kind `openpgp-public`: view
  is a uid/fingerprint/created read-out over the armor, actions Copy, Download,
  Copy fingerprint, **Import to key cache**, **Publish**. This is the only kind
  that gets Publish; see §35f.
- `{ role: "key", tags: ["openpgp", "private"] }` — kind `openpgp-private`.
  Masked; actions Copy (mask-gated), Download, Add to keyring. No Publish, ever
  — it is not declared, so there is no button and no reasoning about it at
  runtime.
- `{ role: "key", tags: ["public"] }` / `["private"]` without `keypair` — a
  single `key` handle, or a PEM/DER export. Same card, one half.

### §35f Add to keyring, concretely

The action calls the same code path `agent.save` uses, minus the pipeline:
`saveKeypairKind`-equivalent logic for WebCrypto keypairs (ssh kind for
SSH-mappable algorithms, raw kind otherwise) and the armored path for OpenPGP,
landing in `vault.saveKey`. It is deliberately the same functions: two save
paths that could drift on kind detection or id shape is exactly the class of
bug HANDOFF describes with the ShareCards/`sss.combine` story.

Constraints that follow from the multi-kind vault as built (§28):

- **Symmetric keys are refused**, and therefore *Add to keyring is not
  declared* for them — `agent.save` refuses AES/HMAC with a stated message
  because they have no public half to list and no id scheme fits. The tile does
  not offer what the vault will not accept.
- **Protection defaults to `device`.** Passphrase protection is unavailable for
  ssh/raw kinds (bcrypt_pbkdf, deferred), and asking for a passphrase from a
  tile button would be a form in a tile. The action saves device-protected and
  its receipt line says so: *"Added to My Keys · device protection · change it
  in My Keys."* Rejected: a protection picker in the confirmation — it turns a
  one-click disposition into a settings dialog, and My Keys already owns that
  choice.
- **Already there** → §34d's overwrite banner.
- The receipt line's id is the vault id in kind shape, with a copy affordance,
  because that string is what a later `agent.sign fpr=…` needs.

### §35g Rejected: "Set as signing key"

The brief lists it. There is no such concept in the engine: `agent.sign fpr=`
names its key explicitly, and every recipe that signs says which key it signs
with. A default signing key would make a recipe's meaning depend on device
state — the same recipe would sign with different keys on different machines,
which is the portability property this whole capability exists to protect.
Rejected outright, not deferred.

---

## §36 Auditability

### §36a The decision

**Accept the split, and give dispositions their own durable record: a
per-notebook Activity log, session-scoped, carrying the receipt's digest
discipline. Recipes record derivations; the Activity log records dispositions;
neither pretends to be the other. Promote-to-recipe is rejected.**

### §36b Why not run receipts

The brief suggests UI actions append to the `receipt` shelf. Reading
`receipt.js` and `currentRunReceipt` makes this the wrong shape rather than
merely awkward.

A receipt is **derived**, not accumulated: `run.receipt` is an op that builds
its content at the moment it runs, from `bindings.receipt.runLog` plus the
current call's artifacts. And its value comes entirely from `run.verify`, which
re-runs the recipe and compares digests. A disposition performed by a human
clicking a button **can never be reproduced by a re-run** — which means folding
it into the receipt would make every receipt containing one permanently
unverifiable. The one property receipts have is the one this would destroy.

There is a real relationship, though, and the design keeps it: the Activity log
borrows the receipt's invariant verbatim. **It records digests, never values.**

### §36c Why not promote-to-recipe

This is the one the brief leans toward, and it is the one to argue hardest
against, because it is genuinely appealing and it undoes the premise.

The premise of this whole capability is that a recipe ending in `agent.save`
mutates the keyring of whoever runs it, and that dispositions must therefore
leave recipe text so shared recipes are portable. "Promote to recipe" is a
one-click affordance whose entire effect is **to put the disposition back into
the recipe** — offered on the tile, at the moment of success, when the user is
thinking about their own machine and not at all about the stranger who will run
this later. The best-designed default in the feature would be one click away
from being undone, and the click would feel like tidying up.

It also has a narrower problem: for the actions that most want a record, the
promotion is not well-defined. There is no `hkp.publish` op to promote Publish
into, and this design declines to add one (§38b). Promoting *Add to keyring*
means writing `agent.save protection=device`, which then re-fires on every
subsequent run of the notebook — a keyring write per run, silently, from a step
the user added to *record* that a write had happened once.

Rejected. The path from disposition to derivation stays where it belongs: the
op exists, Source view exists, and someone who wants the save to happen every
run writes it in the recipe deliberately.

### §36d What the Activity log is

A fourth tray tab beside Slots / Keyring / Inputs. Newest first:

```
14:07:22  Add to keyring    kp · private JWK   sha256 1a2b3c4d…
          → My Keys SHA256:Ur1hPKBrJC3z…  ssh · device
14:06:58  Publish           dana.pub.asc       sha256 9f8e7d6c…
          → keys.example.com  0xAABBCCDD…
14:06:12  Download          share-2.txt        sha256 44ffee01…  1.1 KB
```

- **Every action of every tier is logged**, including inert ones. Copy and
  Download are how a secret leaves the notebook, and a log that records only
  the dramatic actions is a log that answers the wrong question at 2am.
- **Digests, never values** — `digestText` over the artifact's content, the same
  function receipts use, so the two records can be cross-read.
- **Session-scoped, never persisted.** It names key ids and directory URLs, and
  `workspace-store.js` already states the rule this follows: localStorage is
  XSS-readable, so nothing sensitive goes there. It clears with Clear session /
  Clear sensitive data, alongside `cellOutputs`.
- **Exportable by copy**, as text, so a ceremony can paste it into its minutes.
  Deliberately not a downloadable signed object: a signed activity log would
  imply a verifiability it does not have (nobody can re-run a click).
- Entries are appended by the tile's action runner, in one place, so a new
  action cannot forget to log — the same structural move as routing receipts
  through `ActionResult`.

Rejected: making the log an artifact so it could ride a pipeline. It would be a
value that exists outside any derivation, which is the exact thing §37a
forbids buttons from producing.

---

## §37 The rest of the inventory

### §37a The pruning rule

One rule decides most of the brief's candidate list:

> **A button may move an artifact. It may never compute a new one.**

Copy, Download, Print, Publish, Add to keyring, Import — all of these take the
value that exists and put it somewhere. *Decrypt with…*, *Verify threshold*,
*Trust…* as a computation, *Send to peer* — these produce a new value, or a new
verdict, which would exist in the notebook with no derivation behind it, no
type, and no place in the recipe or the receipt. That is a value the CLI cannot
reproduce, which is the line the brief itself draws.

The corollary is more useful than the rule: **several of the brief's candidate
actions are really views.** "Inspect packets" on a ciphertext is not a button,
it is what the ciphertext tile should show. Applying that turns a list of
actions nobody would click into a set of tiles worth looking at.

### §37b The inventory

| Role / tags | View | Actions | Notes |
|---|---|---|---|
| `ciphertext`, `envelope` | Packet structure read-out over the existing `packet-map.js` / `packet-hex-view.js`, raw armor one toggle away | Copy, Download | *Decrypt with…* rejected (§37a). The envelope tile keeps its "required for recovery (not a share)" label, which the engine already writes. |
| `share` | `ShareCards`, the built widget — currently reachable only from `CeremonySheet` | Print cards, Download | Cards keep their own per-mount reveal and their own print warning; the tile does not bypass them. *Verify threshold* rejected (§37a); *Check a share…* already exists under More ▸ and is not duplicated here. |
| `recipients` | Row list: fingerprint, label, email, approval state, encrypt-capable — the fields the engine already serializes (`engine.js:4274-4284`) | Copy list, Import to key cache (all), per-row Import | ⚙ role must become `recipients`; the engine stamps `"text"` today. *Save as group* rejected — no group concept exists, and inventing one in a tile is how a parallel vocabulary starts. |
| `sshsig` | Namespace, hash algorithm, signer fingerprint — parsed by the shipped `lib/ssh/sshsig.js` decoder | Copy, Download | Nothing else. Verification is `ssh.verify`: it needs a key and a payload, neither of which a tile has. |
| `netvalue` | `NetworkArtifact`, unchanged | Copy, Download | *Send to peer* rejected on type grounds, not taste: `channel` and `session` are HANDLE types, live only inside the run that made them (HANDOFF's three-way rule). A tile outlives its run, so the channel is already gone. |
| `diagnostic` | `NetworkArtifact`'s pair matrix, plus the shipped "Configure TURN" CTA | Copy, Configure TURN | The one existing action that is neither inert nor a disposition: it *navigates* (jumps to `rtc.ice`'s `turn=` field). Tier `inert` — it changes no state, it moves the caret. |
| `qr` | The SVG, rendered as an `<img>` with a `data:image/svg+xml;base64,` source | Download (.svg), Print | `img-src 'self' data:` permits this; inlining the SVG string would need `dangerouslySetInnerHTML`, which is a script-injection surface for a value that came from the pipeline. Copy dropped — copying SVG source is not a thing anyone wants, and an action nobody uses is a button everyone reads past. |
| `receipt` | Cell/artifact digest table, the shape `run.verify` compares | Copy, Download | No "verify this" button: verification re-runs the recipe, which is `run.verify`, an op. |
| `text`, `secret`, `inspect`, `token` | §32e / fallback | Copy, Download, Expand | Unchanged behaviour. |

### §37c Actions declared once, listed here for completeness

`copy`, `download`, `expand` (inert, on every kind); `key.copyPublicLine`,
`key.copyFingerprint`, `artifact.showQr` (inert); `keyring.add`,
`pubkey.import`, `shares.print` (local); `key.publish` (outward);
`diag.configureTurn` (inert, navigational). Twelve actions total across the
whole inventory — the brief's illustrative table had roughly twenty-five.

---

## §38 Migration

### §38a `agent.save` stays — but not for the reason the charter gives

The charter says `agent.save` must stay "for CLI runs". **That is not true
today**, and building on it would be building on sand: `basilisk run` refuses
the entire `agent` toolbox at pre-flight with exit code 4, because the pre-flight
map is derived from `getStep().toolbox` and `agent` is classed browser-bound
(the IndexedDB vault). `docs/CLI.md` documents this, and the agent/SSH
IMPLEMENTATION-STATUS records the consequence: `--approve` was not shipped
because a boundary op never reaches the gate in Node.

`agent.save` stays anyway, for three better reasons:

1. **Removing a registered op is a breaking change with no migration target.**
   The repo's rule is that retired names are removed and rewritten by
   `migrateRecipe` — `to`/`from`, `quorum.send/recv`, `hex`/`unhex`. There is
   nothing to rewrite `agent.save` *to*: its replacement is a button, and
   `migrateRecipe` cannot emit a click. Every saved workspace and shared link
   containing it would fail live parse.
2. **A button cannot loop.** `foreach … | agent.save` over a set of generated
   keys is a real use, and the tile affordance is inherently one-at-a-time.
3. **It becomes CLI-real when the CLI key store lands** (agent/SSH §30d). The
   op should not be retired months before the host that needs it exists.

What changes is its **doc steer**, following the §26f precedent: a leading line
saying that for a one-off save the artifact tile's *Add to keyring* is the
portable choice, because a recipe containing `agent.save` writes to the keyring
of everyone who runs it.

### §38b `hkp.publish` is not added

There is no publish op today. Publishing is a UI-only path:
`useNotebook().publishArtifact` → `hkp-ops.js`'s `publishArmoredKey` → this
site's own `/api/v1/me/keys` or `/pks/add`. This design **keeps it that way**
and declines to add an op, which is the same conclusion the brief reaches from
the other direction: a recipe that publishes on behalf of whoever runs it is the
worst instance of the hazard this capability exists to remove.

Two facts implementers must not discover late:

- **Publish targets this site's directory, not the upstream keyservers.** The
  `connect-src` allow-list contains `keys.openpgp.org` and
  `keys.mailvelope.com`, but `upstream-hkp.js` only implements *lookup*; there
  is no upstream write path. The confirmation banner's "Where" line therefore
  names this site, and must not be worded as though it could name a keyserver.
  Publishing upstream is a separate capability (it is already open question 5 in
  DESIGN-ITERATION-PROMPT) and is out of scope here.
- **Publish stays declared on exactly one kind** (`role: "public-key"`), which
  is what `publishArtifact` already enforces server-side of itself by throwing
  on any other role. The registry and the function now agree in two places
  instead of one, so `artifact-actions.test.js` asserts that no other kind
  declares `key.publish`.

### §38c What changes for existing recipes, and what it costs

Nothing about what a recipe *computes* changes. Two observable metadata changes
do, and both need saying out loud:

1. **`role` and `tags` change on some artifacts.** The projection floor (§32c)
   gives keypair exports `role: "key"` where they had `"text"`/`"secret"`, and
   `recipients` exports `role: "recipients"` where they had `"text"`. `role` is
   printed by the CLI (`role=…` in `artifactHeader`, and in `--json`), so
   headless output text changes for those recipes even though every value is
   byte-identical.
2. **`role` is inside the receipt digest.** `SAFE_ARTIFACT_FIELDS` includes
   `role`, and `digestArtifact` hashes it. A receipt produced before this change
   will therefore **fail** `run.verify` against a run after it, with a digest
   mismatch — for a run that is in fact identical.

That second one is a genuine one-time break, and reporting it as "digest
mismatch" would send someone hunting a nonexistent tampering. **Decision: land
the role change together with a `RECEIPT_VERSION` bump to 2**, and have the
comparison in `run.verify` detect a v1 receipt and say so:
*"This receipt was made before the artifact-role change (receipt v1, this build
writes v2). Digests of unchanged values will not match; re-issue the receipt."*
The version field exists for shape changes, and the shape of what is hashed is
what changed.

Rejected: excluding `role` from the digest to dodge the break. `role` is a
claim about what an artifact *is*, made by the run — a witness should be able to
check that the ceremony's third artifact was a share and not a public key.
Dropping it to avoid a migration would trade a permanent weakening for a
one-time inconvenience.

### §38d Saved workspaces and session state

- `workspace-store.js` persists **title and recipe text only** — no artifacts,
  no roles, no tile state. Saved workspaces load unchanged, with no migration
  and no schema bump.
- Published state (`publishedAs` / `directoryUrl`) is kernel-held and dies with
  the session, as today. The Activity log (§36d) is session-scoped for the same
  reason. Nothing this design adds is persisted.
- Recipe text is untouched: no new ops, no retired ops, no `migrateRecipe`
  entries. Shared links and the fragment format are unaffected.

### §38e Ops that stay recipe-only

Deliberately, and stated so absence reads as decision: `gpg.decrypt`,
`ssh.verify`, `run.verify`, `sss.combine` / `vss.combine`, `rtc.send`,
`age.decrypt`. Every one of them takes an input the tile does not have — a key,
a payload, a peer, a second artifact — and every one produces a value that
belongs in the recipe that will be re-run. §37a is the rule; these are the
names it excludes, listed here so nobody re-proposes them as tile actions in
six months.
