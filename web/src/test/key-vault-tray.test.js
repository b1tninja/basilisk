/**
 * The Keys tray is the vault's home, and the vault's state is visible before it
 * blocks anything.
 *
 * Two defects with one shape, closed here. The first is the split that produced
 * the original report: `my-keys-mount.js` divides keys by *where the bytes
 * live* — "Your keys" on your account, "Your browser vault" in this browser —
 * and a session told somebody with three of the first that they had none of the
 * second. Both statements were true. The second is this repo's signature
 * defect: `unlockedCount` and `sessionEarliestExpiry` were both computed,
 * correct, and reaching almost nobody — the count needed the tray open *and*
 * the Keys tab selected, and the expiry had no caller in the app at all.
 *
 * These are source assertions for the same reason the rest of the toolkit's
 * are: the suite runs in node with no DOM, so what can be pinned is that the
 * consumer exists and reads the right thing. Behaviour lives in
 * `key-power.test.js` and `vault-manage.test.js`, which test functions.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { KEY_POWERS } from "../lib/toolkit/key-power.js";

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const SHELL = read("../toolkit/ToolkitShell.tsx");
const VAULT = read("../toolkit/widgets/KeyVault.tsx");
const RUNBAR = read("../toolkit/widgets/RunBar.tsx");
const START = read("../toolkit/widgets/SessionStart.tsx");
const CSS = read("../css/toolkit.css");
const MYKEYS = read("../lib/my-keys-mount.js");

describe("every state in the vocabulary has a rule to draw it", () => {
  it("enumerates all five, because the CSP refuses the alternative", () => {
    // `style-src 'self'`, so a colour picked at the call site never arrives.
    // A sixth value added to the vocabulary with no rule here is a badge that
    // silently renders as whatever it inherits.
    for (const power of KEY_POWERS) {
      expect(CSS, power).toMatch(new RegExp(`data-key-power="${power}"`));
    }
  });

  it("colours only the states that are not ordinary", () => {
    // A vault key at rest is not a hazard and a key you do not hold is not an
    // error; drawing either in a warning colour spends attention on the wrong
    // row and teaches the reader to ignore the one that matters.
    expect(CSS).toMatch(
      /\[data-key-power="absent"\],\s*\.key-power\[data-key-power="held"\]\s*\{\s*color: var\(--muted-foreground\)/
    );
    expect(CSS).toMatch(/\[data-key-power="unusable"\]\s*\{\s*color: var\(--error\)/);
    expect(CSS).toMatch(/\[data-key-power="loaded"\]\s*\{\s*color: var\(--warn\)/);
    expect(CSS).toMatch(/\[data-key-power="ready"\]\s*\{\s*color: var\(--success\)/);
  });
});

describe("the Keys tab stopped being the one with no number", () => {
  it("carries how many keys are open, like every sibling tab", () => {
    expect(SHELL).toMatch(/id: "keys" as const,[\s\S]{0,200}count: keysLoaded/);
    expect(SHELL).toMatch(/loadedCount\(keyViews\.map\(\(v\) => v\.power\)\)/);
  });

  it("counts from the rows the tray draws, not a second derivation", () => {
    // The badge and the list have to answer the same question or the tab is a
    // number contradicting the panel it opens.
    expect(VAULT).toMatch(/loadedCount\(keys\.map\(\(k\) => k\.power\)\)/);
  });
});

describe("a key open in this browser is visible without going looking", () => {
  it("puts the chip on the row that is never collapsed", () => {
    expect(SHELL).toMatch(/keyChip=\{\{/);
    expect(RUNBAR).toMatch(/data-key-chip/);
    expect(RUNBAR).toMatch(/data-key-power=\{chip\.power\}/);
  });

  it("gives sessionEarliestExpiry its first caller", () => {
    // Exported, correct, and reaching nothing — the dead-mechanism defect this
    // repo closes over and over. The chip is the consumer.
    expect(SHELL).toMatch(/import \{ sessionEarliestExpiry \} from "\.\.\/lib\/vault-session\.js"/);
    expect(SHELL).toMatch(/return sessionEarliestExpiry\(\)/);
    expect(SHELL).toMatch(/expiresAt: keysExpireAt/);
  });

  it("says nothing at all when nothing is held", () => {
    // A permanent "0 keys" on every notebook that never touches one is noise,
    // and noise is what makes the chip that matters unreadable.
    expect(RUNBAR).toMatch(/keyChip && keyChip\.loaded > 0/);
  });

  it("is a way into the tray, not only a readout", () => {
    expect(RUNBAR).toMatch(/onOpenKeys/);
    expect(SHELL).toMatch(/onOpenKeys=\{\(\) => \{[\s\S]{0,120}setTrayTab\("keys"\)/);
  });
});

describe("the session says what a key will ask of it, before the press", () => {
  it("annotates each option with the same words the tray uses", () => {
    expect(START).toMatch(/\{k\.note \? ` — \$\{k\.note\}` : ""\}/);
    expect(SHELL).toMatch(/note: keyViews\.find\(\(v\) => v\.fingerprint === k\.fingerprint\)\?\.powerLabel/);
  });

  it("looks the chosen key up in every row, not only the offered ones", () => {
    // A key that expires with the sheet open drops out of the chooser and
    // leaves the fingerprint selected. Removing a row is not a refusal.
    expect(SHELL).toMatch(/const chosenSessionKey = useMemo\(\(\) => \{[\s\S]{0,300}nb\.vaultKeys\.find/);
    expect(SHELL).toMatch(/heldCount: nb\.vaultKeys\.length/);
  });
});

describe("a never-trust mark is a refusal, not a prompt", () => {
  it("names the mark and where to change it", () => {
    expect(START).toMatch(/export const NEVER_TRUSTED/);
    expect(START).toMatch(/marked this key/);
    expect(START).toMatch(/ownertrust/);
  });

  it("guards both doors onto the room", () => {
    // The row's button and `Fingerprint`'s own actions menu both add. A check
    // on the button alone leaves the menu route open, which is how the
    // original `confirm()` was bypassed by the one path nobody tested.
    expect(START).toMatch(/if \(refused\.has\(clean\)\) \{/);
    expect(START).toMatch(/never \? NEVER_TRUSTED/);
    expect(START).toMatch(/aria-live="polite"[\s\S]{0,200}data-add-refusal/);
  });

  it("shows a short-id hit rather than hiding it and calling the search empty", () => {
    // The shell used to drop these, so "No key here answers to that" was
    // printed to somebody whose search had matched — a refusal naming a state
    // they were not in, which is the class of bug this whole change is about.
    expect(START).toMatch(/export const SHORT_ID_HIT/);
    expect(START).toMatch(/short \? SHORT_ID_HIT/);
    expect(SHELL).not.toMatch(/hit\.fingerprint\.length >= 40/);
  });

  it("never asks a native dialog to carry a security decision", () => {
    // Comments stripped first: both files explain the `confirm()` they
    // replaced, and prose about an absence satisfies a naive grep — the same
    // trap `disabled-needs-reason.test.js` documents.
    const code = (t) => t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
    expect(code(START)).not.toMatch(/(?<![\w.])confirm\(/);
    expect(code(VAULT)).not.toMatch(/(?<![\w.])confirm\(/);
  });
});

describe("the vault's verbs have a consumer in the tray", () => {
  it("wires generate, import, export and delete to the shared module", () => {
    expect(SHELL).toMatch(/generateVaultKey\(spec\)/);
    expect(SHELL).toMatch(/importPrivateKey\(spec\.armored/);
    expect(SHELL).toMatch(/exportVaultKey\(\{ \.\.\.spec, meta \}\)/);
    expect(SHELL).toMatch(/await deleteKey\(fingerprint\)/);
    for (const prop of [
      "onGenerate=",
      "onImport=",
      "onExport=",
      "onDelete=",
      "onDeviceLabel=",
      "onTrust=",
      "onCopyPublicLine=",
    ]) {
      expect(SHELL, prop).toContain(prop);
    }
  });

  it("offers passkey PRF enrolment, and says why when it cannot", () => {
    // An option that simply vanishes teaches nobody why the security key in
    // their hand is not on offer.
    expect(SHELL).toMatch(/isPasskeyPrfAvailable\(\)/);
    expect(VAULT).toMatch(/useRefusal\(passkeyAvailable \? undefined : passkeyWhy\)/);
  });

  it("writes all four export formats", () => {
    for (const id of ["asc", "gpg", "qr", "paper"]) {
      expect(VAULT, id).toMatch(new RegExp(`id: "${id}"`));
    }
  });

  it("still lets /my-keys do all of it, because nothing was deleted yet", () => {
    // Both surfaces working at once is the point of this phase: the retirement
    // of the standalone pages depends on this landing first, and a vault with
    // one door that has just moved is a vault somebody cannot open.
    for (const fn of [
      "function renderVaultSection",
      "function renderGenerateCard",
      "function renderImportCard",
      "function renderExportPanel",
      "async function runVaultExport",
    ]) {
      expect(MYKEYS, fn).toContain(fn);
    }
  });
});
