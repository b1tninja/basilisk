import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type PointerEvent as ReactPointerEvent,
} from "react";
import {
  Link2,
  Eraser,
  Plus,
  MoreHorizontal,
  KeyRound,
  LayoutGrid,
  ArrowDownToLine,
  History,
  ArrowUpFromLine,
  SlidersHorizontal,
  Cable,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Fingerprint } from "@/components/ui/fingerprint";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { restartLiveIce } from "../lib/toolkit/quorum-ops.js";
import { closeLink, restartLink } from "../lib/webrtc/link-registry.js";
import { RELAY_DISCLOSURE } from "../lib/webrtc/relay-fallback.js";
import { setClipboardReadGate } from "../lib/toolkit/clipboard-ops.js";
import {
  beginApprovalRun,
  clearApprovalGrants,
  listApprovalGrants,
  revokeApprovalGrants,
  setApprovalGate,
  type ApprovalDecision,
  type ApprovalRequest,
} from "../lib/toolkit/approval-gate.js";
import { ApprovalBanner } from "./widgets/ApprovalBanner";
import {
  activityAsText,
  clearActivity,
  formatActivityTime,
  listActivity,
  onActivityChange,
} from "../lib/toolkit/activity-log.js";
import { execFileRead } from "../lib/toolkit/file-ops.js";
import { execQrScan } from "../lib/toolkit/qr-scan.js";
import { setCssVar } from "../lib/css-vars.js";
import { cn } from "@/lib/cn";
import { cellErrorRows, recipeUpgrade, useNotebook } from "./useNotebook";
import { RecipientBinderHost } from "./RecipientBinderHost";
import { CellWarnings, warningDismissKey } from "./CellWarnings";
import {
  OpsShelf,
  DocsFooter,
  CellTypeErrors,
  CellProvenance,
  RoomCells,
  GpgKeyBinder,
  KeyVault,
  type VaultKeyView,
  ConnectionsPanel,
  DkgPanel,
  PoolPanel,
  CeremonySheet,
  ShareCheck,
  IntegrityPanel,
  STEP_MIME,
  parseStepMime,
  ModeToggle,
  MenuPopover,
  PresetMenu,
  RecipeChipFlow,
  ParamFieldGroup,
  CryptoProfileControl,
  RunBar,
  ReadinessBar,
  OutputList,
  CellAssign,
  ShareSheet,
  SessionSheet,
  HandoffQueue,
  NotebookShare,
  PlanPanel,
  SessionStrip,
  TopBar,
  type HandoffRow,
  type OwedBack,
  type RecipientChoice,
  type SuiteTone,
  type SuiteDetail,
} from "./widgets/index";
import { getStep } from "../lib/toolkit/registry.js";
import { stepUnboundSlots } from "../lib/toolkit/input-needs.js";
import type { DkgParticipant } from "../lib/quorum/dkg-session.js";
import type {
  PoolParticipant,
  PoolParticipantState,
} from "./widgets/PoolPanel";
import {
  GALLERY_ENTRIES,
  ROOM_TEMPLATES,
  compileRecipe,
  outSlotLabels,
  projectTypeForMember,
  publishedSlots,
} from "../lib/toolkit/recipe.js";
import { planRun } from "../lib/toolkit/plan.js";
import { roomRoster } from "../lib/notebook/roster.js";
import { departedPeers, unassignDeparted } from "../lib/toolkit/peer-relabel.js";
import {
  hashForJoin,
  hashForNotebook,
  hashForToolkitState,
  parseToolkitHash,
  recipeLinkDiscloses,
  toolkitShareUrl,
  writeToolkitHash,
} from "../lib/toolkit/fragment.js";
import {
  START_OPENS,
  sessionKeyChoices,
  startIssues,
} from "../lib/toolkit/session-flow.js";
import {
  roomCeremony,
  roomCeremonySummary,
} from "../lib/toolkit/room-ceremony.js";
import {
  custodianRecovery,
  dealHoldings,
  roomRecovery,
} from "../lib/toolkit/room-recovery.js";
import {
  keyPower,
  keyPowerReadout,
  loadedCount,
  strongestPower,
} from "../lib/toolkit/key-power.js";
import { sessionEarliestExpiry } from "../lib/vault-session.js";
import { expiryNote } from "../lib/toolkit/artifact-readouts.js";
import {
  exportVaultKey,
  generateVaultKey,
  importPrivateKey,
} from "../lib/toolkit/vault-manage.js";
// The picker the encryption side has always had, on the side that had none.
// `SessionStart` cannot reach for these itself — it is on the design surface,
// where a widget takes plain props and reads no store.
import {
  listTrustedRecipientSuggestions,
  searchRecipients,
} from "../lib/recipient-picker.js";
import { primaryUidLabel } from "../lib/key-hit.js";
import { qrSvg } from "../lib/qr.js";
import { stepOverridesProfile } from "../lib/pgp/profile-from-step.js";
import {
  cellPipelineTip,
  nestedTipFor,
  selectorGhostsFor,
  tipFitFor,
} from "../lib/toolkit/suggest.js";
import { getTrust, listTrusted, setTrust, type TrustLevel } from "../lib/trust.js";
import { getSuiteStatus, runCryptoSelfTests } from "../lib/crypto-self-test.js";
import { getFipsMode, setFipsMode, FIPS_MODE_DISCLAIMER } from "../lib/fips-mode.js";
import { unverifiedSuitesAmong, suitesUsedByAst } from "../lib/toolkit/suite-gate.js";
import {
  listWorkspaces,
  saveWorkspace,
  parseWorkspaceFile,
  newWorkspaceId,
} from "../lib/toolkit/workspace-store.js";
import type { ToolkitWorkspace } from "../lib/toolkit/workspace-store.js";
import { openSignedPlaybook } from "../lib/toolkit/playbook.js";
import type { PlaybookOpening } from "../lib/toolkit/playbook.js";
import { deleteKey, isPasskeyPrfAvailable, listKeys } from "../lib/vault.js";
import { getDeviceLabel, setDeviceLabel } from "../lib/prefs.js";
import { exposureTrace } from "../lib/toolkit/slot-graph.js";
import { copyText, formatFingerprint } from "../lib/utils.js";
import { NO_LINK_YET } from "./widgets/InviteCard";
import type { ArmedBranch, ChipPath, ChipStemView } from "./widgets/RecipeChipFlow";
import type { CellStatus, RecipeChain, RecipeStep } from "./notebook-types";

type CellView = "pipeline" | "source";

type SuiteState = "verified" | "unverified" | "error";

/** Extends the OpenPGP/WebCrypto/SSS CAST suite map with a client-side WebAuthn capability check. */
type ToolkitSuiteStatus = {
  openpgp: SuiteState;
  webcrypto: SuiteState;
  sss: SuiteState;
  webauthn: SuiteState;
};

/**
 * `file.read | qr.scan` on a photo of a share card.
 *
 * Composed from the two ops rather than reaching for a camera: the realistic
 * input is a phone photo or a screenshot that arrives as a file, and the
 * browser's own picker is the consent — the same reasoning `file.read` itself
 * records. Kept at module scope so it is obviously the same pair of calls a
 * recipe would make, with no shell state involved.
 */
async function scanCardPhoto(): Promise<string> {
  const file = await execFileRead({ accept: "image/*", as: "bytes" });
  const scanned = await execQrScan(file, {});
  return String(scanned.data ?? "");
}

/**
 * Why Run all refuses when the recipe does not compile.
 *
 * The shell is the only thing that holds `validation.errors`, and until this
 * existed it handed the run bar a single bit derived from them — the one shape
 * of defect this whole area keeps producing, a control that declines with the
 * words for it sitting one component away.
 *
 * The first error verbatim, then a count. Verbatim because these sentences
 * already name the step and the reason ("Unknown step \"foo\""), and a
 * paraphrase here would be a second vocabulary for the compiler's complaints.
 * The count because Run all is a whole-notebook control: fixing the named error
 * and finding the button still dead is precisely the report this change exists
 * to end.
 */
function runRefusal(
  validation: { ok?: boolean; errors?: { message: string }[] } | undefined
): string | null {
  if (!validation || validation.ok) return null;
  const errors = validation.errors || [];
  const [first] = errors;
  if (!first) {
    // `ok: false` with nothing in `errors` is a compiler bug, not a user state,
    // and saying "the recipe has a problem" would be the contentless reason
    // this rule forbids. Naming it as ours is the honest sentence available.
    return "The recipe did not compile, and the compiler returned no message — that is a fault in this build rather than something in the notebook. Copy the recipe before reloading.";
  }
  const rest = errors.length - 1;
  return `The recipe does not compile: ${first.message}${
    rest > 0 ? ` — and ${rest} more error${rest > 1 ? "s" : ""} after it` : ""
  }.`;
}

/**
 * The id of a cell's readiness line, so its Run button can describe itself
 * with the sentence already on screen. Index-keyed rather than `useId`: this
 * is inside a `.map` where hooks cannot go, and a cell index is unique on the
 * page by construction.
 */
const cellReadinessId = (cell: number) => `cell-readiness-${cell}`;

/**
 * The two ids the workspace's landmarks are named by.
 *
 * Constants rather than `useId`, because both are referenced across the shell
 * — the notebook's `<main>` is named by a heading that lives up in the top
 * bar, several hundred lines away and inside another component — and because
 * exactly one shell renders per page, so a generated id would buy uniqueness
 * that is already guaranteed and cost the ability to point at it from here.
 */
const NOTEBOOK_TITLE_ID = "toolkit-notebook-title";
const TRAY_TITLE_ID = "toolkit-tray-title";

/** Collapse an artifact's content to one displayable line for OutputList (§20h). */
function oneLinePreview(content: string, max = 140): string {
  const flat = content.replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max)}…` : flat;
}

function webauthnCapabilityStatus(): SuiteState {
  // WebAuthn isn't covered by the POST/CAST self-test (crypto-self-test.js) —
  // this is a plain browser-capability probe, not a verified algorithm test.
  return typeof window !== "undefined" && typeof window.PublicKeyCredential !== "undefined"
    ? "verified"
    : "unverified";
}

const SUITE_BADGE_LABEL: Record<keyof ToolkitSuiteStatus, string> = {
  webcrypto: "WebCrypto",
  openpgp: "OpenPGP",
  sss: "SSS",
  webauthn: "WebAuthn",
};

// Same localStorage key/shape as toolkit-legacy.js's pane layout, so the
// preference carries over between the legacy and React toolkit.
const LAYOUT_KEY = "basilisk.toolkit.layout";
const OPS_PANE_LIMITS = { min: 160, max: 520, def: 220 };

/**
 * How far one arrow key moves the panel edge, in px.
 *
 * The drag has no step — it follows the pointer — so this number exists only
 * for the keyboard, and it is a trade between the two things a keyboard user
 * wants from a resizer: land on the width you meant, and get there. 16px
 * crosses the 360px range in 23 presses, which is a held arrow key rather
 * than a count, and it is still fine enough to nudge a truncated op label
 * into view. `Shift` multiplies it, because the coarse move is the one that
 * would otherwise be key-repeat: four steps at a time crosses the range in
 * six presses. A modifier nobody discovers costs nothing — the plain arrow
 * already reaches every width — whereas `Home`/`End` are the two ends and
 * cannot serve as "roughly twice as far".
 */
const OPS_PANE_STEP = 16;

/**
 * The one place a Toolkit-panel width is held to its limits.
 *
 * The drag and the arrow keys are two roads to the same number, and two
 * clamping expressions is how they would come to disagree about what the
 * minimum is. Rounds as well as clamps: the drag arrives with a fractional
 * `clientX` and the stored preference is read back on the next load, so a
 * width that is not an integer is a width that gets written to localStorage.
 */
function clampOpsWidth(width: number) {
  return Math.round(Math.max(OPS_PANE_LIMITS.min, Math.min(OPS_PANE_LIMITS.max, width)));
}

type ToolkitLayout = { opsW?: number | null; opsCollapsed?: boolean | null };

function loadToolkitLayout(): ToolkitLayout {
  try {
    return JSON.parse(window.localStorage.getItem(LAYOUT_KEY) || "{}") || {};
  } catch {
    return {};
  }
}

function saveToolkitLayout(patch: ToolkitLayout) {
  try {
    const next: ToolkitLayout = { ...loadToolkitLayout(), ...patch };
    for (const k of Object.keys(next) as (keyof ToolkitLayout)[]) {
      if (next[k] == null) delete next[k];
    }
    window.localStorage.setItem(LAYOUT_KEY, JSON.stringify(next));
  } catch {
    /* private mode etc. — layout just won't persist */
  }
}

function formatCountdown(ms: number): string {
  const total = Math.max(0, Math.round(ms / 1000));
  const m = Math.floor(total / 60);
  const s = total % 60;
  return `${m}:${String(s).padStart(2, "0")}`;
}

function relativeTime(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime();
  const mins = Math.round(ms / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

/** Short elapsed-seconds form for the cell status line ("14s ago", not "0m ago"). */
function relativeTimeShort(atMs: number, now: number): string {
  const secs = Math.max(0, Math.round((now - atMs) / 1000));
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

// Cell-status colours live in toolkit.css as `[data-cell-status]` rules — the
// map that used to be here fed a style prop the production CSP refuses.

/** One-line status: dot color + plain-language text, replacing the old badge pile. */
function describeCellStatus(
  status: CellStatus,
  timing: { ranAt: number; durationMs: number } | null,
  now: number
): string {
  if (status === "running") return "running…";
  if (status === "error") return timing ? `failed ${relativeTimeShort(timing.ranAt, now)}` : "failed";
  if (status === "stale") return "edited since last run";
  // No timing, and none is withheld: a declined cell has no duration because
  // nothing here took any time. This line is the only place a reader finds out
  // that the gate fired, so it says both halves — where the cell runs, and that
  // this is not where.
  if (status === "declined") return "placed elsewhere — not run here";
  if (status === "ok" && timing) {
    return `ran ${relativeTimeShort(timing.ranAt, now)} · ${timing.durationMs}ms`;
  }
  return "never run";
}

/**
 * Blocker copy + priority for ReadinessBar (§20e). Priority: recipient/key
 * binding first, runtime secrets second, everything else after. Action text
 * always matches the named blocker.
 */
const NEED_BLOCKER: Record<
  string,
  { priority: number; label: string; action: string; tray: "keys" | "inputs" }
> = {
  // Recipients are public keys you encrypt *to*, so they live in Keys — this
  // pointed at Inputs, where they have never been. The wording matches
  // `gpg.encrypt`'s runtime error deliberately: a failure discovered before
  // the run and the same failure discovered during it should not be two
  // different sentences describing one problem.
  "needs recipients": {
    priority: 0,
    label: "no recipients chosen",
    action: "Open Keys",
    tray: "keys",
  },
  "needs key": { priority: 0, label: "no key is unlocked", action: "Open Keys", tray: "keys" },
  "needs input": { priority: 1, label: "message text isn't set", action: "Add text", tray: "inputs" },
  "needs ciphertext": { priority: 1, label: "ciphertext isn't pasted", action: "Paste", tray: "inputs" },
  "needs shares": { priority: 1, label: "share mnemonics aren't entered", action: "Enter", tray: "inputs" },
  "needs envelope": { priority: 1, label: "an OpenPGP envelope isn't provided", action: "Provide", tray: "inputs" },
  // `keypair` (§31c) takes its JWK/PEM at run time, so Inputs is right here —
  // unlike recipients above. Listed explicitly so it reads as a sentence
  // rather than falling through to "key material is missing".
  "needs key material": {
    priority: 1,
    label: "no key has been pasted",
    action: "Paste",
    tray: "inputs",
  },
};

/**
 * One-line description of where the next inserted/appended op will land —
 * shown in the toolbox header so it always agrees with the pipeline's own
 * gap highlight, instead of the caret being invisible `pendingInsert` state.
 */
function describeCaretPosition(
  pendingInsert: ChipPath | null,
  focusedCell: number,
  steps: RecipeStep[]
): string {
  if (pendingInsert?.body != null) {
    return `inside step ${pendingInsert.stem + 1} · cell [${focusedCell}]`;
  }
  const stem = pendingInsert?.stem;
  if (stem == null || stem >= steps.length) {
    return steps.length
      ? `at the end of cell [${focusedCell}]`
      : `in empty cell [${focusedCell}]`;
  }
  if (stem <= 0) return `at the start of cell [${focusedCell}]`;
  const prev = steps[stem - 1];
  return `after \`${prev?.name || "…"}\` in cell [${focusedCell}]`;
}

const PGP_ENCRYPT_STEPS = new Set(["gpg.encrypt", "gpg.symencrypt"]);

/**
 * Why the deal's picker cannot be opened right now, in one place.
 *
 * Two doors reach it — the Templates card and a `#t=room-deal` link — and a
 * closed door that gave two accounts of itself would be worse than one that
 * gave none.
 *
 * ## Why it is not simply moved under the live half
 *
 * `RoomRecovery` sits under *both* halves of `SessionSheet`, and the reason
 * given there — a recovery is most often written while the original room is
 * live — invites the same treatment here. It does not transfer, and the
 * argument is not the sheet's geometry:
 *
 *  - **Writing a deal replaces the notebook you have open.** The picker's own
 *    button says so, in those words. During an exchange that notebook is what
 *    the room agreed to run, and this sheet's description promises the
 *    notebook "replaces nothing anybody has written without their say-so". A
 *    one-press whole-notebook replacement inside a live room is that promise
 *    inverted, for every peer at once. A recovery is a *new* notebook for a
 *    room that may already be gone, which is why it can be offered anywhere.
 *  - **It would need a second derivation of the roster.** `draftCeremony`
 *    reads `sessionDraft.audience`; a live session's roster is
 *    `sessionAudience`, computed elsewhere. Mirroring the picker means either
 *    generating a deal for the room you are *not* in, or standing up a second
 *    source of truth for the audience of a document whose whole safety
 *    property is that the fingerprints in its headers and the people in the
 *    room cannot disagree.
 *
 * So the refusal stays. What it now says is what stopping costs, because two
 * things were wrong with the earlier sentence and neither was the state:
 *
 *  - "Close the session" named a press with a near-homonym on the main
 *    toolbar. **Clear session** there is `clearSensitive` — it evicts unlocked
 *    private keys and clears the activity log, and does not touch the
 *    exchange. A reader following the old remedy from the Templates gallery
 *    would have found that button first, lost their keys, and still been
 *    refused. The press that works is `SessionLive`'s **Close session**, so
 *    both are named and told apart.
 *  - Closing is not free. `closeQuorumExchange` empties `handoffs` — the cells
 *    and results peers have sent for a decision — along with the inbox, the
 *    unacked sends and the notebook proposal. A remedy that silently discards
 *    a peer's unanswered document is not one a person can consent to, so the
 *    sentence names it.
 *
 * Deliberately still a sentence and not a button: putting a session-closing
 * press inside a browse surface would be a destructive act one click from the
 * Templates gallery, with the confirmation nowhere.
 */
const CEREMONY_PICKER_LIVE =
  "A deal is written before the room opens, and writing one replaces the notebook you have open — while an exchange is live that is the notebook this room is running, so there is no picker on this sheet. Close the session to write one — the press is “Close session” in the session panel, not “Clear session” in the toolbar — and closing drops anything a peer has sent you that you have not answered yet. Or use the notebook you already dealt from.";

/** Every step (including tee/foreach nests) whose `profile` param overrides the session default. */
function collectProfileOverrides(chains: RecipeChain[]): ChipPath[] {
  const out: ChipPath[] = [];
  chains.forEach((chain, cell) => {
    (chain.steps || []).forEach((step, stem) => {
      if (PGP_ENCRYPT_STEPS.has(step.name) && stepOverridesProfile(step)) {
        out.push({ cell, stem, branch: null, body: null });
      }
      (step.body || []).forEach((bs, body) => {
        if (PGP_ENCRYPT_STEPS.has(bs.name) && stepOverridesProfile(bs)) {
          out.push({ cell, stem, branch: null, body });
        }
      });
      (step.branches || []).forEach((br, branch) => {
        (br.body || []).forEach((bs, body) => {
          if (PGP_ENCRYPT_STEPS.has(bs.name) && stepOverridesProfile(bs)) {
            out.push({ cell, stem, branch, body });
          }
        });
      });
    });
  });
  return out;
}

/**
 * One `basilisk:dkg-progress` event. `running` while contributions land, then
 * exactly one terminal phase — see `lib/toolkit/dkg-ops.js`, which is the only
 * thing that dispatches it.
 */
type DkgProgressDetail = {
  phase: "running" | "complete" | "refused" | "failed";
  threshold?: number;
  participants?: number;
  commitments?: string[];
  shares?: string[];
  expected?: string[];
  publicKey?: string;
  /** Fingerprint of the participant whose share did not check. */
  dealer?: string;
  message?: string;
};

/**
 * What a `dkg.run` has told us so far, in the shape `DkgPanel` reads.
 *
 * `dkg.run` blocks its cell for up to two minutes and dispatches
 * `basilisk:dkg-progress` as contributions land. Nothing listened, so the only
 * thing on screen for two minutes was a spinning cell — and if the run refused,
 * the reason a bad share matters (see `lib/quorum/dkg-session.js`) never reached
 * anybody at all.
 *
 * The roster is the exchange's, not a second one: connected and authenticated
 * come from the same rows `ConnectionsPanel` draws, and only `round` comes from
 * the run. That is the panel's own rule — three axes, never merged — and it is
 * why the progress event had to learn to name participants before this could
 * exist. Counts could not have filled this in without inventing it.
 *
 * `verified` is claimed for a peer only when the whole run completed, because
 * until `finalize` returns nobody has checked anything: a share that has
 * *arrived* is not a share that *checks*, and drawing "checked" early would be
 * the one lie this panel exists to avoid.
 */
function dkgParticipants(
  peers: { id: string; fingerprint: string; state?: string; authenticated?: boolean }[],
  selfFpr: string,
  progress: DkgProgressDetail
): DkgParticipant[] {
  const commitments = new Set(progress.commitments || []);
  const shares = new Set(progress.shares || []);
  const out: DkgParticipant[] = [];
  if (selfFpr) {
    out.push({
      id: "you",
      fingerprint: selfFpr,
      self: true,
      // True rather than decorative: this participant dealt its own polynomial
      // before anything was sent. Never read — `dkg-session.js` filters `self`
      // out of every count — but a value on screen should not be a placeholder.
      round: "verified",
      state: "connected",
      authenticated: true,
    });
  }
  for (const p of peers) {
    const fpr = p.fingerprint || "";
    out.push({
      id: p.id,
      fingerprint: fpr,
      round:
        progress.phase === "refused" && progress.dealer === fpr
          ? "bad"
          : progress.phase === "complete"
            ? "verified"
            : shares.has(fpr)
              ? "share"
              : commitments.has(fpr)
                ? "commitments"
                : "waiting",
      state: (p.state || "new") as DkgParticipant["state"],
      authenticated: !!p.authenticated,
    });
  }
  return out;
}

/**
 * One `basilisk:entropy-pool` event. `running` while contributions land, then
 * exactly one terminal phase — see `lib/toolkit/entropy-pool-ops.js`, the only
 * thing that dispatches it.
 */
type PoolProgressDetail = {
  phase: "running" | "complete" | "refused" | "failed";
  round?: "committing" | "revealing";
  participants?: number;
  commitments?: string[];
  reveals?: string[];
  expected?: string[];
  digest?: string;
  /** Fingerprints whose reveal did not open their commitment. */
  broken?: string[];
  /** Fingerprints who committed and never revealed. */
  silent?: string[];
  message?: string;
};

/**
 * What an `entropy.pool` has told us so far, in the shape `PoolPanel` reads.
 *
 * Built the way `dkgParticipants` is — from the exchange's own roster plus the
 * run's progress — and with the same rule: **a state is claimed only when
 * something established it.** A reveal that has *arrived* is not one that opens
 * its commitment; `openEntropyPool` checks every reveal at the end, together.
 * So `verified` waits for the round to open and `broken` for the refusal that
 * names who. Merging "revealed" into "checked" would be the same lie as calling
 * a DKG share checked on arrival, and it costs more here: the whole ceremony
 * exists because a participant may choose theirs after seeing the others.
 */
function poolParticipants(
  peers: { id: string; fingerprint: string }[],
  selfFpr: string,
  progress: PoolProgressDetail
): PoolParticipant[] {
  const commitments = new Set(progress.commitments || []);
  const reveals = new Set(progress.reveals || []);
  const broken = new Set(progress.broken || []);
  const silent = new Set(progress.silent || []);
  const out: PoolParticipant[] = [];
  if (selfFpr) {
    // True rather than decorative: this participant committed and revealed
    // before anything was sent, and its own contribution opens its own
    // commitment by construction.
    out.push({ id: "you", fingerprint: selfFpr, self: true, state: "verified" });
  }
  for (const p of peers) {
    const fpr = p.fingerprint || "";
    const state: PoolParticipantState = broken.has(fpr)
      ? "broken"
      : silent.has(fpr)
        ? "silent"
        : progress.phase === "complete"
          ? "verified"
          : reveals.has(fpr)
            ? "revealed"
            : commitments.has(fpr)
              ? "committed"
              : "waiting";
    out.push({ id: p.id, fingerprint: fpr, state });
  }
  return out;
}

/**
 * Params in one cell that only a `$slot` can fill and that nothing will ask for.
 *
 * The fourth entry in `ReadinessBar`'s own priority list — "blocked required
 * param" — which has been in its doc comment since §20e and had no producer.
 * `unmetForCell` cannot supply it: it is built from `inputNeeds`, and a param
 * with no runtime panel behind it is by definition not one. So the cell reads
 * ready, Run starts, and `ssh.sign` dies on "key= (private key slot) is
 * required" with the recipe still on screen saying nothing.
 *
 * Nests are walked the same way `collectProfileOverrides` walks them, and for
 * the same reason: a step inside a tee branch is a step, and a warning that
 * stopped at the top level would be quietly wrong exactly where a recipe is
 * hardest to read. The `ChipPath` is what makes the blocker's button able to
 * open the field it is talking about rather than a tray that cannot help.
 */
function unboundSlotBlockers(
  chain: RecipeChain | undefined,
  cell: number
): { path: ChipPath; step: string; param: string }[] {
  const out: { path: ChipPath; step: string; param: string }[] = [];
  const add = (step: RecipeStep, path: ChipPath) => {
    for (const u of stepUnboundSlots(step)) {
      out.push({ path, step: u.step, param: u.param });
    }
  };
  (chain?.steps || []).forEach((step, stem) => {
    add(step, { cell, stem, branch: null, body: null });
    (step.body || []).forEach((bs: RecipeStep, body: number) =>
      add(bs, { cell, stem, branch: null, body })
    );
    (step.branches || []).forEach((br: { body?: RecipeStep[] }, branch: number) =>
      (br.body || []).forEach((bs, body) => add(bs, { cell, stem, branch, body }))
    );
  });
  return out;
}

/**
 * Write the notebook to a file the reader can carry.
 *
 * The third offline path, and the only one with no size limit. A link needs a
 * channel to paste into; a QR needs the notebook to be under about 2,950
 * bytes; a file needs neither, which is what makes it the honest fallback when
 * the QR refuses.
 *
 * The recipe text and nothing else — no manifest, no receipt, no keys. It is
 * the same bytes the link's fragment carries, so a notebook restored from a
 * file and one restored from a link are the same notebook, which is the whole
 * premise of treating the recipe as the build input.
 */
function saveNotebookFile(title: string, recipe: string): void {
  const stem =
    String(title || "notebook")
      .trim()
      .replace(/[^A-Za-z0-9._-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 60) || "notebook";
  const blob = new Blob([recipe], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${stem}.recipe.txt`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoked on the next tick rather than immediately: Safari has historically
  // read the blob after the click returns.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function workspaceStepCount(recipe: string): number {
  try {
    const { ast } = compileRecipe(recipe);
    return (ast?.chains || []).reduce(
      (n: number, c: { steps?: unknown[] }) => n + (c.steps?.length || 0),
      0
    );
  } catch {
    return 0;
  }
}

/**
 * What to say when a step's × removed more than the step.
 *
 * A branch with no steps cannot be serialized, so removing the last one takes
 * the branch — and the tee, if that was its last branch. That is more than the
 * × named, so it gets said out loud and undone in one click, on the same rule
 * the branch × already follows. `null` when nothing else went.
 */
function cascadeNote(gone: { droppedBranch: boolean; droppedStem: boolean }) {
  if (gone.droppedStem)
    return "Removed the branch's last step — the empty branch and its tee went with it.";
  if (gone.droppedBranch)
    return "Removed the branch's last step — the empty branch went with it.";
  return null;
}

export function ToolkitShell() {
  const nb = useNotebook();
  const [chipEdit, setChipEdit] = useState<ChipPath | null>(null);
  /**
   * One-shot field to autofocus once chipEdit lands (design v2 §22b).
   *
   * Carries the op as well as the param. It used to be a bare param name and
   * the editor gated it on `selectedStep.name === "rtc.ice"` — correct while
   * "Configure TURN" was the only sender, and a trap the moment a second one
   * existed: `key` is a param on a dozen ops, so a hint meant for `ssh.sign`
   * would have focused whichever of them the editor happened to be showing.
   */
  const [focusParamHint, setFocusParamHint] = useState<{
    step: string;
    param: string;
  } | null>(null);
  useEffect(() => {
    if (!focusParamHint) return;
    const t = window.setTimeout(() => setFocusParamHint(null), 50);
    return () => window.clearTimeout(t);
  }, [focusParamHint]);
  /** Cell the live quorum exchange was opened in — SessionStrip pins there (§21a). */
  const [quorumCell, setQuorumCell] = useState<number | null>(null);
  /**
   * The room being named, before there is one.
   *
   * Shell state rather than the hook's, because until Start is pressed nothing
   * of it exists anywhere else: a half-typed audience is not a session, and
   * putting it in `useNotebook` would give the notebook a field describing a
   * room that may never be opened. Once it *is* opened the live exchange owns
   * every one of these facts and this stops being read.
   */
  const [sessionDraft, setSessionDraft] = useState<{
    role: "offer" | "join";
    keyFingerprint: string;
    audience: string[];
  }>({ role: "offer", keyFingerprint: "", audience: [] });
  /**
   * Cells run here on somebody else's behalf, whose signed answer is owed back.
   *
   * Kept by the shell because it is a record of *presses*, not of documents:
   * `quorum-ops` deliberately keeps no record of what it delivered, and the
   * session keeps none of what it accepted. Accepting an offer is the only
   * moment anything knows a result will be owed, and this is where that press
   * happens.
   */
  const [owedBack, setOwedBack] = useState<OwedBack[]>([]);
  /**
   * Why accepting a still-pending document was refused, by handoff id.
   *
   * Beside `owedBack` because it is the same kind of thing: a record of presses
   * this shell made, which `quorum-ops` and the session both deliberately keep
   * none of. Session-scoped and never persisted — it dies with the exchange, in
   * the same effect that empties `owedBack`.
   *
   * It exists because a refusal no longer consumes. `acceptHandoff` used to take
   * the document on its first line and judge afterwards, so a refused row simply
   * vanished and there was nothing left to annotate; now the row stays, and a
   * row that has been refused once must not look like one nobody has touched.
   */
  const [handoffRefusals, setHandoffRefusals] = useState<Record<string, string>>({});
  /**
   * The live `dkg.run`, or null when none has spoken.
   *
   * Null rather than an idle object so the panel is absent rather than empty:
   * a distributed key generation is a thing you deliberately start, and a
   * permanently-mounted "no DKG" card would be furniture. Cleared when the
   * exchange ends, because a completed run's roster describes a room that is
   * gone.
   */
  const [dkgProgress, setDkgProgress] = useState<DkgProgressDetail | null>(null);
  /**
   * The live `entropy.pool`, or null when none has spoken. Same shape and same
   * reasons as `dkgProgress`: absent rather than empty, and cleared with the
   * exchange, because a pool describes the room that drew it.
   */
  const [poolProgress, setPoolProgress] = useState<PoolProgressDetail | null>(null);
  useEffect(() => {
    const onPool = (ev: Event) => {
      const detail = (ev as CustomEvent).detail as PoolProgressDetail;
      if (detail?.phase) setPoolProgress(detail);
    };
    window.addEventListener("basilisk:entropy-pool", onPool);
    return () => window.removeEventListener("basilisk:entropy-pool", onPool);
  }, []);
  useEffect(() => {
    const onDkg = (ev: Event) => {
      const detail = (ev as CustomEvent).detail as DkgProgressDetail;
      if (detail?.phase) setDkgProgress(detail);
    };
    window.addEventListener("basilisk:dkg-progress", onDkg);
    return () => window.removeEventListener("basilisk:dkg-progress", onDkg);
  }, []);
  useEffect(() => {
    if (nb.quorumState.phase !== "idle") return;
    setDkgProgress(null);
    setPoolProgress(null);
  }, [nb.quorumState.phase]);

  /** The last handoff attempt's outcome, in the handoff layer's own words. */
  const [handoffNote, setHandoffNote] = useState<string | null>(null);
  /**
   * The same, one row up: what happened to the *notebook*.
   *
   * Kept apart from `handoffNote` because they answer different questions and
   * one would overwrite the other at the worst moment — "that cell was refused
   * as a notebook this peer has not seen" and "the notebook was shared" belong
   * on screen together, since the second is the answer to the first.
   */
  const [notebookShareNote, setNotebookShareNote] = useState<string | null>(null);
  /**
   * What the last Attest press did, in the words of whichever layer refused it.
   *
   * Its own slot for `notebookShareNote`'s reason, one step further: sharing a
   * notebook and attesting to one are the two halves of getting a room onto the
   * same run, and "nobody has a confirmed channel yet" answered about one of
   * them is the wrong answer about the other.
   */
  const [attestNote, setAttestNote] = useState<string | null>(null);
  /** Gap click sets pending insert; next shelf append / drop uses it. */
  const [pendingInsert, setPendingInsert] = useState<ChipPath | null>(null);
  /**
   * Tee branch armed from a selector ghost (design turn 47). Client-side only:
   * `- :public |` with no step is not valid recipe text, so the branch
   * materializes together with its first inserted step.
   */
  const [armedBranch, setArmedBranch] = useState<
    (ArmedBranch & { cell: number }) | null
  >(null);
  /** Inserting a container auto-focuses its own first body gap (turn 46b). */
  const focusNestAfterInsert = (cell: number, name: string, stem: number) => {
    if (name === "tee" || name === "foreach" || name === "scatter") {
      setPendingInsert({ cell, stem, branch: null, body: 0 });
    }
  };
  /**
   * §32d — clipboard.read's permission moment. Asked every run and never
   * remembered (clipboard contents change silently between runs). The Allow
   * handler reads the clipboard itself so the read happens inside the click's
   * transient activation.
   */
  /**
   * The pending boundary-op approval (§27). Inline at the requesting cell,
   * never a modal — the context is the point.
   */
  const [approvalAsk, setApprovalAsk] = useState<{
    request: ApprovalRequest;
    resolve: (d: ApprovalDecision) => void;
  } | null>(null);
  const [clipboardAsk, setClipboardAsk] = useState<{
    resolve: (text: string | null) => void;
  } | null>(null);
  /** §32d — clipboard.write toast ("ok" weight, 2s auto-dismiss). */
  const [clipboardWrote, setClipboardWrote] = useState<number | null>(null);
  /**
   * `file.save`'s confirmation, at the same weight and for the same reason:
   * the user just drove a save dialog, so a modal would be telling them what
   * they already know. `file.read` has no counterpart — the picker itself is
   * both the permission and the receipt.
   */
  const [fileSaved, setFileSaved] = useState<{ name: string; bytes: number } | null>(
    null
  );
  useEffect(() => {
    setApprovalGate(
      (request) =>
        new Promise<ApprovalDecision>((resolve) => {
          setApprovalAsk({ request, resolve });
        })
    );
    setClipboardReadGate(
      () =>
        new Promise<string | null>((resolve) => {
          setClipboardAsk({ resolve });
        })
    );
    const onWrote = (ev: Event) => {
      setClipboardWrote((ev as CustomEvent<{ chars: number }>).detail?.chars ?? 0);
    };
    const onSaved = (ev: Event) => {
      const d = (ev as CustomEvent<{ name: string; bytes: number }>).detail;
      setFileSaved({ name: d?.name ?? "file", bytes: d?.bytes ?? 0 });
    };
    window.addEventListener("basilisk:clipboard-wrote", onWrote);
    window.addEventListener("basilisk:file-saved", onSaved);
    return () => {
      setClipboardReadGate(null);
      setApprovalGate(null);
      window.removeEventListener("basilisk:clipboard-wrote", onWrote);
      window.removeEventListener("basilisk:file-saved", onSaved);
    };
  }, []);
  useEffect(() => {
    if (clipboardWrote == null) return;
    const t = window.setTimeout(() => setClipboardWrote(null), 2000);
    return () => window.clearTimeout(t);
  }, [clipboardWrote]);
  useEffect(() => {
    if (!fileSaved) return;
    const t = window.setTimeout(() => setFileSaved(null), 2500);
    return () => window.clearTimeout(t);
  }, [fileSaved]);
  const [cellViews, setCellViews] = useState<Record<number, CellView>>({});
  const [rawDrafts, setRawDrafts] = useState<Record<number, string>>({});
  /**
   * Warnings the user has read and cleared, keyed by cell + message.
   *
   * Session state on purpose: it is not part of the notebook, so saving and
   * reopening a recipe — or handing it to someone else — brings its advice
   * back. Muting a security notice should not be a property of the file.
   */
  const [dismissedWarnings, setDismissedWarnings] = useState<Set<string>>(
    () => new Set()
  );
  const [presetMenuOpen, setPresetMenuOpen] = useState(false);
  /**
   * Which part of the session sheet the last press asked for, or null.
   *
   * Set by the Templates gallery's room entries and by nothing else: the
   * Share tier, the Connections tab and an invite link open the whole window
   * and have no section to name. Cleared when the sheet closes so a later
   * door does not inherit an earlier door's destination.
   */
  const [sessionFocus, setSessionFocus] = useState<
    "ceremony" | "recovery" | null
  >(null);
  const [trayOpen, setTrayOpen] = useState(true);
  const [shareOpen, setShareOpen] = useState(false);
  const [trayTab, setTrayTab] = useState<
    "keys" | "slots" | "connections" | "outputs" | "activity" | "inputs" | "params"
  >("keys");
  /**
   * One-shot undo — set right before an edit that removes more than the click
   * named, cleared once used or superseded. Load-a-template was the first such
   * edit; deleting a tee's last branch, which takes the emptied tee with it,
   * is the second, and `note` is how it says which one happened.
   */
  const [undoSnapshot, setUndoSnapshot] = useState<{
    title: string;
    chains: RecipeChain[];
    note?: string;
  } | null>(null);
  useEffect(() => {
    if (!undoSnapshot) return;
    const t = window.setTimeout(() => setUndoSnapshot(null), 6000);
    return () => window.clearTimeout(t);
  }, [undoSnapshot]);
  useEffect(() => {
    if (nb.quorumState.phase === "offering") setQuorumCell(nb.runningCell);
    else if (nb.quorumState.phase === "idle") setQuorumCell(null);
  }, [nb.quorumState.phase, nb.runningCell]);
  const [opsWidth, setOpsWidth] = useState(() => {
    const w = loadToolkitLayout().opsW;
    return typeof w === "number" && w >= OPS_PANE_LIMITS.min ? w : OPS_PANE_LIMITS.def;
  });
  const [opsCollapsed, setOpsCollapsed] = useState(
    () => loadToolkitLayout().opsCollapsed === true
  );
  const [opsDragging, setOpsDragging] = useState(false);
  // Publish the panel width as a custom property instead of a style prop; the
  // stylesheet reads `--ops-width` (see lib/css-vars for why this route).
  useEffect(() => {
    setCssVar("--ops-width", opsWidth, "px");
  }, [opsWidth]);
  /**
   * Bumped whenever a mark this browser keeps about a key changes.
   *
   * It was `trustTick` and covered `setTrust` alone. Device labels are the same
   * shape of thing — written to localStorage by a helper with no change event —
   * and a second counter for them would be two answers to "has anything about
   * these keys changed". The name says both, because a reader who sees a device
   * label re-render on a trust mark should be able to find out why here.
   */
  const [localMarkTick, setLocalMarkTick] = useState(0);
  const applyTrust = (fpr: string, level: TrustLevel) => {
    setTrust(fpr, level);
    setLocalMarkTick((n) => n + 1);
  };
  const opsWorkspaceRef = useRef<HTMLDivElement | null>(null);

  const toggleOpsCollapsed = () => {
    setOpsCollapsed((prev) => {
      const next = !prev;
      saveToolkitLayout({ opsCollapsed: next });
      return next;
    });
  };

  const onOpsSplitterPointerDown = (e: ReactPointerEvent<HTMLDivElement>) => {
    if (opsCollapsed) return;
    e.preventDefault();
    const target = e.currentTarget;
    target.setPointerCapture(e.pointerId);
    setOpsDragging(true);
    let width = opsWidth;
    const onMove = (ev: PointerEvent) => {
      const rect = opsWorkspaceRef.current?.getBoundingClientRect();
      if (!rect) return;
      width = clampOpsWidth(ev.clientX - rect.left);
      setOpsWidth(width);
    };
    const onUp = () => {
      setOpsDragging(false);
      target.removeEventListener("pointermove", onMove);
      target.removeEventListener("pointerup", onUp);
      saveToolkitLayout({ opsW: width });
    };
    target.addEventListener("pointermove", onMove);
    target.addEventListener("pointerup", onUp);
  };

  /**
   * Reset, reached from the pointer and from the keyboard.
   *
   * `opsW: null` and not `opsW: OPS_PANE_LIMITS.def`, which is the part worth
   * naming: reset means "I have no preference", so the next load falls back
   * to whatever the default is *then*. Writing the current default would
   * freeze today's 220 into storage and quietly outlive a change to it.
   *
   * The double-click had this to itself. Now that Enter means the same thing
   * it is a function, because a second copy of two lines is a second answer
   * to what reset means, and the null is exactly the half a copy loses.
   */
  const resetOpsWidth = () => {
    setOpsWidth(OPS_PANE_LIMITS.def);
    saveToolkitLayout({ opsW: null });
  };

  /**
   * The keyboard's half of the splitter.
   *
   * `role="separator"` with a tab stop is a window splitter, and the role was
   * already on the element claiming a control that could not be focused, let
   * alone operated. The panel is drawn to the *left* of this handle, so Right
   * widens and Left narrows — the edge goes where the key points, which is
   * the only mapping that survives someone not having read anything.
   *
   * Every branch that acts calls `preventDefault`: arrows and Home/End all
   * scroll the nearest scrollable ancestor by default, and the workspace has
   * several, so without it a resize would also throw the notebook around.
   *
   * There is no `opsCollapsed` guard here, unlike the pointer path. This
   * element is not rendered while the panel is collapsed, so a guard would be
   * a branch that cannot be taken — the pointer handler's is already
   * unreachable for the same reason and is left alone rather than grown a
   * twin.
   */
  const onOpsSplitterKeyDown = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Enter") {
      e.preventDefault();
      resetOpsWidth();
      return;
    }
    const step = e.shiftKey ? OPS_PANE_STEP * 4 : OPS_PANE_STEP;
    let next: number;
    if (e.key === "ArrowRight") next = opsWidth + step;
    else if (e.key === "ArrowLeft") next = opsWidth - step;
    else if (e.key === "Home") next = OPS_PANE_LIMITS.min;
    else if (e.key === "End") next = OPS_PANE_LIMITS.max;
    else return;
    e.preventDefault();
    const width = clampOpsWidth(next);
    setOpsWidth(width);
    // Persisted per press rather than on some end-of-gesture, because a key
    // press has no end: there is no `pointerup` to hang the write on, and the
    // width after one press is as much a preference as the width after ten.
    saveToolkitLayout({ opsW: width });
  };

  const [now, setNow] = useState(() => Date.now());
  /**
   * Live session grants (§27c). Re-read on the same one-second tick that
   * drives the unlock countdown, so the use counter ticks up while a
   * grant-covered run is using the key — being able to *watch* it is what
   * makes the grant something other than a rubber stamp.
   */
  /**
   * Where private key material travels in this notebook (§26c). Computed
   * once over every cell rather than per-cell, because the trace crosses
   * cells: a key exported in cell 1 is still a key in cell 4.
   */
  const exposedSteps = useMemo(
    () => exposureTrace(nb.chains).steps,
    [nb.chains]
  );
  /**
   * Where every cell runs, and why — computed from the notebook's own text.
   *
   * **`nb.source`, never a re-serialization of `nb.chains`.** Serializing the
   * chains drops blank cells, so every cell after the first blank shifts by
   * one, and the plan's indices then disagree with the manifest's and with the
   * editor's. That is the defect the cell-index work closed, and it comes back
   * the moment a caller rebuilds the text instead of using it.
   *
   * The roster and `me` are `handoffWho`'s, which is the same answer the run
   * and every handoff step uses. This panel used to build its own roster from
   * the peer rows and pass no `me` at all, and both halves of that were wrong
   * in the same direction: the rows are the audience *minus this browser*, so
   * a cell the author placed on their own label was reported as running on
   * "no one in this room", and with no `me` the planner asked `who-am-i`
   * forever. Neither is a fabrication being avoided — the exchange knows the
   * audience and knows which fingerprint this browser is, so the label is a
   * fact — and a panel that answers it differently from the run would be
   * drawing a placement the run does not use.
   *
   * Absent a session there is no audience, so the roster is empty and the plan
   * is `bound: false`: placement is still computed in label space, which is
   * what makes a `@peer` header mean something while it is being written.
   */
  const runPlan = useMemo(() => {
    let plan;
    try {
      const { roster, me } = nb.handoffWho();
      plan = planRun(compileRecipe(nb.source), { roster, me });
    } catch {
      return null;
    }
    // A notebook that does not compile has no plan, and `planRun` says so by
    // *returning* an `uncompiled` refusal rather than throwing — so a `catch`
    // never sees it. Without this, a brand-new empty notebook opened its
    // Connections tab onto a red "this recipe does not compile" complaint
    // about the absence of a recipe nobody had written yet. The editor owns
    // that conversation; this panel only answers where cells run.
    if (plan.refusals.some((r) => r.reason === "uncompiled")) return null;
    return plan;
  }, [nb.source, nb.handoffWho]);

  /**
   * The recipe's share link, or the reason there is not one.
   *
   * `hashForNotebook` already answers both halves; until now the refusal was
   * handed to `setRunStatus` and scrolled away, so a notebook that could not
   * be shared said so once and then looked identical to one that could. The
   * sheet keeps it.
   */
  const recipeLink = useMemo(() => {
    // An empty notebook hashes fine and yields a bare /toolkit URL, so the row
    // would offer Copy link for a link to nothing. Nothing to send is not the
    // guard refusing — it is a not-yet.
    if (!nb.source.trim()) {
      return {
        ok: false as const,
        reason: "There is nothing in this notebook to send yet.",
        tone: "not-yet" as const,
      };
    }
    const result = hashForNotebook(nb.source);
    return result.ok === false
      ? { ok: false as const, reason: result.reason || "This notebook cannot be shared in a link." }
      : { ok: true as const, url: toolkitShareUrl(result.hash) };
  }, [nb.source]);

  /**
   * The run proof, when this notebook has made one.
   *
   * A proof is not "a run happened" — it is a `run.manifest` and a
   * `run.receipt` document sitting in the outputs, so the test is for those
   * documents rather than for a run having occurred. A notebook can be run
   * many times and still have nothing to send, which is why the sheet's
   * unavailable line names the cells that would produce one.
   */
  const runProof = useMemo(() => {
    let manifest = "";
    let receipt = "";
    let signedBy = "";
    for (const tiles of nb.cellOutputs || []) {
      for (const tile of tiles || []) {
        const text = String((tile as { content?: unknown })?.content ?? "");
        if (!text.startsWith("{")) continue;
        try {
          const doc = JSON.parse(text) as Record<string, string>;
          const digest = String(doc.recipeDigest || "").slice(0, 12).toUpperCase();
          if (doc.kind === "basilisk.run-manifest") manifest = digest;
          if (doc.kind === "basilisk.run-receipt") receipt = digest;
          if (doc.signedBy) signedBy = String(doc.signedBy);
        } catch {
          /* not a document — an output that merely starts with a brace */
        }
      }
    }
    return manifest || receipt ? { manifest, receipt, signedBy } : null;
  }, [nb.cellOutputs]);

  /**
   * The share link as a QR, or the reason it cannot be one.
   *
   * Encoding is attempted rather than predicted: the capacity depends on the
   * error-correction level and the character set the encoder picks, so the
   * only honest test is whether it fits. A notebook link may be up to 6,000
   * characters and a QR holds roughly 2,950, so this genuinely fails on real
   * notebooks — and the sentence says by how much, because "too long" without
   * a number gives a reader nothing to act on.
   */
  const recipeQr = useMemo(() => {
    if (!recipeLink.ok) return null;
    try {
      return { ok: true as const, svg: qrSvg(recipeLink.url, { moduleSize: 3, margin: 2 }) };
    } catch {
      return {
        ok: false as const,
        reason:
          `This notebook's link is ${recipeLink.url.length} characters, which is more than a ` +
          "QR code can hold. Save it as a file instead — that crosses the same gap with no limit.",
      };
    }
  }, [recipeLink]);

  /* ─────────────────────── the shared session's surface ─────────────────── */

  const sessionLive = nb.quorumState.phase !== "idle";

  /**
   * The audience the invite is built from.
   *
   * The live exchange's when there is one, the draft's before that. Not the
   * roster: the roster holds who *arrived*, and an invite is for the people who
   * have not — deriving one from the roster would drop the very person it is
   * being copied for.
   */
  const sessionAudience = sessionLive
    ? nb.quorumState.audience || []
    : sessionDraft.audience;

  /**
   * Who is in the room a `@peer` header can address — including before anybody
   * has connected.
   *
   * The room's answer once there is a room, and the *draft's* answer before
   * that, which is the whole of what made composing impossible. `handoffWho` is
   * `roomRoster` over `quorumState.audience`, and that list is empty until Start
   * is pressed, so every surface that asked "which peers exist" was told "none"
   * at exactly the moment somebody was trying to write a ceremony to run later.
   *
   * Both branches are `roomRoster`, so the assignment menu offers what the room
   * will bind, over the same audience `startSession` is about to be handed. That
   * used to be load-bearing in a second way as well — it was what stopped a
   * draft numbering the peers differently from the room — and that half is gone:
   * a peer is the key, so there is no numbering left to agree about.
   *
   * `me` is the key you are joining as, for the same reason it is the live
   * session's `self`: your own key joins the room the moment you choose it, so
   * before there is a session it is the one fingerprint in the draft that is
   * certainly you.
   */
  const composeWho = useMemo(
    () =>
      sessionLive
        ? nb.handoffWho()
        : roomRoster(sessionDraft.audience, [], sessionDraft.keyFingerprint),
    [sessionLive, nb.handoffWho, sessionDraft.audience, sessionDraft.keyFingerprint]
  );

  /**
   * What the last audience change did to the notebook's placements, or "".
   *
   * A live region on the session panel rather than a toast: the sentence is
   * about cells the reader cannot see from there, so it has to survive being
   * read after the press rather than a few seconds of it. Cleared by the next
   * change that has nothing to say, so it never describes an older edit than
   * the one the reader just made.
   */
  const [relabelNote, setRelabelNote] = useState("");

  /**
   * What the last "Write the ceremony" press did, or "".
   *
   * Its own region rather than sharing `relabelNote`, because the two describe
   * opposite events — one is a notebook being replaced on purpose, the other is
   * cells being stranded by a room that moved — and one line holding whichever
   * happened last would make the reader work out which.
   */
  const [ceremonyNote, setCeremonyNote] = useState("");

  /**
   * Change who is in the draft room, and deal with the cells it strands.
   *
   * Every door onto the draft audience goes through here — the picker, the
   * paste box, the fingerprint menu's "add to the room", choosing your own key,
   * and an invite link arriving as `#j=` — because the hazard is a property of
   * the *change*, not of the control that made it.
   *
   * **Adding somebody now does nothing to the notebook, and that is the whole
   * of what changed here.** A peer used to be a position in the sorted
   * audience, so every add renumbered whoever sorted below it and every header
   * had to be rewritten to keep meaning the same person; a peer is the key now,
   * and a key does not move when somebody else arrives. What is left is
   * removal: a cell placed on a key that has left the room will never run, so
   * it is unassigned and the reader is told which cells.
   *
   * The edits go through `setCellPeer`, the same mutator `CellAssign` presses,
   * so the header is written by `serializeChain` exactly as a person writing it
   * by hand would have it. Nothing here edits recipe text.
   */
  const setDraftAudience = useCallback(
    (next: string[]) => {
      const { edits, note } = unassignDeparted(
        nb.chains as RecipeChain[],
        departedPeers(sessionDraft.audience, next)
      );
      setSessionDraft((d) => ({ ...d, audience: next }));
      for (const edit of edits) {
        nb.setCellPeer(edit.cell, edit.peer, edit.publishSlots);
      }
      setRelabelNote(note);
      // The room the last ceremony was written for is not this room any more,
      // so the sentence saying what was written stops being true of what is on
      // screen. Cleared rather than rewritten: what the notebook now holds is a
      // question the notebook answers.
      setCeremonyNote("");
    },
    [sessionDraft.audience, nb.chains, nb.setCellPeer]
  );

  /**
   * The split-key ceremony this draft room implies, recomputed as it is built.
   *
   * **Derived from the audience rather than configured beside it**, which is
   * the whole of the answer to "how can I assign the cell before the notebook
   * is shared". The cell count, the `shares` number, every `@peer` header and
   * every `to=` are functions of who is in the list — so there is nothing to
   * fill in first and no order to get wrong. Adding a person changes the
   * sentences under the room while the reader is looking at them.
   *
   * `roomCeremony` refuses rooms it cannot write for and says which number is
   * the problem; the panel prints those refusals and the button borrows them.
   */
  const draftCeremony = useMemo(
    () =>
      roomCeremony({
        audience: sessionDraft.audience,
        self: sessionDraft.keyFingerprint,
      }),
    [sessionDraft.audience, sessionDraft.keyFingerprint]
  );

  /**
   * Write it into the notebook — bodies through the loader, headers through the
   * mutator.
   *
   * **The two halves go in by different doors on purpose.** `loadRecipeText`
   * takes the pipelines, which is text this generator composed and had to; the
   * `@peer` header on each cell is then written by `setCellPeer`, the same
   * mutator the "Who runs this cell" menu presses and the same one
   * `setDraftAudience` uses when a room shrinks. So no header in this app is
   * ever spelled by hand — `serializeChain` writes all of them — and a change to
   * how a header is spelled cannot leave this path behind.
   *
   * It replaces the notebook rather than appending, and the panel says so above
   * the button. Appending would put a ceremony's `out $set` beside whatever
   * slots were already there and hand the reader a duplicate-slot error for a
   * collision they did not make.
   */
  const writeRoomCeremony = useCallback(() => {
    if (draftCeremony.issues.length || !draftCeremony.cells.length) return;
    const bodies = draftCeremony.cells.map((c) => c.recipe).join("\n\n");
    if (!nb.loadRecipeText(draftCeremony.title, bodies)) {
      // Unreachable unless the generator emits something that does not parse,
      // which is what `room-ceremony.test.js` sweeps every room size for. It
      // says the state and stops; there is no remedy to offer a reader for a
      // recipe they did not write.
      setCeremonyNote(
        "The ceremony that was generated for this room does not compile, so nothing was written. The notebook you had is untouched."
      );
      return;
    }
    draftCeremony.cells.forEach((c, i) => nb.setCellPeer(i, c.peer));
    setCeremonyNote(
      `Wrote ${draftCeremony.cells.length} cells — a ${draftCeremony.threshold}-of-${draftCeremony.shares} split, one share per person. Start the session, then Share this notebook: a cell only crosses to somebody holding the same text.`
    );
  }, [draftCeremony, nb.loadRecipeText, nb.setCellPeer]);

  /**
   * The other agreement — recovery, generated at recovery time.
   *
   * The deal picker above answers "who is in the room"; this one answers the
   * only question a recovery has, **who is contributing**, and reads
   * everything else off the shares themselves: who holds what comes from the
   * deal notebook's own text (`dealHoldings`), and the threshold, count and
   * set id come off this machine's share header (`nb.shareFacts` — four
   * facts, never the words). Dealer-absent is not a mode: the dealer is a
   * checkbox like everyone else, checked or not.
   */
  const [recoveryContributors, setRecoveryContributors] = useState<string[]>([]);
  const [recoveryNote, setRecoveryNote] = useState("");
  const recoveryHoldings = useMemo(
    () => dealHoldings(nb.chains as RecipeChain[]),
    [nb.chains]
  );
  /**
   * Whose recovery this would be: the live session's own key when there is
   * one, the draft's chosen key before that — the same key `SessionStart`'s
   * chooser names, so the two sections cannot disagree about who "you" is.
   */
  const recoverySelf = (
    sessionLive ? String(nb.quorumState.self || "") : sessionDraft.keyFingerprint
  ).toUpperCase();
  const recoveryFacts = useMemo(() => {
    const mine = recoveryHoldings.find((h) => h.fingerprint === recoverySelf);
    if (!mine) return null;
    return nb.shareFacts(mine.slot);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [recoveryHoldings, recoverySelf, nb.shareFacts]);
  const draftRecovery = useMemo(
    () =>
      roomRecovery({
        self: recoverySelf,
        header: recoveryFacts,
        holdings: recoveryHoldings,
        contributors: recoveryContributors,
      }),
    [recoverySelf, recoveryFacts, recoveryHoldings, recoveryContributors]
  );

  /**
   * Write it — bodies through the loader, headers through the mutator,
   * exactly `writeRoomCeremony`'s two doors and for its reason: no header in
   * this app is ever spelled by hand.
   */
  const writeRoomRecovery = useCallback(() => {
    if (draftRecovery.issues.length || !draftRecovery.cells.length) return;
    const bodies = draftRecovery.cells.map((c) => c.recipe).join("\n\n");
    if (!nb.loadRecipeText(draftRecovery.title, bodies)) {
      setRecoveryNote(
        "The recovery that was generated does not compile, so nothing was written. The notebook you had is untouched."
      );
      return;
    }
    draftRecovery.cells.forEach((c, i) => nb.setCellPeer(i, c.peer));
    setRecoveryNote(
      `Wrote ${draftRecovery.cells.length} cells — a ${draftRecovery.threshold}-of-${draftRecovery.total} recovery gathering ${draftRecovery.contributors.length} ${draftRecovery.contributors.length === 1 ? "share" : "shares"}. Share this notebook so the contributors hold the same text, then each runs their own cell.`
    );
  }, [draftRecovery, nb.loadRecipeText, nb.setCellPeer]);

  /**
   * The paste path — one unheaded cell, no picker, no session. Offered from
   * the same section because the reader it serves (a custodian holding words
   * on paper, in a cold browser) is exactly the one the picker cannot
   * describe: no deal notebook, no holdings, no key.
   */
  const writeCustodianRecovery = useCallback(() => {
    const r = custodianRecovery();
    if (!nb.loadRecipeText(r.title, r.cells[0].recipe)) {
      setRecoveryNote(
        "The paste recovery does not compile, so nothing was written. The notebook you had is untouched."
      );
      return;
    }
    setRecoveryNote(
      "Wrote one cell that reads share mnemonics from the Inputs tray — paste each card into its own row there, then press Run. $recovered is a digest of what came back, for checking against the deal's $expected."
    );
  }, [nb.loadRecipeText]);

  /**
   * The same function, reachable from an effect that must not re-subscribe.
   *
   * The `#j=` listener below is mounted once and deliberately so — it is bound
   * to `hashchange` and rebuilding it on every keystroke would put an
   * add/remove pair between each character and the next. It still has to
   * relabel, because an invite is an audience arriving from outside and a
   * notebook may already be placed against a different one.
   */
  const draftAudienceRef = useRef(setDraftAudience);
  useEffect(() => {
    draftAudienceRef.current = setDraftAudience;
  });

  /**
   * The peers offered as one press each, when there is a room to name.
   *
   * `listTrustedRecipientSuggestions` is the same source the recipient binder
   * opens on — keys you marked trusted, resolved from the device key cache —
   * and it is the group the session panel had no access to. Its only
   * suggestions were `nb.vaultKeys`, this browser's own private keys, which is
   * the one group that is mostly *not* the people you are meeting.
   *
   * Loaded here rather than in the widget because `SessionStart` is on the
   * design surface, where the rule is that a widget takes plain props and
   * reads no store.
   */
  const [trustedPeers, setTrustedPeers] = useState<RecipientChoice[]>([]);
  const sessionSheetOpen = nb.sheet === "session";
  useEffect(() => {
    // Not gated on the sheet being open any more, and that is the change: this
    // list is the only source of a *name* for a key, and a peer is drawn as a
    // placard on the notebook itself now — the assignment menu, the cell's
    // header — long before anybody opens the session sheet. Gating it there
    // meant every placard was nameless until the reader had visited a panel
    // that has nothing to do with the cell they are looking at. It still
    // re-reads when the sheet opens and when a trust mark changes, because
    // those are the two moments the answer can differ.
    let live = true;
    void (async () => {
      try {
        const rows = await listTrustedRecipientSuggestions();
        if (live) {
          setTrustedPeers(
            rows.map((hit) => ({
              fingerprint: String(hit.fingerprint || "").toUpperCase(),
              label: primaryUidLabel(hit),
            }))
          );
        }
      } catch {
        // A cache that will not open leaves the search field and the paste box,
        // which are the two paths that do not depend on it.
      }
    })();
    return () => {
      live = false;
    };
  }, [sessionSheetOpen, localMarkTick]);

  /**
   * A name for a key, where this browser has met it.
   *
   * The vault's uids and the trusted marks, which are the two groups a reader
   * has already put a name to — your own keys, and the people you have decided
   * about. Nothing is fetched for this: a key with no name behind it says so
   * rather than sending a lookup because a menu was opened.
   *
   * **It is declared here, above every surface that draws a peer, and that
   * position is load-bearing.** A peer is a fingerprint now, so this map is
   * the *only* thing standing between a reader and forty characters of hex
   * wherever a person is named — the session sheet's room list, the
   * assignment menu, the connections roster. It used to sit below the first
   * two of those, which is a temporal dead zone rather than an ordering
   * preference (see `handoffWho` in `useNotebook` for what that cost last
   * time).
   *
   * No second source: `listTrustedRecipientSuggestions` is the recipient
   * binder's own list and `nb.vaultKeys` is the Keys tray's. A placard that
   * resolved a name some other way would be a second opinion about whose key
   * this is, one component away from the first.
   */
  const peerNames = useMemo(() => {
    const names = new Map<string, string>();
    for (const row of nb.vaultKeys) {
      if (row.uid) names.set(String(row.fingerprint || "").toUpperCase(), row.uid);
    }
    for (const row of trustedPeers) {
      if (row.label) names.set(String(row.fingerprint || "").toUpperCase(), row.label);
    }
    return names;
  }, [nb.vaultKeys, trustedPeers]);



  /**
   * The invite link. `hashForJoin` refuses an audience that names fewer than
   * two keys, because that audience derives no room — so `null` here is the
   * same refusal, not a rendering shortcut.
   */
  const inviteUrl = useMemo(() => {
    const hash = hashForJoin(sessionAudience);
    return hash.ok ? toolkitShareUrl(hash.hash) : null;
  }, [sessionAudience]);

  /**
   * Put the invite **link** on the clipboard, and refuse rather than substitute.
   *
   * Four controls say "Copy invite" and three of them used to copy
   * `quorumState.invite`, which is a status line — `quorum <room> · 3 keys ·
   * <host>` — with no fingerprint in it. This app's own reader settles what
   * that is worth: session-flow's audience reader finds **zero** fingerprints
   * in it and reports the paste as `nothing`, while the link's `#j=` yields
   * the audience and the `join` role. (Named in prose only: the shell must
   * never read a paste itself — `session-flow.test.js` pins that, because two
   * readings are two answers to who a paste added.) So the paste box was never
   * missing; it was
   * being handed the one artifact it is right to reject.
   *
   * A fifth read `inviteUrl || quorumState.invite`, which is worse than either
   * branch alone: it degrades to the unusable string exactly when the link is
   * absent, so the failure arrives as a paste that finds nothing rather than
   * as a refusal that says why.
   *
   * With no link there is nothing to copy — an audience of fewer than two
   * derives no room — and the reason is the sentence `InviteCard` already
   * shows, borrowed rather than reworded so the two cannot drift.
   */
  const copyInvite = useCallback(() => {
    if (!inviteUrl) {
      nb.refuse(NO_LINK_YET);
      return;
    }
    void copyText(inviteUrl);
  }, [inviteUrl, nb]);

  /**
   * Keep the address bar on whatever is worth sending — a live room's invite,
   * otherwise the notebook — so that copying the URL is always a way to share.
   *
   * Every piece of this existed and none of it was wired: `writeToolkitHash`
   * had no caller anywhere in the product, so the two share links this file
   * builds were reachable only through a button somebody had to find first,
   * and the URL of a session you had already started still said `/toolkit`.
   *
   * **`history.replaceState`, never `location.hash =`.** `useNotebook` listens
   * for `hashchange` and *loads* the notebook from whatever it finds, so
   * assigning the hash would feed each keystroke's own link back in as a fresh
   * recipe to compile — a loop through the editor, taking the cursor with it.
   * `replaceState` fires no such event. It also writes no history entry, which
   * is the behaviour you want when the URL is tracking a text field: Back
   * belongs to the reader's navigation, not to their typing.
   *
   * Debounced because a rewrite per keystroke is both wasted work and, in
   * Safari, a rate limit that throws.
   *
   * `hashForToolkitState` decides *what* to write, and can decline — see its
   * refusals for why a notebook holding secret material clears the bar rather
   * than leaving a link that would misdescribe it.
   */
  const audienceKey = sessionAudience.join(",");
  useEffect(() => {
    const timer = window.setTimeout(() => {
      const next = hashForToolkitState({
        recipe: nb.source,
        sessionLive,
        audience: audienceKey ? audienceKey.split(",") : [],
        currentHash: window.location.hash || "",
      });
      if (next.write) writeToolkitHash(next.hash);
    }, 250);
    return () => window.clearTimeout(timer);
  }, [nb.source, sessionLive, audienceKey]);

  /**
   * An invite arriving as a link — the joiner's entry point.
   *
   * Only `#j=`. Every other hash form is `useNotebook.loadFromHash`'s, and this
   * deliberately loads *nothing*: an invite carries no recipe and must not, so
   * all that happens is the sheet opens with the audience filled in and the
   * role set to the one the link implies. The press is still the reader's, and
   * so is the choice of key.
   *
   * **On `hashchange` as well as at mount**, which it was not. Clicking a link
   * to `/toolkit#j=…` while the toolkit is *already open* is a same-document
   * navigation: the URL changes, no document loads, and a mount-only effect
   * never runs again. That is the likeliest way an invite is ever opened — the
   * two of you are talking, they already have Basilisk up, the link arrives —
   * and it did nothing at all. No sheet, no audience, no error.
   *
   * Re-running is safe for the reason the guard is written the way it is: the
   * notebook rewrites its own `#r=` as you type, and every one of those hashes
   * leaves here at the first line.
   */
  useEffect(() => {
    const openFromHash = () => {
      const action = parseToolkitHash(window.location.hash || "");
      if (action.kind !== "join") return;
      setSessionDraft((d) => ({ ...d, role: "join" }));
      draftAudienceRef.current(action.audience);
      nb.setSheet("session");
    };
    openFromHash();
    window.addEventListener("hashchange", openFromHash);
    return () => window.removeEventListener("hashchange", openFromHash);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /**
   * `/toolkit#keys` — the nav's Keys entry, and the vault's front door.
   *
   * The tray defaults to open on the Keys tab, so most of the time this
   * changes nothing. It matters in the two states where it is the difference
   * between a working link and a dead one: a reader who collapsed the tray
   * (`trayOpen` survives nothing, but a click does) or who is sitting on
   * another tab, and — the likelier case — anyone already on `/toolkit` when
   * they press Keys. That is a same-document navigation: the hash changes, no
   * document loads, and nothing would happen at all.
   *
   * Deliberately separate from the `#j=` effect below rather than folded into
   * it. They read the same hash and share nothing else: one opens a panel, the
   * other assembles a room from an audience, and merging them would put a
   * session's rules in front of a tray.
   */
  useEffect(() => {
    const openFromHash = () => {
      const action = parseToolkitHash(window.location.hash || "");
      if (action.kind !== "tray" || action.tray !== "keys") return;
      setTrayOpen(true);
      setTrayTab("keys");
    };
    openFromHash();
    window.addEventListener("hashchange", openFromHash);
    return () => window.removeEventListener("hashchange", openFromHash);
  }, []);

  /**
   * `/toolkit#t=room-deal` — a template link for a notebook that has no text.
   *
   * The third hash a shell answers and `useNotebook` does not, for the reason
   * the other two are here: this opens a *panel*, and panels are the shell's.
   * `loadFromHash` handles every `#t=` that names recipe text and says so when
   * one names nothing at all; the two room entries name a generator instead,
   * and this is the half that reaches it.
   *
   * The entry's own `opens` decides which picker, rather than a branch on the
   * id — `ROOM_TEMPLATES` declares it and `PresetMenu` presses the same field,
   * so a third room entry added tomorrow is reachable by link on the day it is
   * reachable by menu. `preset-company.test.js` derives each entry's
   * declaration from what its generator actually writes, so `opens` is a
   * checked field rather than a trusted one.
   *
   * **On `hashchange` as well as at mount**, which is where this link is
   * likeliest to arrive: somebody with the toolkit already open clicks it, the
   * URL changes, no document loads, and a mount-only effect never runs again.
   * That is the defect `4027326` closed for `#j=`, and it would be the same one
   * here.
   *
   * The live-session case refuses instead of opening, in the menu's own words.
   * `SessionSheet` shows `SessionStart` only while nothing is live, so the
   * deal's picker is not on that sheet during an exchange — opening it anyway
   * would scroll at an element that is not there and leave a reader looking at
   * the session panel wondering what their link did. That is the failure
   * `6575aba` found by browser one layer down, and the answer is to name the
   * state rather than to open something.
   */
  useEffect(() => {
    const openFromHash = () => {
      const action = parseToolkitHash(window.location.hash || "");
      if (action.kind !== "preset") return;
      const room = ROOM_TEMPLATES.find((t) => t.id === action.id);
      if (!room?.opens) return;
      if (room.opens === "ceremony" && sessionLive) {
        nb.refuse(CEREMONY_PICKER_LIVE);
        return;
      }
      setSessionFocus(room.opens);
      nb.setSheet("session");
    };
    openFromHash();
    window.addEventListener("hashchange", openFromHash);
    return () => window.removeEventListener("hashchange", openFromHash);
  }, [sessionLive, nb.refuse, nb.setSheet]);

  // An answer owed to a peer is owed *on a session*. When the exchange ends
  // there is no channel to send it on and no peer to send it to, and a button
  // still offering to would fail with a transport error rather than saying the
  // room is gone.
  //
  // The refusals go with them, and for a plainer reason: `closeQuorumExchange`
  // empties `handoffs`, so every id these are keyed by names a document that no
  // longer exists. Keeping them would be keeping a note about a row nothing can
  // draw.
  useEffect(() => {
    if (!sessionLive) {
      setOwedBack([]);
      setHandoffRefusals({});
    }
  }, [sessionLive]);

  /**
   * The vault rows that could actually open a session.
   *
   * One derivation feeding the picker, its suggestions and the count behind
   * "there is nothing to choose". `nb.vaultKeys` holds all three vault kinds,
   * and the count used to be its length — so an ssh key made "you have not
   * chosen yet" the answer for somebody with nothing to choose, which is the
   * original report one layer down.
   */
  const sessionKeys = useMemo(() => sessionKeyChoices(nb.vaultKeys), [nb.vaultKeys]);

  /**
   * The chosen key, with whatever the agent session observed about its armor.
   *
   * Looked up in **every** row this browser holds, not in the filtered choices.
   * A fingerprint stays in the draft while the list is re-derived every render,
   * so a key that expires with the sheet open drops out of `sessionKeys` and
   * leaves the choice standing — and a chosen key nothing can find is a chosen
   * key nothing can refuse. `startIssues` is what says so; this is what lets it.
   *
   * Re-read on `now` for the reason the tray's rows are: a session entry
   * expires on a clock, so "what is loaded" is a question with a different
   * answer a minute later and no event to announce it.
   */
  const chosenSessionKey = useMemo(() => {
    void now;
    const row = nb.vaultKeys.find((k) => k.fingerprint === sessionDraft.keyFingerprint);
    if (!row) return null;
    const entry = nb.sessionList().find((e) => e.fingerprint === row.fingerprint);
    return { ...row, locked: entry?.locked, loaded: !!entry };
  }, [nb.vaultKeys, sessionDraft.keyFingerprint, nb.sessionList, now]);

  const sessionIssues = useMemo(
    () =>
      startIssues({
        audience: sessionDraft.audience,
        keyFingerprint: sessionDraft.keyFingerprint,
        live: sessionLive,
        keyCount: sessionKeys.length,
        // Everything held, so "no private key in this browser" is never said to
        // somebody looking at three of them. The two numbers differ exactly
        // when the vault holds only keys that cannot open a session.
        heldCount: nb.vaultKeys.length,
        key: chosenSessionKey,
        // The field `agent.unlock` reads. Bound here rather than checked inside
        // the run, so the refusal arrives while the reader is still looking at
        // the choice that caused it.
        passphraseBound: Boolean(nb.gpgPassphrase),
      }),
    [
      sessionDraft,
      sessionLive,
      sessionKeys.length,
      nb.vaultKeys.length,
      chosenSessionKey,
      nb.gpgPassphrase,
    ]
  );

  /**
   * Offers and results waiting on a press.
   *
   * Re-read on `handoffTick`, which `quorum-ops` bumps whenever the queue
   * changes. The list itself is never mirrored into state — `takeHandoff` is
   * what removes a document and it may only succeed once, so a copy React held
   * would be a second answer to "is this still pending".
   */
  const pendingHandoffs = useMemo(() => {
    void nb.handoffTick;
    return nb.pendingHandoffs() as HandoffRow[];
  }, [nb.handoffTick, nb.pendingHandoffs]);

  /**
   * Cells the last run declined, paired with the label that owns them and with
   * what the run already did about it.
   *
   * `skippedCells` carries `waitingOn`; the plan carries what each cell writes.
   * Both come from the same run, so this is a join rather than a re-derivation.
   *
   * `autoOffered` is the third column and the one that changes what the row
   * *means*. A run now hands these over by itself, so a row drawn without it
   * would offer to do a thing that has already been done — the reader would
   * press Hand over on a cell the peer is holding. It lands after `busy` drops
   * (the send is an effect, one render later), which is why it is a dependency
   * of its own rather than something the `busy` flip could have carried.
   *
   * It also carries the run's verdict on cells it deliberately did *not* send —
   * `aside`, for a cell this machine is neither waiting on nor holding up. A
   * cell with no verdict at all is the remaining case and it means what it
   * always meant: no run got as far as deciding, because Stop ended it.
   */
  const placedAway = useMemo(() => {
    void nb.busy;
    const done = new Map(nb.autoOffered.map((o) => [o.cell, o]));
    return (nb.skippedCells() as { cell: number; waitingOn?: string; produces?: string[] }[]).map(
      (s) => {
        const noted = done.get(s.cell);
        return {
          cell: s.cell,
          peer: String(s.waitingOn || ""),
          produces: [...(s.produces || [])],
          offered: noted ? noted.state : ("none" as const),
          why: noted?.state === "refused" ? noted.why : undefined,
        };
      }
    );
  }, [nb.busy, nb.skippedCells, nb.autoOffered]);


  /**
   * The live roster's rows with a name attached, where this browser has one.
   *
   * `projectRosterPeers` is the transport's projection and knows nothing about
   * uids — deliberately, it is a pure function over session state in `lib/`.
   * This is the one place the two are joined, so the connections panel and the
   * live session sheet cannot come to show different names for one key.
   */
  const rosterRows = useMemo(
    () =>
      (nb.quorumState.peers || []).map((row) => {
        const name = peerNames.get(String(row.fingerprint || "").toUpperCase());
        return name ? { ...row, name } : row;
      }),
    [nb.quorumState.peers, peerNames]
  );

  /**
   * Peers a cell can be assigned to, and who each one is.
   *
   * The room *and* the peers this notebook already names, unioned. Only the
   * room would make a header impossible to write before anybody joins, which
   * is backwards — a ceremony is written first and run when the other person
   * is free, and `planRun` reports on an unbound notebook precisely so it can
   * be. Only the notebook would mean a peer who joins can never be given a
   * cell without someone typing their key by hand.
   *
   * **"The room" is `composeWho`, not the live exchange.** It used to be
   * `handoffWho`, whose roster is `quorumState.audience` — empty until Start is
   * pressed — so the sentence above described a behaviour the code did not
   * have: the union was the room's nothing plus whatever peers the reader had
   * already typed by hand, which meant the menu was empty exactly when somebody
   * wanted to compose, and the only way to fill it was to write the grammar the
   * menu exists to spare them. Picking two people in the session sheet now
   * offers both of their keys immediately.
   *
   * It includes *this browser's* own key. Before that it was the peer rows,
   * which are the audience minus self — so the one peer a user could never pick
   * from this list was themselves.
   *
   * Each choice carries who it is, because a reader assigning work is choosing
   * a person and forty characters of hex is not a person. `name` is a uid or a
   * trust mark and nothing derived from the key, for the reason
   * `components/ui/fingerprint.tsx` gives at length; where this browser knows
   * no name the row says so rather than inventing a shortened key to fill the
   * gap. The union's second half is the case that makes `fingerprint` optional:
   * a peer the *notebook* names and the room does not has no key here at all —
   * a `@peer1` left in a notebook written before a peer was a key, or a name
   * somebody typed — and it gets a caption of its own.
   */
  const peerChoices = useMemo(() => {
    const { roster, me } = composeWho;
    const labels = [...new Set([...Object.keys(roster), ...(runPlan?.peers || [])])]
      .filter(Boolean)
      .sort();
    return labels.map((label) => {
      const fingerprint = String(roster[label] || "").toUpperCase();
      return {
        label,
        ...(fingerprint ? { fingerprint } : {}),
        ...(label === me ? { self: true } : {}),
        ...(peerNames.get(fingerprint) ? { name: peerNames.get(fingerprint) } : {}),
      };
    });
  }, [composeWho, runPlan, peerNames]);
  /**
   * The Activity log (§36). Session-scoped and never persisted: it names key
   * ids and destinations, and localStorage is XSS-readable.
   */
  const [activity, setActivity] = useState(() => listActivity());
  useEffect(() => onActivityChange(() => setActivity(listActivity())), []);

  /**
   * A share arriving on somebody else's machine, said out loud.
   *
   * `1dbc950` gave a send an outcome that comes back from the far end —
   * `sent · unconfirmed`, amended in place to `reached <fingerprint>'s session
   * 14:07:23` when the ack lands. The record was complete and the announcement
   * was not: the amend happens seconds after the press, on a row inside a tray
   * tab, so the only way to learn that a key share arrived was to have the
   * Activity tab open and be watching it. That is exactly the shape of fact a
   * reader who cannot see the tray has no other route to.
   *
   * A *transition*, never a state: the map starts empty, so nothing that is
   * already confirmed at mount is announced, and only an id whose receipt was
   * seen unconfirmed and is now `reached` produces a sentence. Everything else
   * the log records — Copy, Download, the send itself — is either already on
   * screen where the person pressed it or is not news, and narrating the whole
   * log would put this region back in the noise business the ticker was kept
   * out of.
   *
   * **`announce`, and not `narrate`, and this was found the hard way.** The
   * first version wrote the run status line too, which is what every other
   * event on this hook does. An ack comes back milliseconds after the send, so
   * the confirmation landed *on top of* the run's own verdict — a person who
   * pressed Run on a `quorum.send` cell watched "Done" appear and be replaced
   * before they could read it, and `placed-journey.e2e.js` caught it in four
   * places. The visible home of this fact is the Activity row `1dbc950`
   * amends; what was missing was a voice for it, not a second place to print
   * it.
   */
  const receiptsSeen = useRef(new Map<number, string>());
  const announce = nb.announce;
  useEffect(() => {
    const was = receiptsSeen.current;
    const now = new Map<number, string>();
    const landed: string[] = [];
    for (const e of activity) {
      const receipt = String(e.receipt || "");
      now.set(e.id, receipt);
      const before = was.get(e.id);
      // `before === undefined` is a row this effect has not seen — the first
      // pass after mount, or an entry born already confirmed — and neither is
      // a delivery that happened while somebody was reading this page.
      if (before !== undefined && before !== receipt && receipt.includes("reached ")) {
        landed.push(`${e.artifact || e.label} — ${receipt}`);
      }
    }
    receiptsSeen.current = now;
    if (landed.length) announce(landed.join(" · "));
  }, [activity, announce]);

  const approvalGrants = useMemo(() => {
    void now;
    void approvalAsk;
    return listApprovalGrants();
  }, [now, approvalAsk]);

  /**
   * Whether this browser can turn a security key into a vault passphrase.
   *
   * Asked once, at mount, because it is a capability of the browser and not of
   * a key — and asked *here* rather than inside `KeyVault`, which takes plain
   * props and reads nothing. Its absence is a sentence on the radio rather than
   * a missing option: a choice that vanishes teaches nobody why.
   */
  const [passkeyAvailable, setPasskeyAvailable] = useState(false);
  useEffect(() => {
    let live = true;
    void isPasskeyPrfAvailable()
      .then((ok) => {
        if (live) setPasskeyAvailable(!!ok);
      })
      .catch(() => {
        /* Treated as unavailable, which is what the radio then says. */
      });
    return () => {
      live = false;
    };
  }, []);

  /**
   * Every key this browser holds, with what it can do for you right now.
   *
   * One derivation feeding the tray's rows, the Keys tab's count, the run bar's
   * chip and the session's chooser — which is the whole point of the vocabulary.
   * The old split was on storage and produced two true statements that
   * contradicted each other; a single list answering "what can this key do" is
   * what makes that impossible rather than merely unlikely.
   *
   * Re-read on `now` for the reason the countdowns are: a session entry expires
   * on a clock, so `held` becomes `loaded` and back again with no event to
   * announce either.
   */
  const keyViews = useMemo<VaultKeyView[]>(() => {
    void localMarkTick;
    const sessions = new Map(nb.sessionList().map((e) => [e.fingerprint, e]));
    return nb.vaultKeys.map((k) => {
      const entry = sessions.get(k.fingerprint);
      const key = { ...k, locked: entry?.locked, loaded: !!entry };
      const readout = keyPowerReadout(key, now);
      return {
        fingerprint: k.fingerprint,
        uid: k.uid,
        email: k.email,
        kind: k.kind,
        protection: k.protection,
        publicLine: k.publicLine,
        power: readout.power,
        powerLabel: readout.label,
        why: readout.why,
        loadedUntil: entry?.expiresAt ?? null,
        trust: getTrust(k.fingerprint)?.level ?? null,
        deviceLabel: getDeviceLabel(k.fingerprint),
        // The same verdict `GpgKeyBinder` and `OpenPgpKeyCard` draw, from the
        // same function — a row that said "expires in 3 days" one place and
        // nothing in another would be two opinions about one key. A session
        // key's `expires` is the agent TTL rather than a validity, so it is
        // left alone here for the reason `keyIsExpired` leaves it alone.
        expiryNote: k.protection === "session" ? null : expiryNote(k.expires, now),
        grants: approvalGrants
          .filter((g) => g.keyId === k.fingerprint)
          .map((g) => ({ use: g.use, uses: g.uses, expiresAt: g.expiresAt })),
      };
    });
  }, [nb.vaultKeys, nb.sessionList, now, localMarkTick, approvalGrants]);

  /**
   * How many keys are open, and when the first of them closes.
   *
   * Both read from `keyViews`, so the tab's number, the chip's word and the
   * row's countdown are one derivation. `sessionEarliestExpiry` is the vault
   * session's own answer to the second question and had no caller anywhere in
   * the app — the value existed, was correct, and reached nothing.
   */
  const keysLoaded = useMemo(
    () => loadedCount(keyViews.map((v) => v.power)),
    [keyViews]
  );
  /**
   * The keys this browser has marked `never`.
   *
   * Read here rather than inside `SessionStart`, which takes plain props and
   * opens no store. Re-read on `localMarkTick` so a mark changed in the Keys
   * tray takes effect in the room being assembled without a reload — the two
   * surfaces are one browser's opinion about one key.
   */
  const neverTrustedKeys = useMemo(() => {
    void localMarkTick;
    return listTrusted()
      .filter((t) => t.level === "never")
      .map((t) => t.fingerprint.toUpperCase());
  }, [localMarkTick]);

  const keysExpireAt = useMemo(() => {
    // Re-read on the same one-second tick the countdowns run on: an expiry is
    // a fact about a clock, and nothing announces it passing.
    void now;
    return sessionEarliestExpiry();
  }, [now]);

  /**
   * The vault acts, wired to `vault-manage.js` and followed by a refresh.
   *
   * Each one resolves with the line the panel prints or throws the sentence it
   * refused with — `KeyVault` never sees a vault, and the refusals are the
   * shared module's rather than a second set written for the tray.
   */
  const generateIntoVault = async (spec: {
    name: string;
    email: string;
    expiryPreset: string;
    protection: "passphrase" | "passkey" | "device";
    passphrase: string;
  }) => {
    const { fingerprint } = await generateVaultKey(spec);
    await nb.refreshVault();
    return `Generated ${formatFingerprint(fingerprint)} and stored it in this browser's vault.`;
  };

  const importIntoVault = async (spec: {
    armored: string;
    passphrase: string;
    target: "vault" | "session";
  }) => {
    const res = await importPrivateKey(spec.armored, {
      passphrase: spec.passphrase,
      target: spec.target,
    });
    await nb.refreshVault();
    return res.target === "session"
      ? `Loaded ${formatFingerprint(res.fingerprint)} for this session only — nothing was written down.`
      : `Imported ${formatFingerprint(res.fingerprint)} into this browser's vault.`;
  };

  const exportFromVault = async (spec: {
    fingerprint: string;
    format: string;
    exportPassphrase: string;
  }) => {
    const meta = (await listKeys()).find((k) => k.fingerprint === spec.fingerprint) || null;
    const { filename } = await exportVaultKey({ ...spec, meta });
    return `Wrote ${filename}.`;
  };

  const deleteFromVault = async (fingerprint: string) => {
    await deleteKey(fingerprint);
    // A deleted key cannot stay unlocked in the agent session: the armor is
    // still in memory and every reader would go on offering it.
    nb.lockKey(fingerprint);
    revokeApprovalGrants(fingerprint);
    await nb.refreshVault();
  };

  const copyPublicLine = (fingerprint: string) => {
    const line = String(
      nb.vaultKeys.find((k) => k.fingerprint === fingerprint)?.publicLine || ""
    );
    if (!line) return;
    void copyText(line);
  };

  /**
   * The EFF wordlist, fetched only when somebody asks for a suggestion — the
   * 7776-word list is ~44 KB gzipped and most notebooks never make a key.
   */
  const suggestPassphrase = async () => {
    const { generateWordPassphrase } = await import("../lib/passphrase-gen.js");
    const { passphrase, bits } = await generateWordPassphrase(6);
    return { passphrase, bits };
  };

  const [workspaces, setWorkspaces] = useState<ToolkitWorkspace[]>(() => listWorkspaces());
  const [workspaceError, setWorkspaceError] = useState("");
  /**
   * What checking each playbook entry's signature said, keyed by entry id.
   *
   * Filled on Load and kept, so the row goes on saying who vouched — or that
   * nobody this browser knows did — rather than flashing a verdict and
   * forgetting it. Absent means "not checked yet", which is a third state and
   * is drawn as one.
   */
  const [playbookState, setPlaybookState] = useState<Record<string, PlaybookOpening>>({});
  const [workspaceOpening, setWorkspaceOpening] = useState("");
  const [inspectedSlot, setInspectedSlot] = useState<string | null>(null);
  const [suiteStatus, setSuiteStatus] = useState<ToolkitSuiteStatus>(() => ({
    openpgp: "unverified",
    webcrypto: "unverified",
    sss: "unverified",
    webauthn: "unverified",
  }));
  const [fipsMode, setFipsModeState] = useState(() => getFipsMode());

  useEffect(() => {
    // The POST/CAST self-test is kicked off once at boot in pages/toolkit.tsx
    // and runs async (it's idempotent — this just awaits the same promise).
    // Read suite status once it settles so the badges reflect the real
    // result rather than the pre-test default. WebAuthn has no CAST
    // coverage, so it's a separate browser-capability probe done eagerly.
    let cancelled = false;
    setSuiteStatus((prev) => ({ ...prev, webauthn: webauthnCapabilityStatus() }));
    void runCryptoSelfTests().finally(() => {
      if (cancelled) return;
      setSuiteStatus({ ...getSuiteStatus(), webauthn: webauthnCapabilityStatus() });
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const onFipsModeChange = (on: boolean) => {
    setFipsMode(on);
    setFipsModeState(on);
  };

  const unverifiedSuiteNames = (Object.keys(suiteStatus) as (keyof ToolkitSuiteStatus)[]).filter(
    (k) => suiteStatus[k] !== "verified"
  );

  // TopBar's single suiteStatus pill, worst-tone-wins (design v2 §21e) — the
  // four per-suite checks are unchanged, only their render site moves here.
  const suiteDetail: SuiteDetail[] = (
    Object.keys(SUITE_BADGE_LABEL) as (keyof ToolkitSuiteStatus)[]
  ).map((suite) => {
    const state = suiteStatus[suite];
    const tone: SuiteTone = state === "verified" ? "ok" : state === "error" ? "error" : "warn";
    const note =
      suite === "webauthn"
        ? state === "verified"
          ? "browser"
          : "unavailable"
        : state === "verified"
          ? "verified"
          : state === "error"
            ? "error"
            : "unverified";
    return { name: SUITE_BADGE_LABEL[suite], tone, note };
  });
  const suitePillStatus = (() => {
    const worst: SuiteTone = suiteDetail.some((s) => s.tone === "error")
      ? "error"
      : suiteDetail.some((s) => s.tone === "warn")
        ? "warn"
        : "ok";
    const issues = suiteDetail.filter((s) => s.tone !== "ok").length;
    const label =
      issues === 0
        ? `${suiteDetail.length} suites ready`
        : `${suiteDetail.length - issues} suites ready · ${issues} issue${issues === 1 ? "" : "s"}`;
    return { label, tone: worst };
  })();

  const profileOverrides = useMemo(
    () => collectProfileOverrides(nb.chains),
    [nb.chains]
  );

  // Runtime secrets (message / ciphertext / shares / envelope / recipients) are
  // notebook-wide state in useNotebook.ts already — aggregate every cell's needs
  // so the Inputs tray tab shows the right fields regardless of which cell is focused.
  const notebookNeeds = useMemo(() => {
    const needs = new Set<string>();
    for (const chain of nb.chains) {
      for (const n of nb.cellInputNeeds(chain)) needs.add(n);
    }
    return needs;
  }, [nb.chains, nb.cellInputNeeds]);

  const notebookRecipSlots = useMemo(
    () => Math.max(0, ...nb.chains.map((c) => nb.cellRecipientSlots(c))),
    [nb.chains, nb.cellRecipientSlots]
  );

  // FIPS banner: prefer the real recipe-based check (suite-gate.js) against
  // the crypto suites it actually knows about (openpgp/webcrypto/sss); fall
  // back to the WebAuthn capability flag since suite-gate doesn't track it.
  const fipsBlockedMessage = useMemo(() => {
    if (!fipsMode) return null;
    const usedGated = suitesUsedByAst(nb.compiled.ast);
    const blockedGated = unverifiedSuitesAmong(
      { openpgp: suiteStatus.openpgp, webcrypto: suiteStatus.webcrypto, sss: suiteStatus.sss },
      usedGated
    );
    if (blockedGated.length) {
      return `FIPS mode: recipe uses unverified ${blockedGated.join(", ")} ops`;
    }
    if (suiteStatus.webauthn !== "verified") {
      return "FIPS mode: blocked — webauthn unverified";
    }
    return null;
  }, [fipsMode, nb.compiled.ast, suiteStatus]);

  // Drives both the Keys tray tab's unlock countdown and each cell's "ran Xs ago" line.
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, []);

  useEffect(() => {
    if (nb.sheet === "workspace") setWorkspaces(listWorkspaces());
  }, [nb.sheet]);

  const lockAllSessions = () => {
    for (const e of nb.sessionList()) nb.lockKey(e.fingerprint);
    // §27c: Lock revokes the approval grants too. A grant that survives
    // "Lock all" would be a standing permission to use keys that are no
    // longer unlocked — the opposite of what the button promises.
    clearApprovalGrants();
  };

  const saveCurrentWorkspace = () => {
    const result = saveWorkspace({ id: newWorkspaceId(), title: nb.title, recipe: nb.source });
    if (!result.ok) {
      setWorkspaceError(result.reason);
      return;
    }
    setWorkspaceError("");
    setWorkspaces(listWorkspaces());
  };

  /**
   * Write the cell that turns this notebook into a signed playbook.
   *
   * A button, not a document. Signing here would mint a signature nobody read
   * a recipe for, which is the rule `attest.js` and `documents.js` both state
   * — so this puts `playbook … | gpg.sign key=$me | out $playbook` in front of
   * the person and they press Run. Downloading the result is the artifact
   * tile's existing `download` action; a second file path here would be a
   * second answer to a question the notebook already answers.
   */
  const writePlaybookCell = () => {
    const title = String(nb.title || "").trim() || "Untitled notebook";
    const signer = nb.vaultKeys[0]?.fingerprint || "";
    const sign = signer ? ` | gpg.sign key=$${signer}` : " | gpg.sign";
    const ok = nb.appendRecipeCell(
      `playbook ${JSON.stringify(title)} purpose=""${sign} | out $playbook`
    );
    if (!ok) {
      setWorkspaceError("Could not write the playbook cell.");
      return;
    }
    setWorkspaceError("");
    nb.setSheet(null);
  };

  const importWorkspaceFile = async (file: File) => {
    const text = await file.text();
    const result = parseWorkspaceFile(text, { filename: file.name });
    if (!result.ok) {
      setWorkspaceError(result.reason);
      return;
    }
    const saved = saveWorkspace({
      id: result.workspace.id,
      title: result.workspace.title,
      recipe: result.workspace.recipe,
      playbook: result.workspace.playbook,
    });
    if (!saved.ok) {
      setWorkspaceError(saved.reason);
      return;
    }
    setWorkspaceError("");
    setWorkspaces(listWorkspaces());
  };

  /**
   * Load a library entry, verifying first when it is a playbook.
   *
   * The recipe a playbook entry loads comes out of the **verified** bytes,
   * never out of the stored preview: `workspace-store.js` is localStorage and
   * localStorage is XSS-writable, so the row you are looking at is a claim and
   * the signature is the only thing that answers it.
   *
   * A failure is shown and the notebook is left alone. It is deliberately not
   * a silent skip — see the sheet's copy: an entry nobody's key verifies is the
   * row a person most needs to see, and one that cannot be opened without the
   * reason on screen is the point of listing it at all.
   */
  const loadWorkspaceEntry = async (ws: ToolkitWorkspace) => {
    if (!ws.playbook) {
      nb.loadRecipeText(ws.title, ws.recipe);
      nb.setSheet(null);
      return;
    }
    setWorkspaceOpening(ws.id);
    try {
      const keys = await listKeys();
      const opened = await openSignedPlaybook(ws.playbook, keys);
      setPlaybookState((prev) => ({ ...prev, [ws.id]: opened }));
      if (!opened.ok || !opened.playbook) return;
      nb.loadRecipeText(ws.title, opened.playbook.recipeSource);
      nb.setSheet(null);
    } finally {
      setWorkspaceOpening("");
    }
  };

  /**
   * Every cell's outputs, flattened for the tray. The notebook shows a cell's
   * results next to that cell; this is the same data gathered in one place, so
   * a result from cell 0 is reachable without scrolling back to it. Cell index
   * is kept so each row can say where it came from.
   */
  const allOutputs = useMemo(
    () =>
      nb.chains.flatMap((_c, i) =>
        (nb.cellOutputs[i] || []).map((a, oi) => ({ cell: i, index: oi, artifact: a }))
      ),
    [nb.chains, nb.cellOutputs]
  );

  const focusedNeeds = nb.cellInputNeeds(nb.chains[nb.focusedCell] || { steps: [] });
  const recipSlots = nb.cellRecipientSlots(nb.chains[nb.focusedCell] || { steps: [] });
  const unmet = nb.unmetForCell(nb.focusedCell);
  const inputNeedsAttention = unmet.some((u) =>
    ["needs input", "needs ciphertext"].includes(u)
  );

  // A nested caret (inside a tee branch / foreach body) fits against the
  // value flowing into that nest, not the cell's overall tip (design v2 §21d).
  const nestedInsert =
    pendingInsert && (pendingInsert.branch != null || pendingInsert.body != null)
      ? pendingInsert
      : null;

  const tipModel = useMemo(() => {
    if (armedBranch) {
      // The armed caret fits against the *projected* member, not the raw nest
      // input — a :public branch on a keypair takes key ops, not keypair ops.
      const nestTip = nestedTipFor(nb.chains, armedBranch.cell, armedBranch.stem);
      const projected = projectTypeForMember(nestTip, armedBranch.selector);
      const tip = projected.ok ? projected.type : nestTip;
      const { next, tipFit } = tipFitFor(tip, {
        terminal: false,
        hasForeach: false,
        nested: true,
      });
      return { tip, next, tipFit };
    }
    if (nestedInsert) {
      const tip = nestedTipFor(nb.chains, nestedInsert.cell, nestedInsert.stem);
      const { next, tipFit } = tipFitFor(tip, {
        terminal: false,
        hasForeach: false,
        nested: true,
      });
      return { tip, next, tipFit };
    }
    const { tip, terminal, hasForeach } = cellPipelineTip(nb.chains, nb.focusedCell);
    const { next, tipFit } = tipFitFor(tip, { terminal, hasForeach });
    return { tip, next, tipFit };
  }, [nb.chains, nb.focusedCell, nestedInsert, armedBranch]);

  // Nested tee/foreach is rejected by the parser, so while the caret is inside
  // a branch or body the two are absent from the shelf entirely — not dimmed
  // (design turn 47, "nested is rejected").
  const shelfOps = useMemo(
    () =>
      nestedInsert || armedBranch
        ? nb.filteredOps.filter(
            (s: { name: string }) =>
              s.name !== "tee" && s.name !== "foreach" && s.name !== "scatter"
          )
        : nb.filteredOps,
    [nb.filteredOps, nestedInsert, armedBranch]
  );

  /**
   * Find the first `rtc.ice` step anywhere in the notebook and open its param
   * panel with `turn=` focused (design v2 §22b's "Configure TURN" action).
   * No-op if the notebook has no rtc.ice step to jump to.
   */
  const openRtcIceTurnParam = () => {
    for (let cell = 0; cell < nb.chains.length; cell++) {
      const steps = nb.chains[cell]?.steps || [];
      for (let stem = 0; stem < steps.length; stem++) {
        const step = steps[stem];
        if (step.name === "rtc.ice") {
          nb.setFocusedCell(cell);
          setCellView(cell, "pipeline");
          setChipEdit({ cell, stem, branch: null, body: null });
          setFocusParamHint({ step: "rtc.ice", param: "turn" });
          return true;
        }
      }
    }
    return false;
  };

  /**
   * **Upgrade recipe**, from either of the two places that offer it.
   *
   * One handler for both so the source view and the error banner cannot come
   * to disagree about what the button does — the same reason the action table
   * exists one layer down. The rewrite, and the status line naming it, are
   * `upgradeCellRecipe`'s; all this owns is the draft.
   *
   * `rawDrafts` is cleared for the cell because the draft it held is now
   * stale — the textarea re-reads `cellRecipeSource`, which is the migrated
   * text round-tripped through the parser, so what is on screen afterwards is
   * what the notebook actually holds.
   */
  const applyRecipeUpgrade = (i: number, text?: string) => {
    if (!nb.upgradeCellRecipe(i, text)) return;
    setRawDrafts((prev) => {
      const next = { ...prev };
      delete next[i];
      return next;
    });
  };

  const cellView = (i: number): CellView => cellViews[i] || "pipeline";
  const setCellView = (i: number, view: CellView) => {
    setCellViews((prev) => ({ ...prev, [i]: view }));
    if (view === "source") {
      setRawDrafts((prev) => ({
        ...prev,
        [i]: prev[i] ?? nb.cellRecipeSource(i),
      }));
    }
  };

  return (
    <TooltipProvider delayDuration={300}>
      <div className="toolkit-shell flex min-h-0 flex-1 flex-col bg-[var(--background)] text-[var(--foreground)]">
        {/* Top bar — notebook identity + suite status + templates/more, matching design v2 §20d/21e */}
        <TopBar
          title={nb.title}
          onRename={(next) => nb.setTitle(next)}
          headingId={NOTEBOOK_TITLE_ID}
          subtitle={`${nb.chains.length} cell${nb.chains.length === 1 ? "" : "s"}`}
          suiteStatus={suitePillStatus}
          suiteDetail={suiteDetail}
        >
            <PresetMenu
              // The gallery, not `nb.presets`: the two room entries are not
              // recipes and `loadPreset` will never be asked for one. They are
              // here because a menu of seventy solo notebooks was the only
              // evidence this product offered about whether a shared one
              // existed, and it said no.
              presets={GALLERY_ENTRIES}
              label="Templates"
              open={presetMenuOpen}
              onOpenChange={setPresetMenuOpen}
              onLoad={(id) => {
                const hasContent = nb.chains.some((c) => (c.steps || []).length > 0);
                setUndoSnapshot(hasContent ? { title: nb.title, chains: nb.chains } : null);
                nb.loadPreset(id);
              }}
              onAppend={(id) => nb.appendPreset(id)}
              onAddBoth={(pairId) => {
                nb.appendPresetPair(pairId);
              }}
              // One road to a shared notebook: the entry opens the picker that
              // knows the roster, and the picker writes the notebook. Nothing
              // is pasted and nothing anybody has open is replaced by pressing
              // this — the generators' own Write buttons still ask for that.
              onOpenRoom={(opens) => {
                setSessionFocus(opens);
                nb.setSheet("session");
              }}
              roomRefusal={{
                // Named because it is true and performable, not to be tidy.
                // Why the picker is not simply mirrored under the live half —
                // and what the remedy costs the person who follows it — is
                // argued on `CEREMONY_PICKER_LIVE` itself.
                //
                // Hoisted to a const because a `#t=room-deal` link reaches the
                // same closed door from the other side, and the two doors must
                // not describe it differently.
                ceremony: sessionLive ? CEREMONY_PICKER_LIVE : undefined,
              }}
              triggerClassName="h-auto rounded-[6px] px-[11px] py-[5px] text-[length:11.5px] font-medium"
            />
            <MenuPopover
              label={<MoreHorizontal className="opacity-80" />}
              align="end"
              triggerClassName="h-auto w-auto rounded-[6px] p-[6px]"
              items={[
                {
                  id: "ceremony",
                  label: "Key ceremony…",
                  onSelect: () => nb.openCeremony(),
                },
                {
                  // Sits beside the ceremony because it is the other end of
                  // the same act: one makes cards, this one answers the
                  // question their holders will have months later.
                  id: "sharecheck",
                  label: "Check a share…",
                  onSelect: () => nb.setSheet("sharecheck"),
                },
                {
                  id: "integrity",
                  label: "Verify this deployment…",
                  onSelect: () => nb.setSheet("integrity"),
                },
                {
                  id: "workspace",
                  label: "Workspace library",
                  onSelect: () => nb.setSheet("workspace"),
                  separatorBefore: true,
                },
                {
                  id: "toolkit-prefs",
                  label: "Toolkit preferences",
                  onSelect: () => nb.setSheet("prefs"),
                },
                {
                  id: "copy",
                  label: "Copy recipe",
                  onSelect: () => void nb.copyRecipe(),
                  separatorBefore: true,
                },
                { id: "reset", label: "Reset notebook", onSelect: () => nb.resetNotebook() },
                {
                  id: "prefs",
                  label: "Preferences",
                  href: "/preferences",
                  separatorBefore: true,
                },
                { id: "published", label: "Published keys", href: "/published" },
              ]}
            />
        </TopBar>

        {/* Run bar — run controls + the one global readiness summary, matching design v2 §18b/19g/21a */}
        <RunBar
          state={
            approvalAsk
              ? "waiting-approval"
              : nb.busy &&
                  (nb.quorumState.phase === "offering" ||
                    nb.quorumState.phase === "waiting")
                ? "waiting-peer"
                : nb.busy
                ? "running"
                : nb.readinessBlocker
                  ? "blocked"
                  : "idle"
          }
          blocker={nb.readinessBlocker}
          // The compiler's own message, not `!validation.ok`. Every one of
          // these already names a cell and a step — "Unknown step \"foo\"",
          // "tee/foreach list body is empty" — and the boolean this used to be
          // threw all of it away one prop before it reached the button that
          // needed it. The count is here because a reader who fixes the first
          // and finds Run still dead has learned nothing about the second.
          runRefusal={runRefusal(nb.compiled.validation)}
          focusedCell={nb.focusedCell}
          progress={nb.runProgress}
          waitingCell={nb.runningCell ?? undefined}
          sessionInvite={nb.quorumState.invite}
          onCopyInvite={copyInvite}
          onCancelSession={() => nb.cancelQuorum()}
          // The one row that is never collapsed, carrying the one fact that was
          // two deliberate acts away: a private key is decrypted in this
          // browser, and here is when it goes.
          keyChip={{
            power: strongestPower(keyViews.map((v) => v.power)),
            loaded: keysLoaded,
            expiresAt: keysExpireAt,
          }}
          now={now}
          onOpenKeys={() => {
            setTrayOpen(true);
            setTrayTab("keys");
          }}
          onRunAll={() => void nb.runFrom(0)}
          onRunFrom={(from) => void nb.runFrom(from)}
          onStop={() => nb.stopRun()}
          onBind={() => {
            setTrayOpen(true);
            setTrayTab("inputs");
          }}
        >
          {/* Was Copy link, which is one of the three transfers this notebook
              supports and the only one that had an entry point. The sheet's
              first row is still Copy link, so the fast path costs one more
              click and the other two stop being unreachable. */}
          <Button variant="ghost" onClick={() => setShareOpen(true)}>
            <Link2 />
            Share
          </Button>
          <Button variant="ghost" onClick={() => nb.clearSensitive()}>
            <Eraser />
            Clear session
          </Button>
          <Button variant="outline" onClick={() => setTrayOpen((v) => !v)}>
            Tray <span className="text-[var(--muted-foreground)]">{trayOpen ? "▾" : "▸"}</span>
          </Button>
        </RunBar>

        {nb.runStatus || nb.runError ? (
          <p
            className={cn(
              "border-b border-[var(--border)] px-3.5 py-1.5 text-sm",
              nb.runError ? "text-[var(--error)]" : "text-[var(--muted-foreground)]"
            )}
          >
            {nb.runError || nb.runStatus}
          </p>
        ) : null}

        {/* **The one live region this application has**, and it is deliberately
            not wrapped around the paragraph above.

            That paragraph carries two different kinds of sentence. One is the
            per-cell ticker — `Running cell 3…`, rewritten once per cell — and
            the other is news: the room moved, a rotation dropped a placement,
            a cell was handed over or refused, the run failed and here is why.
            An `aria-live` on the paragraph would announce both, so a twelve
            cell run would interrupt a reader twelve times with a fact they
            cannot act on and bury the one announcement that mattered. The
            hook's `narrate`/`refuse` decide which sentences get here; the
            ticker calls `setRunStatus` and is not among them.

            Empty-but-present from first paint, which is the part that is easy
            to get wrong: a live region has to exist *before* its content
            changes or the first announcement is dropped, so this renders
            unconditionally rather than alongside the paragraph.

            `polite`, never `assertive`: none of this interrupts a person
            mid-word, and the two `aria-live` regions on `SessionStart` are
            inside a sheet that is closed whenever this one is speaking.

            The inner span is re-keyed on `announcement.n` so that the *same*
            sentence twice — two runs both ending "Done", the same refusal
            twice — is a real DOM mutation and therefore a real announcement.
            Without it the second one is byte-identical text and silent.

            `sr-only` and not a hand-rolled clip: the class is in `site.css`
            and the page runs under `style-src 'self'`, which blocks the style
            prop React would otherwise write. */}
        <div
          className="sr-only"
          aria-live="polite"
          aria-atomic="true"
          data-run-announcer
        >
          <span key={nb.announcement.n}>{nb.announcement.text}</span>
        </div>

        {approvalAsk ? (
          <ApprovalBanner
            request={approvalAsk.request}
            onDecide={(decision) => {
              const ask = approvalAsk;
              setApprovalAsk(null);
              ask.resolve(decision);
            }}
          />
        ) : null}
        {clipboardAsk ? (
          <div
            className="flex flex-wrap items-center gap-2 border-b border-l-2 border-[var(--border)] border-l-[var(--warn)] bg-[color-mix(in_srgb,var(--warn)_8%,transparent)] px-3.5 py-1.5"
            data-clipboard-ask
          >
            <span className="text-[length:11.5px] font-semibold text-[var(--foreground)]">
              Read clipboard contents when this cell runs?
            </span>
            <span className="text-[length:10.5px] text-[var(--muted-foreground)]">
              Asked every run — never remembered, since clipboard contents change
              silently between runs.
            </span>
            <div className="ml-auto flex gap-1">
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  clipboardAsk.resolve(null);
                  setClipboardAsk(null);
                }}
              >
                Deny
              </Button>
              <Button
                size="sm"
                variant="secondary"
                onClick={() => {
                  const ask = clipboardAsk;
                  setClipboardAsk(null);
                  // Read inside the click so transient activation is live; a
                  // browser-level denial surfaces as the op's own error.
                  navigator.clipboard
                    .readText()
                    .then((t) => ask.resolve(t))
                    .catch(() => ask.resolve(null));
                }}
              >
                Allow &amp; paste
              </Button>
            </div>
          </div>
        ) : null}
        {clipboardWrote != null ? (
          <p
            className="border-b border-[var(--border)] px-3.5 py-1 text-[length:11px] text-[var(--muted-foreground)]"
            data-clipboard-wrote
          >
            Copied to clipboard · {clipboardWrote} chars
          </p>
        ) : null}
        {fileSaved ? (
          <p
            className="border-b border-[var(--border)] px-3.5 py-1 text-[length:11px] text-[var(--muted-foreground)]"
            data-file-saved
          >
            Saved {fileSaved.name} · {fileSaved.bytes.toLocaleString()} bytes
          </p>
        ) : null}

        {undoSnapshot ? (
          <div className="flex items-center gap-2 border-b border-[var(--border)] bg-[var(--surface-raised)] px-3.5 py-1.5">
            <span className="text-[length:11.5px] text-[var(--muted-foreground)]">
              {undoSnapshot.note || "Replaced the notebook with a template."}
            </span>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                nb.restoreNotebook(undoSnapshot.title, undoSnapshot.chains);
                setUndoSnapshot(null);
              }}
            >
              Undo
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="text-[var(--muted-foreground)]"
              aria-label="Dismiss"
              onClick={() => setUndoSnapshot(null)}
            >
              ✕
            </Button>
          </div>
        ) : null}

        {/*
          `toolkit-workspace` exists for one reason: the layout rules in
          toolkit.css need a handle on this row and on each of its children.
          The columns are sized by three different mechanisms — a CSS variable,
          a Tailwind arbitrary width, and `flex-1` — so there is no way to say
          "stop being columns" from any one of them, and no way to say which
          track a child belongs in either. `display` is deliberately not a
          Tailwind class here: the row is a grid at desktop widths and a column
          flexbox below 1000px, and both of those live in the stylesheet.

          **The notebook comes first, and that is the point.** Stacked on a
          phone the source order is the only order there is, and with the shelf
          first the page opened on 122 operations with its subject below the
          fold. Reordering it here rather than with `order` or
          `column-reverse` is what keeps the document and the picture saying
          the same thing — see the note over `.toolkit-workspace` in
          toolkit.css for how the desktop row still draws it third.
        */}
        <div className="toolkit-workspace min-h-0 flex-1" ref={opsWorkspaceRef}>
          {/*
            Notebook — first in the document, third in the desktop row, and
            the page's `<main>`.

            It was a `<section>` with no name, which is not a landmark at all:
            measured on the shipped bundle the page carried `nav` and one
            `aside` and nothing else, so the subject of the page sat in no
            region, offered no skip target, and could not be jumped to. `main`
            is the tightest honest choice — it is *this* pane, not the shell,
            because a `main` wrapping the top bar and both side panes would
            land a skip link on the chrome again.

            Named by the top bar's `<h1>`, which is the notebook's title and
            already on screen. Pointing at it beats minting an `sr-only`
            heading here: same words, one copy, and a rename moves both.
          */}
          <main
            aria-labelledby={NOTEBOOK_TITLE_ID}
            className="toolkit-notebook flex min-w-0 flex-1 flex-col"
            onDragOver={(e) => {
              if ([...e.dataTransfer.types].includes(STEP_MIME) || [...e.dataTransfer.types].includes("text/plain")) {
                e.preventDefault();
                e.dataTransfer.dropEffect = "copy";
              }
            }}
            onDrop={(e) => {
              const raw =
                e.dataTransfer.getData(STEP_MIME) || e.dataTransfer.getData("text/plain");
              if (!raw) return;
              e.preventDefault();
              const parsed = parseStepMime(raw);
              if (!parsed?.name) return;
              nb.appendOp(
                nb.focusedCell,
                parsed.name,
                parsed.decode ? { decode: true } : undefined
              );
            }}
          >

            <ScrollArea className="flex-1">
              <div className="space-y-3 p-4">
                {nb.chains.map((chain, i) => {
                  const status = nb.cellStatuses[i] || "idle";
                  const needs = nb.unmetForCell(i);
                  const focused = i === nb.focusedCell;
                  // Derived from the cell's own chain rather than asked of the
                  // hook: `unmetForCell` answers "what will the run ask for",
                  // and the whole point of these is that it will ask for
                  // nothing — it will stop.
                  const unbound = focused ? unboundSlotBlockers(chain, i) : [];
                  return (
                    <article
                      key={i}
                      className={cn(
                        "rounded-xl border bg-[var(--surface)]",
                        focused
                          ? "border-[color-mix(in_srgb,var(--brand)_50%,var(--border))] shadow-[0_0_0_1px_color-mix(in_srgb,var(--brand)_28%,transparent)]"
                          : "border-[var(--border)]"
                      )}
                      onClick={() => nb.setFocusedCell(i)}
                    >
                      <header className="flex flex-wrap items-center gap-2 border-b border-[var(--border)] px-3 py-2">
                        <Button size="sm" variant="ghost" onClick={() => nb.setFocusedCell(i)}>
                          [{i}]
                        </Button>
                        <span className="flex items-center gap-1.5">
                          {/* Colour from `[data-cell-status]` in toolkit.css —
                              a closed set, and `style-src 'self'` blocks the
                              style prop in production. */}
                          <span
                            className="cell-status-dot h-[6px] w-[6px] shrink-0 rounded-full"
                            data-cell-status={status}
                            aria-hidden
                          />
                          <span className="text-[length:10.5px] text-[var(--muted-foreground)]">
                            {describeCellStatus(status, nb.cellTimings[i] ?? null, now)}
                          </span>
                        </span>
                        <ModeToggle
                          value={cellView(i)}
                          ariaLabel="Recipe view"
                          className="ml-1"
                          options={[
                            { value: "pipeline", label: "Pipeline", title: "Chips + inline param panel" },
                            { value: "source", label: "Source", title: "Edit the cell recipe as text" },
                          ]}
                          onChange={(view) => {
                            nb.setFocusedCell(i);
                            setCellView(i, view as CellView);
                            if (view !== "pipeline") setChipEdit(null);
                          }}
                        />
                        {/* Beside the view toggle rather than in the ml-auto
                            group: where a cell runs is a property of the cell,
                            not an action on it, and it belongs next to what
                            the cell *is* rather than next to Run and Delete. */}
                        <CellAssign
                          className="ml-1"
                          peer={(chain as { peer?: string }).peer ?? null}
                          // The cell's own `out` labels, at any depth — the
                          // menu cannot offer to publish a slot the cell does
                          // not write, because `publish` stands behind an `out`
                          // and there would be nothing to stand behind.
                          outSlots={outSlotLabels(chain.steps || [])}
                          // Read off the steps, which is where the claim is —
                          // the same call `planRun` and the handoff make, so
                          // the menu cannot show one answer while the plan acts
                          // on another.
                          publishSlots={publishedSlots(chain as RecipeChain)}
                          choices={peerChoices}
                          onAssign={(peer, publishSlots) => {
                            nb.setFocusedCell(i);
                            nb.setCellPeer(i, peer, publishSlots);
                          }}
                        />
                        <div className="ml-auto flex gap-1">
                          {/* Three different states shared one grey button.
                              The readiness bar under this cell already names
                              the missing bindings when there are any, so Run
                              points at it rather than repeating them in the
                              header; the other two have nothing on screen and
                              say it themselves. */}
                          <Button
                            size="sm"
                            disabledReason={
                              !chain.steps?.length
                                ? "This cell is empty — drop an op into it, or type one, and Run has something to do."
                                : needs.length
                                  ? `This cell still needs ${needs.join(", ")} before it can run — the line under it says which value and opens the field.`
                                  : undefined
                            }
                            reasonId={
                              focused && needs.length && chain.steps?.length
                                ? cellReadinessId(i)
                                : undefined
                            }
                            busy={nb.busy}
                            onClick={(e) => {
                              e.stopPropagation();
                              nb.setFocusedCell(i);
                              void nb.runFrom(i);
                            }}
                          >
                            Run
                          </Button>
                          {/* **Secondary, and next to Run rather than under a
                              menu.** `run.js` built `scope` as a capability and
                              said out loud that whether a per-cell control
                              should exist was a product decision it would not
                              make; this is that decision, and it is additive.
                              Run keeps walking to the end of the notebook,
                              because that is what every finger in this product
                              already expects it to do.

                              The label is the whole difference and it is spelt
                              out rather than hinted at: `Only this cell` beside
                              `Run` reads correctly the first time, where an
                              icon or a `Run ¹` would need a tooltip — and a
                              tooltip reaches neither touch nor most screen
                              readers, which is the trap `RunBar` carries a
                              correction for. `aria-label` carries the sentence
                              those three words abbreviate, because "Only this
                              cell" read out of its row does not say what it is
                              only doing.

                              An ordinary button in the header's action group,
                              so Tab reaches it straight after Run.

                              **Absent rather than refused, and only here.**
                              Every reason this control could decline for is a
                              reason Run declines for in the same words —
                              narrowing a scope changes nothing about whether a
                              cell can run at all — and Run is always on screen
                              carrying that sentence. A second button repeating
                              it would put the identical refusal on the page
                              twice and announce it twice, which is the defect
                              `refusal.tsx` grew `reasonId` to prevent. There is
                              no state in which this is missing and its absence
                              is the news: Run is right beside it, saying why
                              nothing here will run. */}
                          {chain.steps?.length && !needs.length ? (
                            <Button
                              size="sm"
                              variant="outline"
                              aria-label={`Run only cell ${i}, without the cells below it`}
                              busy={nb.busy}
                              onClick={(e) => {
                                e.stopPropagation();
                                nb.setFocusedCell(i);
                                void nb.runCellOnly(i);
                              }}
                            >
                              Only this cell
                            </Button>
                          ) : null}
                          <Button
                            size="sm"
                            variant="ghost"
                            className="text-[var(--error)]"
                            // A notebook is never zero cells — deleting the
                            // last one would leave nothing to type into. Say
                            // that rather than leaving an ✕ that does nothing,
                            // which reads as a delete that failed.
                            disabledReason={
                              nb.chains.length <= 1
                                ? "This is the only cell. A notebook always has one — clear its contents instead, or add a cell first and delete this one after."
                                : undefined
                            }
                            aria-label="Delete cell"
                            onClick={(e) => {
                              e.stopPropagation();
                              nb.deleteCell(i);
                            }}
                          >
                            ✕
                          </Button>
                        </div>
                      </header>

                      <div className="space-y-3 p-3">
                        {focused &&
                        (focusedNeeds.includes("text") ||
                          focusedNeeds.includes("gpg") ||
                          focusedNeeds.includes("shares") ||
                          focusedNeeds.includes("envelope") ||
                          recipSlots > 0) ? (
                          <div
                            className={cn(
                              "flex flex-wrap items-center gap-2 rounded-[10px] border-l-[3px] px-3 py-2",
                              inputNeedsAttention ? "cell-runtime-needs" : "cell-runtime-ready"
                            )}
                          >
                            <span className="text-[length:0.65rem] font-bold uppercase tracking-wider text-[var(--brand)]">
                              Reads at run
                            </span>
                            <span className="text-xs text-[var(--muted-foreground)]">
                              {[
                                focusedNeeds.includes("text") && "Inputs → message",
                                focusedNeeds.includes("gpg") && "Inputs → ciphertext",
                                focusedNeeds.includes("shares") && "Inputs → shares",
                                focusedNeeds.includes("envelope") && "Inputs → envelope",
                                recipSlots > 0 && "Inputs → recipients",
                              ]
                                .filter(Boolean)
                                .join(" · ")}
                            </span>
                            <Button
                              size="sm"
                              variant="ghost"
                              className="ml-auto"
                              onClick={(e) => {
                                e.stopPropagation();
                                setTrayOpen(true);
                                setTrayTab("inputs");
                              }}
                            >
                              Edit in tray
                            </Button>
                          </div>
                        ) : null}

                        {focused && (needs.length || unbound.length) ? (
                          <ReadinessBar
                            id={cellReadinessId(i)}
                            blockers={[
                              ...needs
                                .map((n) => ({
                                  need: n,
                                  spec: NEED_BLOCKER[n] || {
                                    priority: 2,
                                    label: n.replace(/^needs\s+/, "") + " is missing",
                                    action: "Open tray",
                                    tray: "inputs" as const,
                                  },
                                }))
                                .map(({ need, spec }) => ({
                                  priority: spec.priority,
                                  id: need,
                                  label: spec.label,
                                  action: spec.action,
                                  onAction: () => {
                                    setTrayOpen(true);
                                    setTrayTab(spec.tray);
                                  },
                                })),
                              // Priority 3 — last in ReadinessBar's own order
                              // (§20e), because everything above it is a value
                              // a tray can hand over, and this one is a line of
                              // recipe the author has to write.
                              ...unbound.map(({ path, step, param }) => ({
                                priority: 3,
                                id: `slot:${path.cell}:${path.stem}:${path.branch ?? ""}:${path.body ?? ""}:${param}`,
                                label: `${step} ${param}= isn't bound to a slot, and nothing will ask for it`,
                                // Names the param, so the button and the field
                                // it opens say the same word.
                                action: `Bind ${param}=`,
                                onAction: () => {
                                  nb.setFocusedCell(path.cell);
                                  setCellView(path.cell, "pipeline");
                                  setChipEdit(path);
                                  setFocusParamHint({ step, param });
                                },
                              })),
                            ].sort((a, b) => a.priority - b.priority)}
                          />
                        ) : null}

                        {quorumCell === i && nb.quorumState.phase !== "idle" ? (
                          <SessionStrip
                            /* `failed` used to be flattened onto `closed`
                               because the strip had nowhere to put it (§33a);
                               it is now its own state with a recovery action. */
                            state={
                              nb.quorumState.phase as
                                | "offering"
                                | "waiting"
                                | "connected"
                                | "closed"
                                | "failed"
                            }
                            room={nb.quorumState.room}
                            invite={nb.quorumState.invite}
                            connected={nb.quorumState.connected}
                            peers={nb.quorumState.peers}
                            onCopyInvite={copyInvite}
                            onCancel={() => nb.cancelQuorum()}
                            onRestartIce={() => void restartLiveIce()}
                          />
                        ) : null}

                        <div className="builder-spine relative space-y-2 pl-1">
                          {/* §33c — belongs to the cell, not to one view of
                              it: an ill-typed pipeline is just as wrong while
                              you are editing the text as while you are looking
                              at chips. Placed above both branches so switching
                              views never hides the complaint. */}
                          <CellTypeErrors
                            className="mb-2"
                            /* Runtime failures land here too, at the same
                               weight and on the same anchor — one surface, so
                               the two channels cannot disagree about which
                               chip a step is (§33c, `cellErrorRows`). */
                            errors={cellErrorRows(
                              nb.cellErrors[i] || [],
                              nb.cellRunErrors[i],
                              chain.steps || []
                            )}
                            steps={chain.steps || []}
                            onFocusStep={(si) => {
                              nb.setFocusedCell(i);
                              setChipEdit({ cell: i, stem: si, branch: null, body: null });
                            }}
                            /* Passed only where the migrator would rewrite
                               something — the banner renders the button when
                               it is passed *and* the message offers it, so a
                               retired name with no rewrite behind it is a
                               sentence and not a dead control. */
                            onUpgradeRecipe={
                              recipeUpgrade(nb.cellRecipeSource(i))
                                ? () => applyRecipeUpgrade(i)
                                : undefined
                            }
                          />
                          {/* Below the errors, and below them in weight: a
                              warning that a run will still succeed does not
                              belong above the reason it will not run. */}
                          <CellWarnings
                            className="mb-2"
                            warnings={(nb.cellWarnings[i] || []).filter(
                              (w) => !dismissedWarnings.has(warningDismissKey(i, w))
                            )}
                            steps={chain.steps || []}
                            onFocusStep={(si) => {
                              nb.setFocusedCell(i);
                              setChipEdit({ cell: i, stem: si, branch: null, body: null });
                            }}
                            onDismiss={(w) =>
                              setDismissedWarnings((prev) => {
                                const next = new Set(prev);
                                next.add(warningDismissKey(i, w));
                                return next;
                              })
                            }
                          />
                          {cellView(i) === "source" ? (
                            <div className="space-y-2">
                              <Textarea
                                className="font-mono text-xs"
                                rows={Math.max(3, (chain.steps || []).length + 2)}
                                value={rawDrafts[i] ?? nb.cellRecipeSource(i)}
                                onChange={(e) =>
                                  setRawDrafts((prev) => ({
                                    ...prev,
                                    [i]: e.target.value,
                                  }))
                                }
                                onBlur={() => {
                                  const text = rawDrafts[i] ?? nb.cellRecipeSource(i);
                                  if (nb.applyCellRecipeText(i, text)) {
                                    setRawDrafts((prev) => {
                                      const next = { ...prev };
                                      delete next[i];
                                      return next;
                                    });
                                  }
                                }}
                                spellCheck={false}
                                placeholder="random 32 | base64 | out $secret"
                              />
                              <div className="flex flex-wrap items-baseline gap-2">
                                <p className="text-xs text-[var(--muted-foreground)]">
                                  Edit the cell recipe as text — applies on blur.
                                </p>
                                {/* The other half of the wiring. A legacy
                                    token in this box is *refused* by
                                    `applyCellRecipeText`, so it never reaches
                                    `chains` and the banner above cannot see
                                    it — the draft is the only copy, which is
                                    why the draft is what gets migrated. */}
                                {recipeUpgrade(rawDrafts[i] ?? nb.cellRecipeSource(i)) ? (
                                  <Button
                                    size="sm"
                                    variant="secondary"
                                    className="h-[22px] px-2 text-[10px]"
                                    data-upgrade-recipe
                                    onClick={() =>
                                      applyRecipeUpgrade(
                                        i,
                                        rawDrafts[i] ?? nb.cellRecipeSource(i)
                                      )
                                    }
                                  >
                                    Upgrade recipe
                                  </Button>
                                ) : null}
                              </div>
                            </div>
                          ) : null}
                          {cellView(i) !== "source" && (chain.steps || []).length === 0 ? (
                            <div className="rounded-lg border border-dashed border-[var(--border)] px-4 py-5 text-center">
                              <p className="mb-3 text-sm text-[var(--muted-foreground)]">
                                Drop an operation from the shelf, or pick a start:
                              </p>
                              <div className="flex flex-wrap justify-center gap-1.5">
                                <Button
                                  size="sm"
                                  variant="secondary"
                                  onClick={() => nb.insertMessaging("encrypt")}
                                >
                                  Encrypt a message
                                </Button>
                                <Button
                                  size="sm"
                                  variant="secondary"
                                  onClick={() => nb.insertMessaging("decrypt")}
                                >
                                  Decrypt
                                </Button>
                                <Button
                                  size="sm"
                                  variant="secondary"
                                  onClick={() => nb.loadPreset("slip39-split")}
                                >
                                  Split a secret
                                </Button>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  onClick={() => setPresetMenuOpen(true)}
                                >
                                  Templates…
                                </Button>
                              </div>
                            </div>
                          ) : null}
                          {cellView(i) !== "source" ? (() => {
                            const list = chain.steps || [];
                            const stems: ChipStemView[] = list.map((s, si) => {
                              const spec = getStep(s.name);
                              // Containers always render their nest region —
                              // an empty tee/foreach shows its own body gap
                              // and ghost affordances instead of masquerading
                              // as a linear op (turn 46).
                              const isNest =
                                s.name === "tee" ||
                                s.name === "foreach" ||
                                s.name === "scatter";
                              return {
                                step: {
                                  name: s.name,
                                  label: spec?.label || s.name,
                                  op: spec || undefined,
                                  keyExposed: exposedSteps.has(s),
                                },
                                hasNest: isNest,
                                nestKind: isNest
                                  ? (s.name as "tee" | "foreach" | "scatter")
                                  : undefined,
                                nestAdd:
                                  s.name === "tee"
                                    ? selectorGhostsFor(
                                        nestedTipFor(nb.chains, i, si)
                                      )
                                    : undefined,
                                branches: (s.branches || []).map((br) => {
                                  const rawSel = String(
                                    br.selector || br.member || ""
                                  ).trim();
                                  // A branch may have no selector at all — the
                                  // grammar makes it optional and every `-`
                                  // line under a `tee` is a branch now, so this
                                  // arm is the common case, not a malformed
                                  // one. It reads "branch" rather than the `:?`
                                  // it used to, which claimed a selector was
                                  // there and unrecognised: nothing is missing.
                                  const sel = !rawSel
                                    ? "branch"
                                    : rawSel.startsWith(":") ||
                                        rawSel.startsWith("[")
                                      ? rawSel
                                      : `:${rawSel}`;
                                  return {
                                    selector: sel,
                                    steps: (br.body || []).map((bs) => {
                                      const bspec = getStep(bs.name);
                                      return {
                                        name: bs.name,
                                        label: bspec?.label || bs.name,
                                        op: bspec || undefined,
                                        keyExposed: exposedSteps.has(bs),
                                      };
                                    }),
                                  };
                                }),
                                body: (s.body || []).map((bs) => {
                                  const bspec = getStep(bs.name);
                                  return {
                                    name: bs.name,
                                    label: bspec?.label || bs.name,
                                    op: bspec || undefined,
                                    keyExposed: exposedSteps.has(bs),
                                  };
                                }),
                              };
                            });
                            const selected =
                              chipEdit?.cell === i ? chipEdit : null;
                            const selectedStep = (() => {
                              if (!selected) return null;
                              const stem = list[selected.stem];
                              if (!stem) return null;
                              if (selected.body != null) {
                                const body =
                                  selected.branch != null
                                    ? stem.branches?.[selected.branch]?.body
                                    : stem.body;
                                return body?.[selected.body] || null;
                              }
                              if (selected.branch != null) return null;
                              return stem;
                            })();
                            const selectedSpec = selectedStep
                              ? getStep(selectedStep.name)
                              : null;
                            return (
                              <>
                                <RecipeChipFlow
                                  cell={i}
                                  stems={stems}
                                  selected={selected}
                                  activeGap={
                                    pendingInsert?.cell === i ? pendingInsert : null
                                  }
                                  armedBranch={
                                    armedBranch?.cell === i ? armedBranch : null
                                  }
                                  onSelect={(path) => {
                                    nb.setFocusedCell(i);
                                    setPendingInsert(null);
                                    setArmedBranch(null);
                                    setChipEdit((prev) =>
                                      prev &&
                                      prev.cell === path.cell &&
                                      prev.stem === path.stem &&
                                      (prev.branch ?? null) ===
                                        (path.branch ?? null) &&
                                      (prev.body ?? null) === (path.body ?? null)
                                        ? null
                                        : path
                                    );
                                  }}
                                  onGap={(path) => {
                                    nb.setFocusedCell(i);
                                    setChipEdit(null);
                                    setArmedBranch(null);
                                    setPendingInsert(path);
                                  }}
                                  onBranchHit={(stem, branch) => {
                                    nb.setFocusedCell(i);
                                    setArmedBranch(null);
                                    setPendingInsert({
                                      cell: i,
                                      stem,
                                      branch,
                                      body: null,
                                    });
                                  }}
                                  onArmBranch={(stem, selector) => {
                                    nb.setFocusedCell(i);
                                    setChipEdit(null);
                                    setPendingInsert(null);
                                    setArmedBranch({ cell: i, stem, selector });
                                  }}
                                  onAddBranchStep={(stem, selector, name, opts) => {
                                    nb.setFocusedCell(i);
                                    setArmedBranch(null);
                                    nb.addBranchWithStep(i, stem, selector, name, opts);
                                    const branchIndex = (
                                      nb.chains[i]?.steps?.[stem]?.branches || []
                                    ).length;
                                    setPendingInsert({
                                      cell: i,
                                      stem,
                                      branch: branchIndex,
                                      body: 1,
                                    });
                                  }}
                                  onPeekInstead={(stem) => {
                                    nb.setFocusedCell(i);
                                    setArmedBranch(null);
                                    setPendingInsert(null);
                                    nb.replaceStep(i, stem, "peek");
                                  }}
                                  onRemoveBranch={(stem, branch) => {
                                    nb.setFocusedCell(i);
                                    setChipEdit(null);
                                    setPendingInsert(null);
                                    setArmedBranch(null);
                                    const before = {
                                      title: nb.title,
                                      chains: nb.chains,
                                    };
                                    // True when that was the tee's last branch
                                    // and the tee went with it. More was
                                    // removed than the × named, so say it and
                                    // put it back within one click.
                                    if (nb.removeBranch(i, stem, branch)) {
                                      setUndoSnapshot({
                                        ...before,
                                        note: "Removed the last branch — the empty tee went with it.",
                                      });
                                    }
                                  }}
                                  onCancelArmed={() => setArmedBranch(null)}
                                  onReorder={(from, to) => {
                                    if (from.cell !== i || to.cell !== i) return;
                                    nb.setFocusedCell(i);
                                    setChipEdit(null);
                                    if (from.body != null || to.body != null) {
                                      if (
                                        from.stem !== to.stem ||
                                        (from.branch ?? null) !== (to.branch ?? null) ||
                                        from.body == null ||
                                        to.body == null
                                      ) {
                                        return;
                                      }
                                      nb.reorderNest(
                                        i,
                                        from.stem,
                                        from.branch ?? null,
                                        from.body,
                                        to.body
                                      );
                                      return;
                                    }
                                    nb.reorderStem(i, from.stem, to.stem);
                                  }}
                                  onDropStep={(path, name, opts) => {
                                    nb.setFocusedCell(i);
                                    setPendingInsert(null);
                                    setArmedBranch(null);
                                    if (path.body != null) {
                                      nb.nestOp(
                                        path.cell,
                                        path.stem,
                                        path.branch ?? null,
                                        name,
                                        { ...opts, at: path.body }
                                      );
                                      return;
                                    }
                                    nb.insertOpAt(path.cell, path.stem, name, opts);
                                    focusNestAfterInsert(i, name, path.stem);
                                    setChipEdit(null);
                                  }}
                                  onRemove={(path) => {
                                    nb.setFocusedCell(i);
                                    if (path.body != null) {
                                      const before = {
                                        title: nb.title,
                                        chains: nb.chains,
                                      };
                                      const gone = nb.removeNestStep(
                                        path.cell,
                                        path.stem,
                                        path.branch ?? null,
                                        path.body
                                      );
                                      const note = cascadeNote(gone);
                                      if (note) setUndoSnapshot({ ...before, note });
                                    } else {
                                      nb.removeStep(path.cell, path.stem);
                                    }
                                    setChipEdit((prev) =>
                                      prev &&
                                      prev.cell === path.cell &&
                                      prev.stem === path.stem &&
                                      (prev.branch ?? null) ===
                                        (path.branch ?? null) &&
                                      (prev.body ?? null) === (path.body ?? null)
                                        ? null
                                        : prev
                                    );
                                  }}
                                />
                                {focused && selectedStep && selectedSpec ? (
                                  <div className="cell-recipe-inline-edit rounded-lg border border-[var(--border)] p-3">
                                    <div className="mb-2 flex flex-wrap items-center gap-2">
                                      <strong>{selectedSpec.label || selectedStep.name}</strong>
                                      <span className="text-xs text-[var(--muted-foreground)]">
                                        {selectedSpec.doc || ""}
                                      </span>
                                      <div className="ml-auto flex gap-1">
                                        <Button
                                          size="sm"
                                          variant="ghost"
                                          className="text-[var(--error)]"
                                          title="Remove step"
                                          aria-label="Remove step"
                                          onClick={() => {
                                            if (!selected) return;
                                            if (selected.body != null) {
                                              const before = {
                                                title: nb.title,
                                                chains: nb.chains,
                                              };
                                              const note = cascadeNote(
                                                nb.removeNestStep(
                                                  selected.cell,
                                                  selected.stem,
                                                  selected.branch ?? null,
                                                  selected.body
                                                )
                                              );
                                              if (note)
                                                setUndoSnapshot({ ...before, note });
                                            } else {
                                              nb.removeStep(selected.cell, selected.stem);
                                            }
                                            setChipEdit(null);
                                          }}
                                        >
                                          ✕
                                        </Button>
                                        <Button
                                          size="sm"
                                          variant="ghost"
                                          onClick={() => setChipEdit(null)}
                                        >
                                          Done
                                        </Button>
                                      </div>
                                    </div>
                                    {(() => {
                                      const isPgpEncryptStep = PGP_ENCRYPT_STEPS.has(
                                        selectedStep.name
                                      );
                                      const handleParamChange = (
                                        name: string,
                                        value: string | number | boolean
                                      ) => {
                                        if (!selected) return;
                                        if (selected.body != null) {
                                          nb.updateNestStepParams(
                                            selected.cell,
                                            selected.stem,
                                            selected.branch ?? null,
                                            selected.body,
                                            name,
                                            value
                                          );
                                        } else {
                                          nb.updateStepParams(
                                            selected.cell,
                                            selected.stem,
                                            name,
                                            value
                                          );
                                        }
                                      };
                                      return (
                                        <>
                                          {/* §39b — `gpg.sign key=` names a key you
                                              hold, so it gets the vault binder rather
                                              than a free-text field you must paste a
                                              fingerprint into. Recipients keep their own
                                              (opposite-direction) resolution path. */}
                                          {selectedStep.name === "gpg.sign" ? (
                                            <GpgKeyBinder
                                              className="mb-3"
                                              label="Sign with"
                                              keys={nb.vaultKeys}
                                              value={String(selectedStep.params?.key || "")}
                                              onChange={(fpr) => handleParamChange("key", fpr)}
                                            />
                                          ) : null}
                                          {/* Recipients, on the step that needs
                                              them. `gpg.encrypt` without a
                                              `to=` cannot run until someone is
                                              chosen, and the chooser used to
                                              live only in the Inputs tray with
                                              nothing here pointing at it — so
                                              the op looked broken rather than
                                              unconfigured. Seeded from the
                                              current selection so this and the
                                              tray copy agree. */}
                                          {selectedStep.name === "gpg.encrypt" &&
                                          notebookRecipSlots > 0 ? (
                                            <div className="mb-3 rounded-[9px] border border-[var(--border)] bg-[var(--surface-raised)] p-2.5">
                                              <p className="mb-1.5 text-[length:11px] font-bold">
                                                Recipients
                                              </p>
                                              <RecipientBinderHost
                                                slots={notebookRecipSlots}
                                                foreach={nb.compiled.validation?.foreachGpg}
                                                initial={nb.boundRecipients}
                                                onChange={nb.setBoundRecipients}
                                              />
                                            </div>
                                          ) : null}
                                          {isPgpEncryptStep ? (
                                            <CryptoProfileControl
                                              className="mb-3"
                                              value={{
                                                profile:
                                                  (selectedStep.params?.profile as
                                                    | "auto"
                                                    | "modern"
                                                    | "compatible"
                                                    | "custom") || "auto",
                                                cipher: String(
                                                  selectedStep.params?.cipher || "aes256"
                                                ),
                                                aead: String(selectedStep.params?.aead || "ocb"),
                                                s2k: String(selectedStep.params?.s2k || "argon2"),
                                                compression: String(
                                                  selectedStep.params?.compression || "off"
                                                ),
                                              }}
                                              onChange={handleParamChange}
                                              sessionProfile={nb.sessionEncryptProfile}
                                              recipients={
                                                selectedStep.name === "gpg.encrypt"
                                                  ? nb.boundRecipients
                                                  : []
                                              }
                                            />
                                          ) : null}
                                          <ParamFieldGroup
                                            params={selectedSpec.params || []}
                                            values={selectedStep.params || {}}
                                            visibilityFor={
                                              isPgpEncryptStep
                                                ? (p) => ({
                                                    show: ![
                                                      "profile",
                                                      "cipher",
                                                      "aead",
                                                      "s2k",
                                                      "compression",
                                                    ].includes(p.name),
                                                  })
                                                : undefined
                                            }
                                            onChange={handleParamChange}
                                            onRequestBind={() => {
                                              setTrayOpen(true);
                                              setTrayTab("slots");
                                            }}
                                            focusParam={
                                              focusParamHint?.step === selectedStep.name
                                                ? focusParamHint.param
                                                : null
                                            }
                                          />
                                          {/* §31d — last row of the editor, a
                                              footer rather than a callout, so
                                              it never competes with the op's
                                              own description. */}
                                          <DocsFooter
                                            op={selectedSpec}
                                            className="mt-2 border-t border-[var(--border)] pt-2"
                                          />
                                        </>
                                      );
                                    })()}
                                  </div>
                                ) : null}
                              </>
                            );
                          })() : null}
                        </div>

                        {/* Whose values this cell's last run used, when any
                            arrived from another machine — finding 7a: the
                            gather is the thing a person is reading when the
                            secret comes back, so the senders are named here,
                            above the outputs they produced. Renders nothing
                            for a purely local run. */}
                        <CellProvenance
                          className="mt-3 px-1"
                          provenance={nb.cellProvenance[i]}
                        />
                        {(nb.cellOutputs[i] || []).length > 0 ? (
                          <OutputList
                            className="mt-3"
                            outputs={(nb.cellOutputs[i] || []).map((a, oi) => {
                              const label =
                                a.label || a.filename || `output ${oi + 1}`;
                              let diagnosticAction:
                                | { label: string; onClick: () => void }
                                | undefined;
                              if (a.role === "diagnostic") {
                                try {
                                  const parsed = JSON.parse(a.content);
                                  if (parsed && parsed.ok === false) {
                                    diagnosticAction = {
                                      label: "Configure TURN",
                                      onClick: openRtcIceTurnParam,
                                    };
                                  }
                                } catch {
                                  /* not our diagnostic JSON — no action */
                                }
                              }
                              return {
                                label,
                                // §33a: one mapping, identical to the tray's.
                                // This pane used to add `publishable ? "key"`
                                // and collapse everything else to "text", so
                                // the same artifact wore two different badges
                                // depending on which pane you looked at. Role
                                // already says "public-key"; the ternary was
                                // re-deriving it and disagreeing.
                                kind: a.role === "diagnostic" ? "diag" : a.role || "text",
                                // The kind registry matches on these (§32b); without them
                                // every tile resolves to the fallback.
                                role: a.role,
                                tags: a.tags,
                                traits: a.traits,
                                // What Download saves the file as, and as what
                                // content type. The engine named the artifact
                                // when it emitted it; nothing downstream gets
                                // to invent a second name for it.
                                filename: a.filename,
                                mime: a.mime,
                                diagnosticAction,
                                sizeBytes: new TextEncoder().encode(a.content).length,
                                sensitive: a.sensitive,
                                revealable: a.revealable,
                                preview: a.sensitive
                                  ? undefined
                                  : oneLinePreview(a.content),
                                // Network artifacts render as manager widgets
                                // instead of a JSON preview (§23a/23b/29d/30d).
                                netType: a.netType,
                                netKind: a.netKind,
                                netData: a.netData,
                                content: a.content,
                                inspectSnapshot: a.inspectSnapshot,
                                // JOSE artifacts render as the JWT reader —
                                // verdict, claims, and a live expiry clock.
                                jose: a.jose,
                                // A decrypt's signature verdict, which the tile
                                // cannot re-derive: the plaintext carries no
                                // trace of the signature that was on the wire.
                                signature: a.signature,
                                onConfigureTurn: openRtcIceTurnParam,
                                onCopy: () => void copyText(a.content),
                                publishedAs: a.publishedAs,
                                directoryUrl: a.directoryUrl,
                                // Whether this artifact *may* be published is
                                // the kind table's answer (§38b — `key.publish`
                                // is declared on `openpgp-public` alone).
                                // What the shell supplies is the route, and
                                // the host the confirmation must name: this
                                // site, never an upstream keyserver, because
                                // no upstream write path exists.
                                onPublish: () => nb.publishArtifact(i, oi),
                                directoryHost: location.host,
                              };
                            })}
                          />
                        ) : null}
                      </div>
                    </article>
                  );
                })}

                <div className="flex justify-center py-2">
                  <Button variant="ghost" size="sm" onClick={() => nb.addCell()}>
                    <Plus />
                    Cell
                  </Button>
                </div>

                <details className="rounded-lg border border-[var(--border)] p-3">
                  <summary className="cursor-pointer text-sm text-[var(--muted-foreground)]">
                    Notebook source (text)
                  </summary>
                  <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap font-mono text-xs">
                    {nb.source}
                  </pre>
                </details>
              </div>
            </ScrollArea>
          </main>

          {opsCollapsed ? (
            <button
              type="button"
              className="ops-rail flex w-[28px] shrink-0 items-center justify-center border-r border-[var(--border)] bg-[color-mix(in_srgb,var(--surface-raised)_88%,var(--surface))] text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
              title="Expand Toolkit panel"
              onClick={toggleOpsCollapsed}
            >
              <span className="[writing-mode:vertical-rl] text-[11px] font-semibold tracking-wide">
                Toolkit
              </span>
            </button>
          ) : (
            // Width rides `--ops-width`, published through a constructed
            // stylesheet (lib/css-vars) — a resizable panel is a continuous
            // value no enumerated rule can cover, and every inline form of it
            // is blocked by `style-src 'self'`.
            <div className="ops-panel relative flex min-h-0">
              <OpsShelf
                className="w-full"
                ops={shelfOps}
                filter={nb.opsFilter}
                onFilter={nb.setOpsFilter}
                castStatus={suiteStatus}
                tipFit={tipModel.tipFit}
                tip={{
                  base: tipModel.tip.base,
                  kind: tipModel.tip.kind,
                  encoding: tipModel.tip.encoding,
                }}
                /* Content only — OpsShelf owns the band's chrome, so the
                   caret announcement and the fit filter's escape hatch share
                   one border and one wash instead of stacking two. */
                caretBanner={
                  <div className="px-2.5 py-2">
                    <div className="text-[length:9.5px] font-bold uppercase tracking-wider text-[var(--caret)]">
                      Caret ·{" "}
                      {armedBranch
                        ? `new ${armedBranch.selector} branch on step ${armedBranch.stem + 1} · cell [${nb.focusedCell}]`
                        : describeCaretPosition(
                            pendingInsert,
                            nb.focusedCell,
                            nb.chains[nb.focusedCell]?.steps || []
                          )}
                    </div>
                    {!pendingInsert ||
                    nestedInsert ||
                    (pendingInsert.body == null &&
                      pendingInsert.stem >=
                        (nb.chains[nb.focusedCell]?.steps || []).length) ? (
                      <div className="mt-0.5 text-[length:10.5px] text-[var(--muted-foreground)]">
                        Showing{" "}
                        <strong className="text-[var(--foreground)]">
                          {tipModel.tipFit.size} op{tipModel.tipFit.size === 1 ? "" : "s"}
                        </strong>{" "}
                        that accept <code className="font-mono">{tipModel.tip.base || "anything"}</code>.
                      </div>
                    ) : null}
                  </div>
                }
                onAppend={(name, opts) => {
                  if (armedBranch && armedBranch.cell === nb.focusedCell) {
                    const ab = armedBranch;
                    setArmedBranch(null);
                    nb.addBranchWithStep(ab.cell, ab.stem, ab.selector, name, opts);
                    // Keep building in the branch that just landed.
                    const branchIndex = (
                      nb.chains[ab.cell]?.steps?.[ab.stem]?.branches || []
                    ).length;
                    setPendingInsert({
                      cell: ab.cell,
                      stem: ab.stem,
                      branch: branchIndex,
                      body: 1,
                    });
                    return;
                  }
                  if (pendingInsert && pendingInsert.cell === nb.focusedCell) {
                    const path = pendingInsert;
                    setPendingInsert(null);
                    if (path.body != null) {
                      nb.nestOp(path.cell, path.stem, path.branch ?? null, name, {
                        ...opts,
                        at: path.body,
                      });
                      // Keep the caret in the same scope, after the new step.
                      setPendingInsert({ ...path, body: path.body + 1 });
                      return;
                    }
                    nb.insertOpAt(path.cell, path.stem, name, opts);
                    focusNestAfterInsert(path.cell, name, path.stem);
                    return;
                  }
                  // The shelf's plain append is one of the few mutations that
                  // genuinely means "wherever the caret is". It says so by
                  // passing `focusedCell` explicitly — read from this render,
                  // not from a setter that has not run yet.
                  const endStem = nb.chains[nb.focusedCell]?.steps?.length ?? 0;
                  nb.appendOp(nb.focusedCell, name, opts);
                  focusNestAfterInsert(nb.focusedCell, name, endStem);
                }}
              />
              <button
                type="button"
                className="absolute right-1 top-1 flex h-5 w-5 items-center justify-center rounded text-[var(--muted-foreground)] hover:bg-[var(--surface-raised)] hover:text-[var(--foreground)]"
                aria-label="Collapse Toolkit panel"
                title="Collapse panel"
                onClick={toggleOpsCollapsed}
              >
                ‹
              </button>
            </div>
          )}
          {!opsCollapsed ? (
            /* A separator with a tab stop is a *window splitter*, and the
               role had been making that claim on its own: no `tabIndex`, no
               `onKeyDown`, so the label announced a resizer that a keyboard
               could not reach, never mind move. The value triplet is the rest
               of the contract — a splitter that can be moved has to be able
               to say where it currently is, and `aria-valuenow` is read off
               the same state the stylesheet's `--ops-width` is published
               from, so the announcement and the picture cannot drift.

               No `aria-controls`: nothing on the panel carries a stable id,
               and minting one whose only reader is this attribute would be a
               relationship asserted rather than one that exists.

               `aria-label` stays a *name*. The two roads through this control
               are in `title`, which — because the label supplies the name —
               is what the accessibility tree uses for the description, so it
               is announced after "Resize Toolkit panel, splitter, 220"
               instead of being crammed into the phrase said on every focus. */
            <div
              role="separator"
              aria-orientation="vertical"
              aria-label="Resize Toolkit panel"
              aria-valuenow={opsWidth}
              aria-valuemin={OPS_PANE_LIMITS.min}
              aria-valuemax={OPS_PANE_LIMITS.max}
              tabIndex={0}
              title="Drag or arrow keys to resize · double-click or Enter to reset"
              className={cn(
                "ops-splitter w-[5px] shrink-0 cursor-col-resize bg-transparent hover:bg-[var(--brand)] focus-visible:bg-[var(--brand)]",
                opsDragging && "bg-[var(--brand)]"
              )}
              onPointerDown={onOpsSplitterPointerDown}
              onDoubleClick={resetOpsWidth}
              onKeyDown={onOpsSplitterKeyDown}
            />
          ) : null}

        {/* Session tray — persistent, not modal. Replaces the old Keyring/Variables/Crypto sheets. */}
        {trayOpen ? (
          <aside
            aria-labelledby={TRAY_TITLE_ID}
            className="toolkit-tray flex w-[328px] shrink-0 flex-col border-l border-[var(--border)] bg-[var(--surface)]"
          >
            {/*
              The one heading here that is not already on screen, and it stays
              that way. The shelf's name was visible and only needed promoting;
              this panel has no title bar, and giving it one would be 328px of
              new furniture on the densest column in the shell to state
              something its own tab strip already says. `sr-only` is what an
              honest heading looks like when the picture is complete without
              it — a name for the landmark and a stop for heading navigation,
              costing no pixels.

              Not `aria-label` on the aside alone: that names the region and
              leaves the outline as empty as it was found.
            */}
            <h2 id={TRAY_TITLE_ID} className="sr-only">
              Session tray
            </h2>
            <div
              role="tablist"
              aria-label="Session tray"
              // `overflow-x-auto` is doing all of the work, and doing two jobs
              // with one word: a flex item whose overflow is not `visible` has
              // an automatic minimum size of *zero*, so declaring the scroll is
              // also what lets this strip shrink below its seven tabs. Before
              // it, the row was 799px wide at a 375px viewport and took the
              // document with it. A `min-w-0` sat here for the same purpose and
              // is gone: measured with it removed, the strip still shrinks to
              // its box and still scrolls (327px of box, 581px of tabs, at
              // 1280), because the overflow value had already zeroed the
              // minimum it was added to zero.
              className="flex items-center gap-1 overflow-x-auto border-b border-[var(--border)] px-2 pt-2"
            >
              {(
                [
                  // §35 — icon + label. Outputs/Inputs deliberately mirror
                  // each other (down-into-tray vs. up-out-of-notebook).
                  // The count is how many keys have armor in the agent session
                  // with a clock running. It was the one tab button carrying no
                  // number, and the number it was missing is the one that says
                  // a private key is open in this browser right now — computed
                  // since `unlockedCount` was written, and reachable only by
                  // opening the tray and selecting this tab.
                  {
                    id: "keys" as const,
                    label: "Keys",
                    count: keysLoaded,
                    Icon: KeyRound,
                  },
                  {
                    id: "slots" as const,
                    label: "Slots",
                    count: nb.slotMetas.length,
                    Icon: LayoutGrid,
                  },
                  // §34 — Connections sits between at-rest material and
                  // at-rest results, in read-to-write order: what you hold →
                  // what is live → what a run just made → what a run still
                  // needs → rarely-touched defaults.
                  {
                    id: "connections" as const,
                    label: "Connections",
                    count:
                      nb.quorumState.phase === "idle" ? 0 : nb.quorumState.connected || 0,
                    Icon: Cable,
                  },
                  {
                    id: "outputs" as const,
                    label: "Outputs",
                    count: allOutputs.length,
                    Icon: ArrowDownToLine,
                  },
                  // §36 — Activity sits after Outputs, continuing the same
                  // read-to-write order: what a run just made, then what was
                  // done with it. Dispositions are not derivations, so they
                  // get their own record rather than being folded into the
                  // recipe or its receipts.
                  {
                    id: "activity" as const,
                    label: "Activity",
                    count: activity.length,
                    Icon: History,
                  },
                  { id: "inputs" as const, label: "Inputs", Icon: ArrowUpFromLine },
                  { id: "params" as const, label: "Params", Icon: SlidersHorizontal },
                ]
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  role="tab"
                  aria-selected={trayTab === tab.id}
                  /* §41c — the label is carried by the button, not the icon,
                     so the accessible name survives if the text is ever
                     collapsed away at narrow widths. The glyph itself is
                     aria-hidden. */
                  aria-label={tab.label}
                  title={tab.label}
                  onClick={() => setTrayTab(tab.id)}
                  className={cn(
                    "inline-flex items-center gap-1 border-b-2 px-2.5 py-1.5 text-[length:11px] font-semibold transition-colors",
                    trayTab === tab.id
                      ? "border-[var(--brand)] text-[var(--foreground)]"
                      : "border-transparent text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
                  )}
                >
                  <tab.Icon size={13} strokeWidth={2} aria-hidden />
                  {tab.label}
                  {tab.count ? (
                    <span className="ml-1 font-mono text-[10px] text-[var(--muted-foreground)]">
                      {tab.count}
                    </span>
                  ) : null}
                </button>
              ))}
              <button
                type="button"
                className="ml-auto h-6 w-6 shrink-0 self-start text-[length:12px] text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
                title="Collapse tray"
                aria-label="Collapse tray"
                onClick={() => setTrayOpen(false)}
              >
                ✕
              </button>
            </div>

            {trayTab === "keys" ? (
              /* The vault itself, not a picker pointing at another page. See
                 KeyVault.tsx for why the Keys tray is where it lives now. */
              <ScrollArea className="flex-1">
                <KeyVault
                  keys={keyViews}
                  now={now}
                  passkeyAvailable={passkeyAvailable}
                  onLockAll={lockAllSessions}
                  onUnlock={(fpr) => void nb.unlockKey(fpr)}
                  onLock={(fpr) => {
                    nb.lockKey(fpr);
                    revokeApprovalGrants(fpr);
                  }}
                  onDelete={deleteFromVault}
                  onGenerate={generateIntoVault}
                  onImport={importIntoVault}
                  onExport={exportFromVault}
                  onTrust={applyTrust}
                  onDeviceLabel={(fpr, label) => {
                    setDeviceLabel(fpr, "", label);
                    setLocalMarkTick((n) => n + 1);
                  }}
                  onCopyPublicLine={copyPublicLine}
                  onInsertCell={(fpr, step) => nb.insertUnlockCell(fpr, step)}
                  onSuggestPassphrase={suggestPassphrase}
                />
              </ScrollArea>
            ) : null}

            {trayTab === "slots" ? (
              <>
                <div className="border-b border-[var(--border)] p-3">
                  <h3 className="text-sm font-bold">Slots</h3>
                  <p className="mt-0.5 text-[length:10.5px] text-[var(--muted-foreground)]">
                    Live <code>$slots</code> from the notebook kernel — metas only, no private
                    armor. Cleared by <strong>Clear session</strong>.
                  </p>
                </div>
                <ScrollArea className="flex-1 px-3">
                  {!nb.slotMetas.length ? (
                    <p className="py-4 text-sm text-[var(--muted-foreground)]">
                      No slots yet — run a cell that ends with <code>out $label</code>.
                    </p>
                  ) : (
                    <ul className="space-y-2 py-3">
                      {nb.slotMetas.map((m) => (
                        <li
                          key={m.label}
                          className="rounded-[9px] border border-[var(--border)] bg-[var(--surface-raised)] px-[10px] py-[10px]"
                        >
                          <div className="flex items-center gap-2">
                            <code className="font-mono text-[length:12.5px] font-bold text-[var(--brand)]">
                              @{m.label}
                            </code>
                            <span className="ml-auto text-[length:10.5px] text-[var(--muted-foreground)]">
                              {m.type}
                            </span>
                            {m.fingerprint ? (
                              <span className="font-mono text-[0.7rem] text-[var(--muted-foreground)]">
                                {nb.formatFingerprint(m.fingerprint)}
                              </span>
                            ) : null}
                          </div>
                          {inspectedSlot === m.label ? (
                            <div className="mt-1 text-xs text-[var(--muted-foreground)]">
                              {m.recipients != null
                                ? `${m.recipients} recipient key${m.recipients === 1 ? "" : "s"}`
                                : m.length != null
                                  ? `${m.length} ${m.type === "text" ? "chars" : "bytes"}`
                                  : m.sensitive
                                    ? "sensitive — value not shown"
                                    : "no further detail"}
                            </div>
                          ) : null}
                          <div className="mt-2 flex flex-wrap gap-1.5">
                            <Button
                              variant="secondary"
                              className="h-auto rounded-md px-[9px] py-[4px] text-[10.5px] font-semibold"
                              /* Tray action with no cell of its own — the
                                 focused cell is what "Insert" means here, and
                                 it is named rather than assumed. */
                              onClick={() => nb.insertSlotRef(nb.focusedCell, m.label)}
                            >
                              Insert
                            </Button>
                            <Button
                              variant="secondary"
                              className="h-auto rounded-md px-[9px] py-[4px] text-[10.5px] font-semibold"
                              onClick={() =>
                                setInspectedSlot((cur) => (cur === m.label ? null : m.label))
                              }
                            >
                              Inspect
                            </Button>
                            <Button
                              variant="secondary"
                              className="ml-auto h-auto rounded-md px-[9px] py-[4px] text-[length:10.5px] font-semibold text-[var(--error)]"
                              onClick={() => nb.clearSlot(m.label)}
                            >
                              Clear
                            </Button>
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}
                  {nb.slotMetas.length ? (
                    <Button
                      variant="outline"
                      className="mb-3 h-auto w-full rounded-[7px] border-dashed py-[6px] text-[length:11.5px] font-semibold text-[var(--muted-foreground)]"
                      onClick={nb.clearAllSlots}
                    >
                      Clear all slots
                    </Button>
                  ) : null}
                </ScrollArea>
              </>
            ) : null}

            {trayTab === "connections" ? (
              <>
                <div className="flex items-start gap-2 border-b border-[var(--border)] p-3">
                  <div className="min-w-0 flex-1">
                    <h3 className="text-sm font-bold">Connections</h3>
                    <p className="mt-0.5 text-[length:10.5px] text-[var(--muted-foreground)]">
                      Whatever is live right now, and the actions that close or repair it.
                      Separate from Outputs, which holds what a run already produced.
                    </p>
                  </div>
                  {/* The second door onto the session window. This tab is where
                      someone comes to ask "is anybody there", and before this
                      the only answer available was a recipe step they had to
                      know the name of. */}
                  <Button
                    size="sm"
                    variant="outline"
                    className="shrink-0"
                    onClick={() => nb.setSheet("session")}
                  >
                    {sessionLive ? "Session" : "Start session"}
                  </Button>
                </div>
                <ScrollArea className="flex-1">
                  {/* The plan sits above the live connections because it is
                      the commitment and they are the observation — what this
                      notebook says it will do, before anything has happened.
                      It renders whether or not a session exists: a `@peer`
                      header means something the moment it is typed, and having
                      to open a connection to find out where a cell would run
                      is how placement stays invisible until it refuses. */}
                  {runPlan ? (
                    <section className="mb-3 flex flex-col gap-1.5">
                      <h4 className="text-[11px] font-bold text-[var(--foreground)]">
                        This notebook
                      </h4>
                      <PlanPanel plan={runPlan} />
                    </section>
                  ) : null}
                  <ConnectionsPanel
                    session={{
                      phase: nb.quorumState.phase,
                      room: nb.quorumState.room,
                      role: nb.quorumState.role,
                      invite: nb.quorumState.invite,
                      connected: nb.quorumState.connected,
                      expected: nb.quorumState.expected,
                      peers: rosterRows,
                    }}
                    links={nb.peerLinks}
                    onCopyInvite={copyInvite}
                    onClose={() => nb.cancelQuorum()}
                    onRestartIce={() => void restartLiveIce()}
                    onCloseLink={(id) => void closeLink(id)}
                    onRestartLink={(id) => void restartLink(id)}
                  />

                  {/* A running (or just-finished) distributed key generation.
                      Beside the connections because it is a property *of* them:
                      a DKG is a full mesh, and the roster below is the same
                      roster above with one more axis on it.

                      No action handlers, deliberately. `DkgPanel` draws "Deal
                      round 1", "Finalize" and "Start a new session" when it is
                      given them, and `dkg.run` is one op that deals every
                      round and finalizes itself — so there is nothing for two
                      of those buttons to call, and the third would be a restart
                      the op layer does not offer. Omitting them renders none:
                      the panel is a progress view here, and the cell's own Run
                      is the start button. Growing `dkg.run` a stepwise sibling
                      to justify three affordances would be designing the op
                      around a drawing. */}
                  {dkgProgress ? (
                    <section className="mt-3 border-t border-[var(--border)] pt-3">
                      <DkgPanel
                        participants={dkgParticipants(
                          nb.quorumState.peers || [],
                          nb.quorumState.self || "",
                          dkgProgress
                        )}
                        started
                        threshold={dkgProgress.threshold || 0}
                        jointPublicKey={
                          dkgProgress.phase === "complete" ? dkgProgress.publicKey || "" : ""
                        }
                      />
                    </section>
                  ) : null}

                  {/* A running (or just-finished) entropy pool, beside the DKG
                      for the same reason: both are the room doing something
                      together, and the roster is the connections roster with
                      one more axis on it.

                      No handlers either, and here the reason is sharper than
                      "the op does everything". A "reveal now" control would be
                      an affordance for the one act the protocol exists to
                      prevent — revealing before every commitment is in hands
                      the last mover the choice committing took away. The cell's
                      Run is the start button; there is nothing else to press. */}
                  {poolProgress ? (
                    <section className="mt-3 border-t border-[var(--border)] pt-3">
                      <PoolPanel
                        phase={poolProgress.phase}
                        round={poolProgress.round}
                        participants={poolParticipants(
                          nb.quorumState.peers || [],
                          nb.quorumState.self || "",
                          poolProgress
                        )}
                        digest={poolProgress.digest}
                        message={poolProgress.message}
                      />
                    </section>
                  ) : null}

                  {/* Above the handoff queue, because it is what the queue
                      presumed. Every check under it compares an arriving offer
                      to the text on *this* machine, and nothing in this product
                      ever put that text here — a joiner refused every offer with
                      a manifest derived from an empty notebook. The queue below
                      only works once both ends are holding the same notebook, so
                      the control that makes that true is drawn first. */}
                  <section className="mt-3 border-t border-[var(--border)] pt-3">
                    <NotebookShare
                      live={sessionLive}
                      hasNotebook={!!nb.source.trim()}
                      proposed={nb.proposedNotebook}
                      // **The outcome of the last press, or a report that is
                      // still resolving — never both, and never appended to.**
                      //
                      // "Shared with 2 peers" was a claim about the far end
                      // made out of a fact about this one:
                      // `_publishDocument` returns how many channels it wrote
                      // to, counting every peer whose `channel.readyState`
                      // reads `open`, and a destroyed browser never fires
                      // `onclose`. That is `dealer-absent-recovery.e2e.js`
                      // finding 6a, and `7ac9f50` answered it by naming the
                      // wire fact as the wire fact and calling it permanently
                      // unconfirmed — because at the time nothing acknowledged
                      // a notebook, and saying "reached 1 of 2" would have been
                      // inventing the acknowledgment.
                      //
                      // Something acknowledges one now: `notebook-ack`, a
                      // document-channel frame the receiving session sends the
                      // instant a verified proposal is handed to the layer that
                      // shows people notebooks. See
                      // `NotebookSession._acknowledgeNotebook` for why it is a
                      // payload kind rather than a tap on `chat` the way
                      // `1dbc950`'s is. So the sentence has a second half that
                      // arrives seconds after the press, and a string frozen at
                      // the press cannot hold it.
                      //
                      // `notebookShareNote` is still the answer to a press —
                      // a refusal, an adopt, a dismiss — and it wins while it
                      // is set, because erasing the answer to something the
                      // reader just did is worse than deferring a report they
                      // are not currently asking about. A *successful* share
                      // clears it, which hands the slot to the live report; the
                      // report is then amended in place as acknowledgments land
                      // and never joined by a second line, since the
                      // acknowledgment moved nothing on this machine and a
                      // second line would say otherwise.
                      note={notebookShareNote || nb.notebookDeliveryNote}
                      onShare={() => {
                        void nb.shareNotebook().then((r) => {
                          setNotebookShareNote(
                            r.ok ? "" : r.why || "That notebook could not be shared."
                          );
                        });
                      }}
                      onAdopt={() => {
                        const r = nb.adoptProposedNotebook();
                        setNotebookShareNote(
                          r.ok
                            ? "Adopted. Both ends now hold the same text, so a cell handed across can be checked against it by digest."
                            : r.why || "That notebook could not be adopted."
                        );
                      }}
                      onDismiss={() => {
                        nb.dismissProposedNotebook();
                        setNotebookShareNote(
                          "Kept yours. Nothing was sent to them — until one of you holds the other's text, a cell handed across is refused as a notebook this peer has not seen."
                        );
                      }}
                    />
                    {/* **The state that had no surface, which is why nobody
                        could act on it.** A person joins a room that is already
                        working on a notebook. They are holding nothing, and they
                        cannot know a notebook exists — there is nothing on their
                        screen to ask about. The dealer cannot see it either:
                        their own notebook is right in front of them, and the
                        share note above is the outcome of a press they made
                        before this peer arrived.

                        The session now replays a shared notebook to peers who
                        verify afterwards, which covers the ordinary case — press
                        Share, then people arrive. What it will not do is deliver
                        text the dealer has since edited away from: that would
                        land silently in an empty notebook and leave both ends
                        believing they had agreed on a notebook only one of them
                        held. So the retention lapses on the first keystroke, and
                        *this line is what stands in for it* — the one remaining
                        path from that state back to a working room.

                        It names the remedy that can actually be performed: the
                        button is directly above this sentence, and pressing it
                        signs the notebook now on screen and sends it. No other
                        wording would be honest, because there is nothing else
                        either person can do.

                        Drawn here rather than passed into `NotebookShare` as a
                        note: `note` is the outcome of the last press, and a
                        standing fact about the room overwriting it would erase
                        the answer to something the reader just did.

                        Rendered only while the notebook is non-empty — a dealer
                        with nothing to share is not withholding anything, and
                        the Share button already refuses that case in its own
                        words. */}
                    {sessionLive &&
                    nb.source.trim() &&
                    nb.peersWithoutNotebook.length > 0 ? (
                      <p
                        className="text-[10.5px] leading-snug text-[var(--muted-foreground)]"
                        data-notebook-unshared
                      >
                        {nb.peersWithoutNotebook.length === 1
                          ? "A peer in this room has not been given this notebook: "
                          : "Peers in this room have not been given this notebook: "}
                        {nb.peersWithoutNotebook.map((fpr, i) => (
                          <span key={fpr}>
                            {i > 0 ? ", " : ""}
                            {/* Whole, never a compact form: there is no name for
                                this key on this browser, and the row telling
                                somebody which peer to act about is the last
                                place to print part of who they are. */}
                            <Fingerprint fpr={fpr} />
                          </span>
                        ))}
                        {". They joined after it was shared, or it has been " +
                          "edited here since — either way nothing has sent them " +
                          "the text on this screen, so every cell handed to them " +
                          "will be refused as a notebook they have not seen. "}
                        {"Share this notebook to send it."}
                      </p>
                    ) : null}
                    {/* **The other end of the sentence above.** `4027326` told
                        the dealer who was holding nothing and stated the gap it
                        left: in the retired case — Share pressed, then edited,
                        then somebody joins — the newcomer learned nothing at
                        join time and found out when an offered cell was
                        refused. This is what they are told instead, and it is
                        driven by the same predicate the dealer's line is, so
                        the two ends of one pair cannot say contradictory
                        things.

                        **It names the state and no more.** What crossed the
                        wire is a kind and a clock: no title, no digest, no cell
                        count. A digest is the leak that matters — a listener
                        with a guess at a ceremony recipe could confirm it
                        against one — and there is nothing in this sentence that
                        could grow into it, because there is nothing on this
                        machine to print.

                        **The remedy named is the one that can be performed, and
                        it is not on this screen.** Only the sender can send a
                        notebook; a "Request it" button here would be a control
                        whose whole effect is to ask somebody to press something
                        on their own machine, and dressing that up as an action
                        would tell the reader they had done something when they
                        had not. So the sentence says to ask them, which is what
                        there is to do. */}
                    {sessionLive && nb.peersHoldingNotebook.length > 0 ? (
                      <p
                        className="text-[10.5px] leading-snug text-[var(--muted-foreground)]"
                        data-notebook-held
                      >
                        {nb.peersHoldingNotebook.length === 1
                          ? "A peer in this room has a notebook and has not sent it here: "
                          : "Peers in this room have a notebook and have not sent it here: "}
                        {nb.peersHoldingNotebook.map((fpr, i) => (
                          <span key={fpr}>
                            {i > 0 ? ", " : ""}
                            {/* Whole, for the line above's reason. */}
                            <Fingerprint fpr={fpr} />
                          </span>
                        ))}
                        {". Nothing here says what is in it — only that it " +
                          "exists. Until they send it, every cell they hand you " +
                          "is refused as a notebook you have not seen. "}
                        {"Ask them to share it: the send is theirs to make."}
                      </p>
                    ) : null}
                  </section>

                  {/* **The room's own cells, as they run.** The two sentences
                      above are about a notebook crossing; this is about what
                      happens once it has. Nothing on this wire said "I ran cell
                      N" before it — `handoff` asks somebody to run one,
                      `result` returns one they were handed, `attestation`
                      signs a finished run — so a peer running their own cells
                      was invisible, and in a ceremony that meant the deal cell
                      running looked exactly like a dealer who had walked away.

                      Only while a session is live, because every row is an
                      announcement from a peer over a channel: with no session
                      there is no room to be running anything, and an empty
                      table drawn beside a Start button would be reporting on a
                      room that does not exist. The widget's own empty state is
                      for the honest case — a live room where nobody has
                      started a cell yet. */}
                  {sessionLive ? (
                    <section className="mt-3 border-t border-[var(--border)] pt-3">
                      <RoomCells rows={nb.peerCellRows} />
                    </section>
                  ) : null}

                  {/* Below the connections, because it is what the connections
                      are *for*. The plan says where a cell runs, the panel
                      above says whether the wire is up, and this is the only
                      surface where a cell actually crosses — until it existed,
                      `offerCell`, `acceptHandoff` and `sendCellResult` were
                      finished and unreachable. */}
                  <section className="mt-3 border-t border-[var(--border)] pt-3">
                    <HandoffQueue
                      live={sessionLive}
                      pending={pendingHandoffs}
                      placedAway={placedAway}
                      owedBack={owedBack}
                      note={handoffNote}
                      refusals={handoffRefusals}
                      onOffer={(cell) => {
                        void nb.offerCell(cell).then((r) => {
                          setHandoffNote(
                            r.ok
                              ? `Cell ${cell} handed to @${r.peer}. Nothing runs there until they accept it.`
                              : r.why || "That cell could not be handed over."
                          );
                        });
                      }}
                      onAccept={(id) => {
                        // The row is read *before* the accept, because an accept
                        // that succeeds removes it and the shell needs the sender
                        // to know who is owed an answer afterwards. A refusal
                        // leaves it, but reading it up here covers both.
                        const row = pendingHandoffs.find((h) => h.id === id);
                        void nb.acceptHandoff(id).then((r) => {
                          if (r.ok && row?.kind === "offer") {
                            const label =
                              (nb.quorumState.peers || []).find(
                                (p) => p.fingerprint === row.from
                              )?.id || row.from;
                            setOwedBack((prev) => [
                              ...prev.filter((o) => o.cell !== row.cell),
                              { cell: row.cell, to: row.from, label: String(label).replace(/^@/, "") },
                            ]);
                          }
                          // Written onto the row that is still there.
                          //
                          // Set on *refusal* specifically, not on any falsy
                          // `ok`: the other way to fail is "no longer pending",
                          // which is about a row that has already gone and has
                          // no row to annotate.
                          //
                          // Dropping it on success is housekeeping and is
                          // described as that rather than as a guard. A handoff
                          // id carries the sender, the cell and the timestamp,
                          // so it names one document and no later one can
                          // collide with it — a kept entry would be unreachable
                          // rather than wrong. What it buys is that the map is
                          // bounded by the queue instead of by how many presses
                          // a session has seen. The property a reader might
                          // expect it to protect — that a reason stays on the
                          // document it was about — is the *keying*, and that
                          // holds whether or not this branch runs.
                          setHandoffRefusals((prev) => {
                            if (r.ok) {
                              if (!(id in prev)) return prev;
                              const { [id]: _gone, ...rest } = prev;
                              return rest;
                            }
                            return "refused" in r && r.refused && r.why
                              ? { ...prev, [id]: r.why }
                              : prev;
                          });
                          setHandoffNote(
                            r.ok
                              ? `Accepted — ${r.registered} value${r.registered === 1 ? "" : "s"} registered. Run the notebook to use them.`
                              : r.why || "That handoff was refused."
                          );
                        });
                      }}
                      /**
                       * Putting a document down, which the queue had no way to do.
                       *
                       * The note names the cell rather than saying "dismissed",
                       * because the reader may have several rows and the one that
                       * left is the fact. It also says the other end was not told:
                       * there is no decline on this wire, so a person who dropped
                       * a row and then wondered why their peer kept waiting would
                       * otherwise have no way to find that out.
                       */
                      onDismiss={(id) => {
                        const r = nb.dismissHandoff(id);
                        setHandoffRefusals((prev) => {
                          if (!(id in prev)) return prev;
                          const { [id]: _gone, ...rest } = prev;
                          return rest;
                        });
                        setHandoffNote(
                          r.ok
                            ? `Dismissed the ${r.kind} for cell ${r.cell}. Nothing was registered and nothing was sent — they have not been told.`
                            : r.why || "That handoff is no longer pending."
                        );
                      }}
                      onSendResult={(cell, label) => {
                        void nb.sendCellResult(cell, label).then((r) => {
                          if (r.ok) setOwedBack((prev) => prev.filter((o) => o.cell !== cell));
                          setHandoffNote(
                            r.ok
                              ? `Cell ${cell} signed and sent back to @${label}.`
                              : r.why || "That result could not be sent."
                          );
                        });
                      }}
                    />
                  </section>
                </ScrollArea>
              </>
            ) : null}

            {trayTab === "activity" ? (
              <>
                <div className="flex items-start gap-2 border-b border-[var(--border)] p-3">
                  <div className="min-w-0 flex-1">
                    <h3 className="text-sm font-bold">Activity</h3>
                    <p className="mt-0.5 text-[length:10.5px] text-[var(--muted-foreground)]">
                      Where this run's values went. Recipes record what a value{" "}
                      <em>is</em>; this records what became of it — the buttons
                      you pressed, and the sends a cell made, which is the one
                      thing here that cannot be undone. Digests, never values.
                      Session-only — it never leaves this tab.
                    </p>
                  </div>
                  {activity.length ? (
                    <div className="flex shrink-0 gap-1">
                      <Button
                        size="sm"
                        variant="secondary"
                        className="h-[22px] rounded-[5px] px-2 text-[10px]"
                        onClick={() => void navigator.clipboard.writeText(activityAsText())}
                      >
                        Copy log
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-[22px] rounded-[5px] px-2 text-[10px]"
                        onClick={() => clearActivity()}
                      >
                        Clear
                      </Button>
                    </div>
                  ) : null}
                </div>
                <ScrollArea className="flex-1 px-3">
                  {!activity.length ? (
                    <p className="py-4 text-sm text-[var(--muted-foreground)]">
                      Nothing yet. Copying, downloading or publishing an
                      artifact records it here, and so does a{" "}
                      <code className="font-mono">quorum.send</code> — the
                      sender keeps the digest of what went and to whom, never
                      the value.
                    </p>
                  ) : (
                    <ul className="space-y-2 py-3" data-activity-log>
                      {activity.map((e, i) => (
                        <li
                          key={`${e.at}-${i}`}
                          className="rounded-[7px] border border-[var(--border)] bg-[var(--surface-raised)] px-2.5 py-1.5"
                          data-action-tier={e.tier}
                        >
                          <div className="flex items-baseline gap-2">
                            <code className="artifact-meta font-mono text-[var(--muted-foreground)]">
                              {formatActivityTime(e.at)}
                            </code>
                            <span className="text-[11px] font-semibold text-[var(--foreground)]">
                              {e.label}
                            </span>
                            <code className="artifact-meta min-w-0 flex-1 truncate font-mono text-[var(--muted-foreground)]">
                              {e.artifact}
                            </code>
                          </div>
                          {/* Digest, never the value — the same function
                              receipts use, so the two records cross-read. */}
                          {e.digest ? (
                            <code className="artifact-meta block font-mono text-[var(--muted-foreground)]">
                              sha256 {e.digest}…
                            </code>
                          ) : null}
                          {/* The action's own account of what it did, above
                              the object it did it to. Seven of the eight
                              receipts say what the label already implies —
                              "Copy" then "Copied" — and the eighth is the
                              reason this is drawn at all: adding a key reports
                              "Added to My Keys" or "Already in My Keys", and
                              nothing else in an entry distinguishes an action
                              that changed something from one that found the
                              work already done. Same label, same artifact,
                              same digest, same detail.

                              Drawn always rather than only when it surprises,
                              because a log that records the interesting cases
                              cannot be trusted to have recorded the
                              interesting case — which is this module's own
                              argument for logging every action rather than the
                              dramatic ones. */}
                          {e.receipt ? (
                            <span className="activity-receipt">{e.receipt}</span>
                          ) : null}
                          {e.detail ? (
                            <code className="artifact-meta block break-all font-mono text-[var(--brand)]">
                              → {e.detail}
                            </code>
                          ) : null}
                        </li>
                      ))}
                    </ul>
                  )}
                </ScrollArea>
              </>
            ) : null}

            {trayTab === "outputs" ? (
              <>
                <div className="border-b border-[var(--border)] p-3">
                  <h3 className="text-sm font-bold">Outputs</h3>
                  <p className="mt-0.5 text-[length:10.5px] text-[var(--muted-foreground)]">
                    Every result this session has produced. Switch a value&rsquo;s display
                    format, or reveal one you explicitly asked to see.
                  </p>
                </div>
                <ScrollArea className="flex-1 px-3">
                  <div className="space-y-3 py-3">
                    {allOutputs.length ? (
                      Object.entries(
                        allOutputs.reduce<Record<number, typeof allOutputs>>((acc, row) => {
                          (acc[row.cell] ||= []).push(row);
                          return acc;
                        }, {})
                      ).map(([cell, rows]) => (
                        <div key={cell}>
                          <button
                            type="button"
                            className="mb-1 flex items-center gap-1.5 font-mono text-[10px] text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
                            title="Focus this cell"
                            onClick={() => nb.setFocusedCell(Number(cell))}
                          >
                            <span className="rounded-[3px] bg-[var(--surface-raised)] px-1 py-px">
                              [{cell}]
                            </span>
                            {rows.length} output{rows.length === 1 ? "" : "s"}
                          </button>
                          <OutputList
                            outputs={rows.map(({ artifact: a, index: oi }) => ({
                              label: a.label || a.filename || `output ${oi + 1}`,
                              kind: a.role === "diagnostic" ? "diag" : a.role || "text",
                              // The kind registry matches on these (§32b); without them
                              // every tile resolves to the fallback.
                              role: a.role,
                              tags: a.tags,
                              traits: a.traits,
                              // Same mapping as the cell list's, for the same
                              // reason: Download's name is the engine's name.
                              filename: a.filename,
                              mime: a.mime,
                              sizeBytes: new TextEncoder().encode(a.content).length,
                              sensitive: a.sensitive,
                              revealable: a.revealable,
                              content: a.content,
                              netType: a.netType,
                              inspectSnapshot: a.inspectSnapshot,
                              jose: a.jose,
                              signature: a.signature,
                              netKind: a.netKind,
                              netData: a.netData,
                              preview: a.sensitive ? undefined : oneLinePreview(a.content),
                              onCopy: () => void copyText(a.content),
                              // §33a/§38b: the same tile, so the same actions.
                              // Publish is declared by the kind, which means
                              // this pane offers it too — and had to be given
                              // the route, or a public key in the tray would
                              // render a disabled Publish whose stated reason
                              // ("needs a connection to the directory") was
                              // not the real one.
                              publishedAs: a.publishedAs,
                              directoryUrl: a.directoryUrl,
                              onPublish: () => nb.publishArtifact(Number(cell), oi),
                              directoryHost: location.host,
                            }))}
                          />
                        </div>
                      ))
                    ) : (
                      <p className="text-[length:11px] italic text-[var(--muted-foreground)]">
                        No outputs yet — run a cell that ends in{" "}
                        <code className="font-mono">out $label</code>.
                      </p>
                    )}
                  </div>
                </ScrollArea>
              </>
            ) : null}

            {trayTab === "inputs" ? (
              <>
                <div className="border-b border-[var(--border)] p-3">
                  <h3 className="text-sm font-bold">Inputs</h3>
                  <p className="mt-0.5 text-[length:10.5px] text-[var(--muted-foreground)]">
                    What the notebook reads at run time. Never saved to the recipe, the share
                    link, or the workspace.
                  </p>
                </div>
                <ScrollArea className="flex-1 px-3">
                  <div className="space-y-3 py-3">
                    {notebookNeeds.has("text") ? (
                      <div className="rounded-[9px] border border-[var(--border)] bg-[var(--surface-raised)] p-2.5">
                        <p className="mb-1.5 text-[length:11px] font-bold">Message</p>
                        <Textarea
                          rows={5}
                          value={nb.inputText}
                          onChange={(e) => nb.setInputText(e.target.value)}
                          placeholder="Paste or load the message — not stored in the recipe."
                        />
                      </div>
                    ) : null}

                    {notebookNeeds.has("keypair") ? (
                      <div className="rounded-[9px] border border-[var(--border)] bg-[var(--surface-raised)] p-2.5">
                        <p className="mb-1.5 text-[length:11px] font-bold">Key material</p>
                        <Textarea
                          rows={4}
                          value={nb.keypairMaterial}
                          onChange={(e) => nb.setKeypairMaterial(e.target.value)}
                          placeholder="Paste a JWK, or -----BEGIN PRIVATE KEY----- …"
                        />
                        <p className="mt-1 text-[length:10px] text-[var(--muted-foreground)]">
                          The private half stays non-extractable once imported, same as a
                          generated key.
                        </p>
                      </div>
                    ) : null}

                    {notebookNeeds.has("gpg") ? (
                      <div className="rounded-[9px] border border-[var(--border)] bg-[var(--surface-raised)] p-2.5">
                        <p className="mb-1.5 text-[length:11px] font-bold">Ciphertext</p>
                        <Textarea
                          rows={3}
                          value={nb.ciphertext}
                          onChange={(e) => nb.setCiphertext(e.target.value)}
                          placeholder="Paste -----BEGIN PGP MESSAGE----- …"
                        />
                      </div>
                    ) : null}

                    {notebookNeeds.has("shares") ? (
                      <div className="rounded-[9px] border border-[var(--border)] bg-[var(--surface-raised)] p-2.5">
                        <p className="mb-1.5 text-[length:11px] font-bold">
                          BLIP39 share mnemonics
                        </p>
                        <div className="space-y-2">
                          {nb.shareRows.map((row, ri) => (
                            <div key={ri} className="flex items-start gap-2">
                              <Textarea
                                rows={2}
                                className="flex-1"
                                value={row}
                                onChange={(e) => {
                                  const next = [...nb.shareRows];
                                  next[ri] = e.target.value;
                                  nb.setShareRows(next);
                                }}
                                placeholder={`Share ${ri + 1} mnemonic…`}
                              />
                              <Button
                                size="sm"
                                variant="ghost"
                                className="text-[var(--error)]"
                                disabledReason={
                                  nb.shareRows.length <= 1
                                    ? "This is the only share box. Recombining needs somewhere to paste at least one mnemonic — clear the box instead of removing it."
                                    : undefined
                                }
                                aria-label="Remove share"
                                onClick={() =>
                                  nb.setShareRows(nb.shareRows.filter((_, x) => x !== ri))
                                }
                              >
                                ✕
                              </Button>
                            </div>
                          ))}
                        </div>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="mt-2"
                          onClick={() => nb.setShareRows([...nb.shareRows, ""])}
                        >
                          + Add share
                        </Button>
                        <label className="mt-3 block text-xs font-semibold text-[var(--muted-foreground)]">
                          Share passphrase (optional)
                        </label>
                        <input
                          type="password"
                          className="mt-1 w-full rounded-md border border-[var(--border)] bg-[var(--surface)] px-2 py-1.5 text-sm"
                          autoComplete="off"
                          value={nb.sharePassphrase}
                          onChange={(e) => nb.setSharePassphrase(e.target.value)}
                        />
                      </div>
                    ) : null}

                    {/* The panel `input-needs.js` has derived since it was
                        written and nothing ever rendered. `agent.unlock`,
                        `agent.save` and `resolveGpgPrivateKey` all read
                        `inputs.gpg.passphrase`, and `agent.save`'s refusal names
                        this panel out loud — so the reader, the derivation and
                        the error message all existed and the field did not.
                        Without it a passphrase-protected key, which is the
                        protection this app recommends, could not sign anything
                        here: the run reached OpenPGP with an empty passphrase
                        and failed in OpenPGP's words. */}
                    {notebookNeeds.has("gpgPass") ? (
                      <div className="rounded-[9px] border border-[var(--border)] bg-[var(--surface-raised)] p-2.5">
                        <p className="mb-1.5 text-[length:11px] font-bold">Key passphrase</p>
                        <input
                          type="password"
                          className="w-full rounded-md border border-[var(--border)] bg-[var(--surface)] px-2 py-1.5 text-sm"
                          autoComplete="off"
                          aria-label="OpenPGP key passphrase"
                          value={nb.gpgPassphrase}
                          onChange={(e) => nb.setGpgPassphrase(e.target.value)}
                        />
                        <p className="mt-1 text-[length:10px] text-[var(--muted-foreground)]">
                          OpenPGP's own lock on the private key, which is not the
                          same as the vault's. Only passphrase-protected keys want
                          one — a device or passkey key needs nothing here. Held in
                          memory for this notebook only; <strong>Clear session</strong>{" "}
                          removes it.
                        </p>
                      </div>
                    ) : null}

                    {notebookNeeds.has("envelope") ? (
                      <div className="rounded-[9px] border border-[var(--border)] bg-[var(--surface-raised)] p-2.5">
                        <p className="mb-1.5 text-[length:11px] font-bold">
                          OpenPGP envelope (armored)
                        </p>
                        <Textarea
                          rows={4}
                          value={nb.envelopeArmored}
                          onChange={(e) => nb.setEnvelopeArmored(e.target.value)}
                          placeholder="-----BEGIN PGP MESSAGE----- … from gpg.symencrypt"
                        />
                      </div>
                    ) : null}

                    {notebookRecipSlots > 0 ? (
                      <div className="rounded-[9px] border border-[var(--border)] bg-[var(--surface-raised)] p-2.5">
                        <p className="mb-1.5 text-[length:11px] font-bold">Recipients</p>
                        <RecipientBinderHost
                          slots={notebookRecipSlots}
                          onChange={nb.setBoundRecipients}
                        />
                      </div>
                    ) : null}

                    {!notebookNeeds.size && !notebookRecipSlots ? (
                      <p className="py-2 text-sm text-[var(--muted-foreground)]">
                        No cell needs runtime input yet — add a step that reads text, ciphertext,
                        shares, an envelope, or recipients.
                      </p>
                    ) : null}
                  </div>
                </ScrollArea>
              </>
            ) : null}

            {trayTab === "params" ? (
              <>
                <div className="border-b border-[var(--border)] p-3">
                  <h3 className="text-sm font-bold">Cryptographic parameters</h3>
                  <p className="mt-0.5 text-[length:10.5px] text-[var(--muted-foreground)]">
                    Applies to new OpenPGP steps. Steps you've overridden (per-step Crypto profile
                    control on the step itself) keep their own profile and show an amber badge
                    here.
                  </p>
                </div>
                <ScrollArea className="flex-1 px-3">
                  <div className="space-y-3 py-3 text-sm">
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-sm font-bold">Default crypto profile</p>
                      <Badge
                        variant="ok"
                        className="rounded-full px-[9px] py-[3px] text-[10.5px] normal-case tracking-normal"
                      >
                        {nb.pgpMode}
                      </Badge>
                    </div>
                    <ModeToggle
                      ariaLabel="OpenPGP profile"
                      value={nb.pgpMode}
                      onChange={(v) => nb.setPgpMode(v as "auto" | "modern" | "compatible")}
                      options={[
                        { value: "auto", label: "Auto" },
                        { value: "modern", label: "Modern" },
                        { value: "compatible", label: "Compat" },
                      ]}
                    />

                    {profileOverrides.length ? (
                      <div className="flex items-center justify-between gap-2 rounded-md border border-l-[3px] border-[color-mix(in_srgb,var(--warn)_45%,var(--border))] border-l-[var(--warn)] bg-[color-mix(in_srgb,var(--warn)_10%,transparent)] px-2.5 py-2">
                        <span className="text-[length:11.5px] text-[var(--foreground)]">
                          {profileOverrides.length} step{profileOverrides.length === 1 ? "" : "s"}{" "}
                          override the session default
                        </span>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="shrink-0"
                          onClick={() => {
                            const first = profileOverrides[0];
                            if (!first) return;
                            nb.setFocusedCell(first.cell);
                            setChipEdit(first);
                          }}
                        >
                          Review
                        </Button>
                      </div>
                    ) : null}

                    <Separator />

                    <p className="text-[length:11px] font-bold uppercase tracking-wider text-[var(--muted-foreground)]">
                      Crypto self-test (POST)
                    </p>
                    <div className="flex flex-wrap gap-1.5">
                      {(Object.keys(SUITE_BADGE_LABEL) as (keyof ToolkitSuiteStatus)[]).map(
                        (suite) => {
                          const verified = suiteStatus[suite] === "verified";
                          return (
                            <Badge
                              key={suite}
                              variant={verified ? "ok" : "warn"}
                              className="rounded-full px-[9px] py-[3px] text-[10.5px] normal-case tracking-normal"
                            >
                              {verified ? "✓" : "⚠"} {SUITE_BADGE_LABEL[suite]}
                            </Badge>
                          );
                        }
                      )}
                    </div>

                    <label className="flex items-center justify-between gap-3 border-t border-[var(--border)] py-2.5">
                      <span className="text-sm">FIPS mode</span>
                      <button
                        type="button"
                        role="switch"
                        aria-checked={fipsMode}
                        aria-label="FIPS mode"
                        onClick={() => onFipsModeChange(!fipsMode)}
                        className={cn(
                          "relative inline-flex h-[19px] w-[34px] shrink-0 items-center rounded-full border transition-colors",
                          fipsMode
                            ? "border-[var(--success)] bg-[color-mix(in_srgb,var(--success)_22%,transparent)]"
                            : "border-[var(--border)] bg-[var(--muted)]"
                        )}
                      >
                        <span
                          className={cn(
                            "inline-block h-[14px] w-[14px] rounded-full bg-[var(--success)] transition-transform",
                            fipsMode ? "translate-x-[17px]" : "translate-x-[2px]",
                            !fipsMode && "bg-[var(--muted-foreground)]"
                          )}
                        />
                      </button>
                    </label>
                    <p className="text-xs leading-relaxed text-[var(--muted-foreground)]">
                      {unverifiedSuiteNames.length
                        ? `Blocks adding or running ops on an unverified suite (${unverifiedSuiteNames
                            .map((s) => SUITE_BADGE_LABEL[s])
                            .join(", ")}, above).`
                        : FIPS_MODE_DISCLAIMER}
                    </p>

                    {fipsBlockedMessage ? (
                      <div className="flex items-center gap-2 rounded-lg border border-[color-mix(in_srgb,var(--warn)_45%,var(--border))] border-l-[3px] border-l-[var(--warn)] bg-[color-mix(in_srgb,var(--warn)_10%,transparent)] px-2.5 py-2">
                        <span className="text-xs text-[var(--foreground)]">
                          {fipsBlockedMessage}
                        </span>
                      </div>
                    ) : null}
                  </div>
                </ScrollArea>
              </>
            ) : null}
          </aside>
        ) : (
          <button
            type="button"
            // `tray-rail` is the mirror of `ops-rail`: the collapsed form of a
            // pane still has to be told which column it belongs in, and still
            // has to stop being a 28px vertical strip when the row stacks.
            className="tray-rail flex w-[28px] shrink-0 items-center justify-center border-l border-[var(--border)] bg-[color-mix(in_srgb,var(--surface-raised)_88%,var(--surface))] text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
            title="Expand session tray"
            onClick={() => setTrayOpen(true)}
          >
            <span className="[writing-mode:vertical-rl] text-[11px] font-semibold tracking-wide">
              Tray
            </span>
          </button>
        )}
        </div>

        {/* Share this notebook — the three transfers, each with its own row.
            `verified` counts peers whose key has actually been confirmed, not
            peers who arrived: they are different claims, and the sheet draws
            the gap between them. */}
        <ShareSheet
          open={shareOpen}
          onOpenChange={setShareOpen}
          recipeLink={recipeLink}
          // What *this* notebook's link would give away, or "" for one that
          // gives nothing away. Derived from the same text the link is built
          // from, so the sentence and the link cannot describe two notebooks.
          recipeDiscloses={recipeLinkDiscloses(nb.source).sentence}
          onCopyRecipeLink={() => void nb.copyShareLink()}
          recipeQr={recipeQr}
          onSaveRecipe={() => saveNotebookFile(nb.title, nb.source)}
          proof={runProof}
          session={
            nb.quorumState.room
              ? {
                  room: nb.quorumState.room,
                  invite: nb.quorumState.invite,
                  joined: (nb.quorumState.peers || []).length,
                  expected: nb.quorumState.expected,
                  verified: (nb.quorumState.peers || []).filter((p) => p.authenticated)
                    .length,
                }
              : null
          }
          /* The row hands off to the session's own window rather than doing
             anything itself. Until this prop was passed, "Start shared session"
             was a button with no handler — the tier that needs the most
             explanation was the one with no way in. */
          onStartSession={() => {
            setShareOpen(false);
            nb.setSheet("session");
          }}
          onCopyInvite={copyInvite}
        />

        {/* The shared session, start to finish. Reached from the Share sheet's
            third tier, from the Connections tab, and from an invite link —
            three doors onto one window, because a session is arrived at from
            all three directions. */}
        <SessionSheet
          open={nb.sheet === "session"}
          focus={sessionFocus}
          onOpenChange={(o) => {
            if (!o) setSessionFocus(null);
            nb.setSheet(o ? "session" : null);
          }}
          live={
            sessionLive
              ? {
                  state: {
                    phase: nb.quorumState.phase,
                    role: nb.quorumState.role,
                    room: nb.quorumState.room,
                    status: nb.quorumState.status,
                    audience: nb.quorumState.audience || [],
                    self: String(nb.quorumState.self || ""),
                    peers: rosterRows,
                  },
                  inviteUrl,
                  onCopyInvite: copyInvite,
                  attestation: nb.attestation,
                  // Refused on the live count, never on the last press's
                  // outcome: a reason derived from what happened once is a
                  // reason that stays true after the state it describes has
                  // gone, and this button would then be dead for the rest of
                  // the session with a sentence about a room that has since
                  // meshed.
                  attestRefusal: nb.quorumState.connected
                    ? undefined
                    : "Nobody in this room has a confirmed channel yet, so an attestation would reach nobody. Nothing here re-sends one later — wait for a peer to confirm, then attest.",
                  onAttest: () => {
                    setAttestNote(null);
                    void nb.attestManifest().then((r) => {
                      setAttestNote(
                        r.ok
                          ? `Signed and sent to ${r.sent} peer${r.sent === 1 ? "" : "s"}. It says you saw this digest — not when, and not that you will run it.`
                          : r.why || "That manifest could not be attested to."
                      );
                    });
                  },
                  attestNote,
                  onRestartIce: () => void restartLiveIce(),
                  onClose: () => nb.cancelQuorum(),
                  onRemove: (fingerprint: string) =>
                    void nb.removeFromRoom(fingerprint),
                }
              : null
          }
          start={{
            role: sessionDraft.role,
            onRole: (role) => setSessionDraft((d) => ({ ...d, role })),
            keys: sessionKeys.map((k) => ({
              fingerprint: k.fingerprint,
              uid: k.uid,
              // What picking this one will ask of you, in the same words the
              // Keys tray uses for the same key. The chooser listed every
              // candidate identically, so "signs immediately" and "will stop
              // the run to ask for a passphrase" looked the same at the moment
              // of the choice.
              note: keyViews.find((v) => v.fingerprint === k.fingerprint)?.powerLabel,
            })),
            keyFingerprint: sessionDraft.keyFingerprint,
            onKeyFingerprint: (fpr) => {
              setSessionDraft((d) => ({ ...d, keyFingerprint: fpr }));
              // Your own key joins the room the moment it is chosen. A room
              // you are not in derives a different room, so leaving that to a
              // second press is leaving a footgun where a default belongs.
              //
              // Through `setDraftAudience` like every other door, so that the
              // one function which knows what an audience change costs the
              // notebook stays the only one that changes an audience.
              if (fpr && !sessionDraft.audience.includes(fpr)) {
                setDraftAudience([...sessionDraft.audience, fpr]);
              }
            },
            audience: sessionDraft.audience,
            // A name for each key, where this browser has one. The room list
            // draws a placard per member, and this is its human half — the
            // other half is the fingerprint the row already has.
            names: Object.fromEntries(peerNames),
            relabelNote,
            trusted: trustedPeers,
            // One press, one lookup. `searchRecipients` is the encrypt side's
            // own search — same cache, same keyserver, same trust ordering —
            // so a person found here is a person found there.
            //
            // Every hit is handed over, including the ones `mergeSearchHits`
            // admits at sixteen characters. Filtering those out here made the
            // empty case lie: "No key here answers to that" was printed to
            // somebody whose search had matched. `SHORT_ID_HIT` is the row's
            // own refusal, so a search that found nothing and a search that
            // found something unusable are two different answers again.
            onSearch: async (query: string) =>
              (await searchRecipients(query))
                .map((hit) => ({
                  fingerprint: String(hit.fingerprint || "").toUpperCase(),
                  label: primaryUidLabel(hit),
                })),
            // The marks this browser holds, so a key you decided not to
            // believe cannot be built into a room by a stray press.
            // `quorum-mount.js` asked this with a `confirm()`, which names a
            // state and offers to ignore it in the same sentence.
            neverTrusted: neverTrustedKeys,
            onAudience: setDraftAudience,
            // The readout did the reading. Applying its audience rather than
            // re-parsing the text is what keeps the sentence on screen and the
            // room in the draft from ever being answers to different questions
            // — and `role` is the one thing only a link can settle.
            onPaste: (result) => {
              setSessionDraft((d) => ({ ...d, role: result.role || d.role }));
              setDraftAudience(result.audience);
            },
            // The one template in this product that is generated rather than
            // typed, offered where the thing it is generated from is chosen.
            // `quorum.send` / `quorum.recv` are named by no preset, so until
            // this existed the only way anybody reached them was by typing two
            // whole fingerprints into step params by hand.
            ceremony: {
              summary: roomCeremonySummary(draftCeremony),
              issues: draftCeremony.issues,
              text: draftCeremony.text,
              // The sentence, not the pipeline: the widget draws the reading
              // of the notebook beside the notebook, and the peer is already
              // in the recipe below it whole. No phase — the deal is one
              // occasion now, and recovery is its own notebook.
              cells: draftCeremony.cells.map((c) => ({ why: c.why })),
              threshold: draftCeremony.threshold,
              shares: draftCeremony.shares,
              onWrite: writeRoomCeremony,
              note: ceremonyNote,
            },
            issues: sessionIssues,
            inviteUrl,
            onCopyInvite: copyInvite,
            opens: START_OPENS,
            onStart: () => {
              void nb.startSession({
                audience: sessionDraft.audience,
                keyFingerprint: sessionDraft.keyFingerprint,
                role: sessionDraft.role,
              });
            },
          }}
          recovery={{
            facts: recoveryFacts
              ? `This machine holds share ${recoveryFacts.index} of ${recoveryFacts.total} — any ${recoveryFacts.threshold} recombine (set ${recoveryFacts.setId}).`
              : "",
            issues: draftRecovery.issues,
            text: draftRecovery.text,
            cells: draftRecovery.cells.map((c) => ({ why: c.why })),
            threshold: draftRecovery.threshold,
            total: draftRecovery.total,
            // Everyone the deal dealt to, minus this machine — the pickable
            // contributors, named where a name is known, whole either way.
            choices: recoveryHoldings
              .filter((h) => h.fingerprint !== recoverySelf)
              .map((h) => ({
                fingerprint: h.fingerprint,
                name: peerNames.get(h.fingerprint),
                chosen: recoveryContributors.includes(h.fingerprint),
              })),
            onToggle: (fpr: string) =>
              setRecoveryContributors((list) =>
                list.includes(fpr) ? list.filter((f) => f !== fpr) : [...list, fpr]
              ),
            onWrite: writeRoomRecovery,
            onWriteCustodian: writeCustodianRecovery,
            note: recoveryNote,
          }}
        />

        {/* Guided key ceremony — the kit's front door (HANDOFF: a window is a Sheet) */}
        <CeremonySheet
          open={nb.sheet === "ceremony"}
          onOpenChange={(o) => nb.setSheet(o ? "ceremony" : null)}
          stage={nb.ceremonyStage}
          onStage={nb.setCeremonyStage}
          threshold={nb.ceremonyParams.threshold}
          shares={nb.ceremonyParams.shares}
          label={nb.ceremonyParams.label}
          qr={nb.ceremonyParams.qr}
          onParams={nb.updateCeremonyParams}
          signingKeys={nb.vaultKeys.map((k) => ({
            fingerprint: k.fingerprint,
            uid: k.uid,
          }))}
          signWith={nb.ceremonyParams.signWith}
          onSignWith={(fingerprint) => nb.updateCeremonyParams({ signWith: fingerprint })}
          onRunStage={nb.runCeremonyStage}
          runState={nb.ceremonyRun}
          runError={nb.ceremonyError}
          expectedDigest={nb.ceremonyView.expectedDigest}
          recoveredDigest={nb.ceremonyView.recoveredDigest}
          shareArtifacts={nb.ceremonyView.shareArtifacts}
          commitmentsText={nb.ceremonyView.commitmentsText}
          playbookText={nb.ceremonyView.playbookText}
          receiptText={nb.ceremonyView.receiptText}
          onScanQr={scanCardPhoto}
        />

        {/*
          The custodian check, reachable cold. No notebook state feeds it and
          none of its inputs come from the session: the person it is for is
          holding a card and nothing else, possibly years later, possibly on a
          machine that has never run this ceremony.
        */}
        <Sheet
          open={nb.sheet === "sharecheck"}
          onOpenChange={(o) => nb.setSheet(o ? "sharecheck" : null)}
        >
          <SheetContent side="right" className="w-full sm:max-w-xl">
            <SheetHeader>
              <SheetTitle>Check a share</SheetTitle>
              <SheetDescription>
                Confirm that the card you are holding really belongs to the split it
                claims to — on its own, without any other share, and without revealing
                anything.
              </SheetDescription>
            </SheetHeader>
            {/* **Scrolls, which it did not.** `SheetContent` is a full-height
                flex column with no overflow anywhere in it, so anything past
                the fold was not merely below the viewport — it was
                unreachable, by pointer and by keyboard alike. Nobody noticed
                while the panel was short. It stopped being short the moment
                the plain-Shamir verdict had to say what it does *not* prove,
                and the first thing to go over the edge was "Do this by hand
                instead" — the fold holding the recovery recipe, i.e. the one
                thing on this panel a custodian actually needs.
                `min-h-0` is the half that is easy to omit: a flex child's
                default `min-height: auto` refuses to shrink below its content,
                so `overflow-y-auto` alone would have scrolled nothing. */}
            <div className="min-h-0 flex-1 overflow-y-auto px-4 pb-4">
              <ShareCheck onScanQr={scanCardPhoto} />
            </div>
          </SheetContent>
        </Sheet>

        {/* Verify-this-deployment (THREAT-MODEL "if you want to verify rather than trust") */}
        <Sheet
          open={nb.sheet === "integrity"}
          onOpenChange={(o) => nb.setSheet(o ? "integrity" : null)}
        >
          <SheetContent side="right" className="w-full sm:max-w-xl">
            <SheetHeader>
              <SheetTitle>Verify this deployment</SheetTitle>
              <SheetDescription>
                Every load hands you the JavaScript that will touch your keys. This is
                what can be checked about the code you were served, and what cannot.
              </SheetDescription>
            </SheetHeader>
            <div className="px-4 pb-4">
              <IntegrityPanel />
            </div>
          </SheetContent>
        </Sheet>

        {/* Workspace library sheet */}
        <Sheet
          open={nb.sheet === "workspace"}
          onOpenChange={(o) => nb.setSheet(o ? "workspace" : null)}
        >
          <SheetContent side="right" className="w-full sm:max-w-md">
            <SheetHeader>
              <div className="flex items-center justify-between gap-2">
                <SheetTitle>Workspace library</SheetTitle>
                <div className="flex shrink-0 gap-1.5">
                  {/* Writes the cell rather than the document: signing is a
                      thing a person does by reading a recipe and pressing Run,
                      never a thing a button does behind them. */}
                  <Button
                    variant="secondary"
                    className="h-auto rounded-[7px] px-[11px] py-[5px] text-[length:11.5px] font-semibold"
                    onClick={writePlaybookCell}
                    title="Add a cell that signs this notebook as a recovery playbook"
                  >
                    Playbook cell
                  </Button>
                  <Button
                    className="h-auto rounded-[7px] px-[11px] py-[5px] text-[length:11.5px] font-bold"
                    onClick={saveCurrentWorkspace}
                  >
                    + Save current
                  </Button>
                </div>
              </div>
              <SheetDescription>
                Named recipes saved in this browser — title and steps only, never Inputs, kernel
                slots, or private keys. A saved <strong>playbook</strong> is checked against your
                keys when you load it; this browser&rsquo;s storage can be rewritten, so the
                signature is what answers for it, not the row.
              </SheetDescription>
            </SheetHeader>
            <Separator />
            {workspaceError ? (
              <p className="px-4 text-sm text-[var(--error)]">{workspaceError}</p>
            ) : null}
            <ScrollArea className="flex-1 px-4">
              {!workspaces.length ? (
                <p className="py-4 text-sm text-[var(--muted-foreground)]">
                  Nothing saved yet — build a recipe, then Save current.
                </p>
              ) : (
                <ul className="space-y-2 py-3">
                  {workspaces.map((ws) => {
                    const opened = playbookState[ws.id];
                    return (
                      <li
                        key={ws.id}
                        className="flex flex-col gap-1.5 rounded-[9px] border border-[var(--border)] bg-[var(--surface)] px-[11px] py-[9px]"
                        data-workspace={ws.id}
                        data-playbook={ws.playbook ? "yes" : "no"}
                        data-verified={opened ? (opened.ok ? "yes" : "no") : "unchecked"}
                      >
                        <div className="flex items-center justify-between gap-3">
                          <div className="min-w-0">
                            <div className="truncate text-[12.5px] font-bold">{ws.title}</div>
                            <div className="text-[length:10.5px] text-[var(--muted-foreground)]">
                              {relativeTime(ws.updatedAt)} · {workspaceStepCount(ws.recipe)} steps
                              {ws.playbook ? " · signed playbook" : ""}
                            </div>
                          </div>
                          <Button
                            variant="secondary"
                            className="h-auto shrink-0 rounded-md px-[9px] py-[4px] text-[10.5px] font-semibold"
                            busy={workspaceOpening === ws.id}
                            onClick={() => void loadWorkspaceEntry(ws)}
                          >
                            {workspaceOpening === ws.id ? "Checking…" : "Load"}
                          </Button>
                        </div>
                        {/*
                          Who vouched, not that somebody did. "Signed by a key
                          you hold" and "signed by a key you trust" are different
                          sentences, so the name and the fingerprint are on
                          screen and the word "verified" never stands alone.
                        */}
                        {ws.playbook && opened?.ok && opened.by ? (
                          <p className="text-[length:10.5px] text-[var(--ok,var(--muted-foreground))]">
                            Signed by <strong>{opened.by.uid || "a key with no name on it"}</strong>{" "}
                            <Fingerprint fpr={opened.by.fingerprint} />, from My Keys. That it
                            is a key you hold is not the same as a key you trust.
                          </p>
                        ) : null}
                        {ws.playbook && opened && !opened.ok ? (
                          <p className="text-[length:10.5px] text-[var(--error)]">
                            {opened.message}
                          </p>
                        ) : null}
                        {ws.playbook && !opened ? (
                          <p className="text-[length:10.5px] text-[var(--muted-foreground)]">
                            Not checked yet — Load verifies it against your keys and refuses to
                            open it if nothing vouches for it.
                          </p>
                        ) : null}
                      </li>
                    );
                  })}
                </ul>
              )}
            </ScrollArea>
            <SheetFooter>
              <label className="w-full">
                <span className="flex w-full cursor-pointer items-center justify-center rounded-[7px] border border-dashed border-[var(--border)] py-[6px] text-[length:11.5px] font-semibold text-[var(--muted-foreground)] hover:bg-[var(--surface-raised)]">
                  Import from file…
                </span>
                <input
                  type="file"
                  accept=".json,.txt,.recipe,.asc"
                  className="hidden"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    e.target.value = "";
                    if (file) void importWorkspaceFile(file);
                  }}
                />
              </label>
            </SheetFooter>
          </SheetContent>
        </Sheet>

        {/* Toolkit preferences sheet */}
        <Sheet open={nb.sheet === "prefs"} onOpenChange={(o) => nb.setSheet(o ? "prefs" : null)}>
          <SheetContent side="right" className="w-full sm:max-w-md">
            <SheetHeader>
              <SheetTitle>Toolkit preferences</SheetTitle>
              <SheetDescription>
                Stored in this browser only (<code>basilisk.toolkit.prefs</code>).
              </SheetDescription>
            </SheetHeader>
            <Separator />
            <div className="space-y-4 p-4 text-sm">
              <div>
                <label className="mb-1 block text-xs font-semibold text-[var(--muted-foreground)]">
                  Clear sensitive data after idle
                </label>
                <select
                  className="w-full rounded-md border border-[var(--border)] bg-[var(--surface)] px-2 py-1.5 text-sm"
                  value={nb.toolkitPrefs.idleClearMinutes}
                  onChange={(e) =>
                    nb.updateToolkitPrefs({ idleClearMinutes: Number(e.target.value) })
                  }
                >
                  <option value={0}>Never</option>
                  <option value={1}>1 minute</option>
                  <option value={5}>5 minutes</option>
                  <option value={15}>15 minutes</option>
                  <option value={60}>60 minutes</option>
                </select>
                <p className="mt-1 text-xs text-[var(--muted-foreground)]">
                  Wipes Inputs, kernel slots, and unlocked agent sessions — not the recipe
                  itself.
                </p>
              </div>

              <label className="flex items-center justify-between gap-3 border-t border-[var(--border)] py-2.5">
                <span>
                  Session-off unlock
                  <p className="text-xs font-normal text-[var(--muted-foreground)]">
                    Unlock keys per-run only — never write to the shared agent session.
                  </p>
                </span>
                <button
                  type="button"
                  role="switch"
                  aria-checked={nb.toolkitPrefs.sessionOff}
                  aria-label="Session-off unlock"
                  onClick={() =>
                    nb.updateToolkitPrefs({ sessionOff: !nb.toolkitPrefs.sessionOff })
                  }
                  className={cn(
                    "relative inline-flex h-[19px] w-[34px] shrink-0 items-center rounded-full border transition-colors",
                    nb.toolkitPrefs.sessionOff
                      ? "border-[var(--success)] bg-[color-mix(in_srgb,var(--success)_22%,transparent)]"
                      : "border-[var(--border)] bg-[var(--muted)]"
                  )}
                >
                  <span
                    className={cn(
                      "inline-block h-[14px] w-[14px] rounded-full bg-[var(--success)] transition-transform",
                      nb.toolkitPrefs.sessionOff ? "translate-x-[17px]" : "translate-x-[2px]",
                      !nb.toolkitPrefs.sessionOff && "bg-[var(--muted-foreground)]"
                    )}
                  />
                </button>
              </label>

              {/* The third party with the strongest terms gets the fullest
                  statement, at the point where the choice is made — the
                  pattern e48f607 set for STUN, applied to the one server that
                  carries the traffic rather than just learning an address.
                  Both halves of the disclosure are here because either one
                  alone misleads: "cannot read it" invites waving it through,
                  "sees your address" invites refusing a relay that genuinely
                  cannot read a byte. */}
              <label className="flex items-center justify-between gap-3 border-t border-[var(--border)] py-2.5">
                <span>
                  Relay fallback (TURN)
                  <p className="text-xs font-normal text-[var(--muted-foreground)]">
                    Off: a connection that cannot be made directly simply fails, and no
                    relay operator ever hears of it. On: after ICE fails outright, ask
                    this server for a short-lived relay credential and retry.
                  </p>
                  <p className="relay-disclosure text-xs font-normal">{RELAY_DISCLOSURE.summary}</p>
                </span>
                <button
                  type="button"
                  role="switch"
                  aria-checked={nb.toolkitPrefs.relayFallback}
                  aria-label="Relay fallback (TURN)"
                  onClick={() =>
                    nb.updateToolkitPrefs({ relayFallback: !nb.toolkitPrefs.relayFallback })
                  }
                  className={cn(
                    "relative inline-flex h-[19px] w-[34px] shrink-0 items-center rounded-full border transition-colors",
                    nb.toolkitPrefs.relayFallback
                      ? "border-[var(--warn)] bg-[color-mix(in_srgb,var(--warn)_22%,transparent)]"
                      : "border-[var(--border)] bg-[var(--muted)]"
                  )}
                >
                  <span
                    className={cn(
                      "inline-block h-[14px] w-[14px] rounded-full transition-transform",
                      nb.toolkitPrefs.relayFallback
                        ? "translate-x-[17px] bg-[var(--warn)]"
                        : "translate-x-[2px] bg-[var(--muted-foreground)]"
                    )}
                  />
                </button>
              </label>

              <label className="flex items-center justify-between gap-3 border-t border-[var(--border)] py-2.5">
                <span>Collapse advanced params by default</span>
                <button
                  type="button"
                  role="switch"
                  aria-checked={nb.toolkitPrefs.collapseAdvanced}
                  aria-label="Collapse advanced params by default"
                  onClick={() =>
                    nb.updateToolkitPrefs({
                      collapseAdvanced: !nb.toolkitPrefs.collapseAdvanced,
                    })
                  }
                  className={cn(
                    "relative inline-flex h-[19px] w-[34px] shrink-0 items-center rounded-full border transition-colors",
                    nb.toolkitPrefs.collapseAdvanced
                      ? "border-[var(--success)] bg-[color-mix(in_srgb,var(--success)_22%,transparent)]"
                      : "border-[var(--border)] bg-[var(--muted)]"
                  )}
                >
                  <span
                    className={cn(
                      "inline-block h-[14px] w-[14px] rounded-full bg-[var(--success)] transition-transform",
                      nb.toolkitPrefs.collapseAdvanced
                        ? "translate-x-[17px]"
                        : "translate-x-[2px]",
                      !nb.toolkitPrefs.collapseAdvanced && "bg-[var(--muted-foreground)]"
                    )}
                  />
                </button>
              </label>
            </div>
          </SheetContent>
        </Sheet>
      </div>
    </TooltipProvider>
  );
}
