import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createKernel } from "../lib/toolkit/kernel.js";
import {
  handoffContext,
  reviewOffer,
  reviewResult,
} from "../lib/toolkit/handoff-shell.js";
import {
  getPendingHandoffs,
  takeHandoff,
  getLiveSession,
  getProposedNotebook,
  clearProposedNotebook,
  openQuorumSession,
  rotateQuorumRoom,
  signSessionDocument,
} from "../lib/toolkit/quorum-ops.js";
import {
  buildNotebookProposal,
  decideProposal,
  proposalToJson,
} from "../lib/toolkit/notebook-share.js";
import {
  attestationToJson,
  buildAttestation,
  manifestAttestedBy,
} from "../lib/toolkit/attest.js";
import { summarizeHandoff, resultToJson } from "../lib/toolkit/handoff.js";
import { labelForFingerprint, planRun } from "../lib/toolkit/plan.js";
import { roomRoster } from "../lib/notebook/roster.js";
import { departedPeers, unassignDeparted } from "../lib/toolkit/peer-relabel.js";
import {
  narrateNoSession,
  narrateOffers,
  offersOwed,
} from "../lib/toolkit/run-offers.js";
import { cellsInScope, createRun, noteOfferVerdicts } from "../lib/toolkit/run.js";
import { offerForSkipped, resultForCell } from "../lib/toolkit/handoff-shell.js";
import { beginApprovalRun, clearApprovalGrants } from "../lib/toolkit/approval-gate.js";
import { clearActivity } from "../lib/toolkit/activity-log.js";
import {
  PRESETS,
  compileRecipe,
  migrateRecipe,
  serializeRecipe,
  setPublishedSlots,
  validateRecipe,
  unresolvedRecipients,
} from "../lib/toolkit/recipe.js";
import {
  stitchPresetPair,
  resolvePresetPair,
  bridgeModeMeta,
} from "../lib/toolkit/conjugate-stitch.js";
import { listSteps, getStep } from "../lib/toolkit/registry.js";
import { readShareHeader } from "../lib/slip39/blip39.js";
import { wiredForCell } from "../lib/toolkit/slot-graph.js";
import {
  ceremonyCells,
  ceremonyTitle,
  tileForSlot,
  type CeremonyStageId,
} from "../lib/toolkit/ceremony.js";
import { collectShareCards } from "../lib/toolkit/share-cards.js";
import {
  MESSAGING_STARTERS,
  parseToolkitHash,
  hashForNotebook,
  toolkitShareUrl,
} from "../lib/toolkit/fragment.js";
import { profileForMode } from "../lib/pgp/profile-from-step.js";
import { listKeys } from "../lib/vault.js";
import { unlockVaultForUse } from "../lib/vault-unlock.js";
import { sessionEvict, sessionList, vaultKindFromId } from "../lib/vault-session.js";
import { getToolkitPrefs, setToolkitPrefs, type ToolkitPrefs } from "../lib/toolkit/prefs.js";
import { configureRelayFallback } from "../lib/webrtc/relay-fallback.js";
import { fetchRelayCredentials } from "../lib/webrtc/turn-credentials.js";
import { formatFingerprint } from "../lib/utils.js";
import type {
  ArtifactTile,
  CellStatus,
  PgpMode,
  RecipeChain,
  RecipeStep,
  RecipeParams,
  ResolvedRecipient,
  SlotMeta,
  VaultKeyRow,
} from "./notebook-types";

/** A manifest attestation as `lib/toolkit/attest.js` defines one. */
export type ManifestAttestation = import("../lib/toolkit/attest.js").ManifestAttestation;

/** The reified run — `lib/toolkit/run.js` holds the argument for its shape. */
export type Run = import("../lib/toolkit/run.js").Run;
/** Why a run started, as `createRun` takes it. */
export type RunCause = import("../lib/toolkit/run.js").RunCause;

/** What one cell's last run here read, wrote and received (`kernel.js`). */
export type CellProvenance = import("../lib/toolkit/kernel.js").CellProvenance;

/** What `manifestAttestedBy` answers about one manifest. */
export type AttestationCoverage = Awaited<ReturnType<typeof manifestAttestedBy>>;

/** One roster row — mirror of lib/notebook/roster's ConnectionPeerRow. */
export type QuorumPeerRow = {
  id: string;
  fingerprint: string;
  state: "new" | "connecting" | "connected" | "disconnected" | "failed" | "closed";
  authenticated: boolean;
  /**
   * Every attestation this peer signed and the session checked against their
   * key — the documents, not their digests, because the coverage check reads
   * `kind` and `v` off the bytes a peer actually signed.
   */
  attested: ManifestAttestation[];
  via?: string;
};

/**
 * One managed peer connection — arrives via `basilisk:peer-links` (§57a).
 *
 * Mirrors `linkRow` in `lib/webrtc/link-registry.js`, and carries **every**
 * link, mesh ones included: the registry is one inventory precisely so the
 * panel does not have to ask two sources what is connected.
 */
export type PeerLinkRow = {
  id: string;
  origin: "peer" | "quorum";
  role: "offerer" | "answerer";
  label: string;
  connectionState:
    | "new"
    | "connecting"
    | "connected"
    | "disconnected"
    | "failed"
    | "closed";
  channelState: string;
  authenticated: boolean;
  via: string;
  /** The relay fallback's state on this link — `off` when none will be used. */
  relay?: {
    phase: "off" | "armed" | "escalating" | "escalated" | "exhausted" | "unavailable";
    configured?: boolean;
    reason?: string;
  };
  relayed?: boolean;
};

/** Mirror of quorum-ops' QuorumExchangeState — arrives via `basilisk:quorum-state`. */
export type QuorumUiState = {
  phase: "idle" | "offering" | "waiting" | "connected" | "closed" | "failed";
  room: string;
  role: "creator" | "joiner" | "";
  invite: string;
  /**
   * The fingerprints the room was derived from — every member, present or not.
   * The room id is a one-way digest of these, so this is the only end of the
   * pair a shell can build an invite from, and the roster cannot substitute:
   * it holds who arrived, not who was asked.
   */
  audience: string[];
  /**
   * How many times this room has moved, counting from zero.
   *
   * The one field that distinguishes "the room I am in lost a member" from
   * "a different room opened", since both show up here as a new `audience` and
   * a new `room`. `dropDepartedPlacements` below is the reason it is carried.
   */
  epoch?: number;
  connected: number;
  expected: number;
  status: string;
  peers: QuorumPeerRow[];
  /** Which fingerprint this browser is, so a label can be matched to "me". */
  self?: string;
};

function emptyChains(): RecipeChain[] {
  return [{ steps: [] }];
}

function cellInputNeeds(chain: RecipeChain): string[] {
  if (!chain?.steps?.length) return [];
  try {
    const v = validateRecipe({ chains: [chain], steps: chain.steps, source: "" });
    return (v.inputNeeds || []) as string[];
  } catch {
    return [];
  }
}

function cellRecipientSlots(chain: RecipeChain): number {
  if (!chain?.steps?.length) return 0;
  try {
    return unresolvedRecipients({
      chains: [chain],
      steps: chain.steps,
      source: "",
    }).slots;
  } catch {
    return 0;
  }
}

/**
 * Drop a selector branch from a `tee` stem — the pure half of `removeBranch`,
 * exported so the last-branch rule can be tested without a renderer.
 *
 * The rule: **when the last branch goes and there is no unselected body left,
 * the `tee` goes with it.** A `tee` exists only to host what hangs off it, and
 * an empty one is not merely pointless but a hard parse error ("tee requires a
 * body"), so keeping it would answer a delete the user asked for with a broken
 * recipe. Dropping it is safe because `tee` is transparent to the main chain —
 * `validateRecipe` leaves the stem type unchanged across a tee — so nothing
 * downstream can notice. The caller is expected to say so and offer an undo;
 * this is more than was clicked on, and silence would be the wrong answer.
 *
 * `peek` is deliberately *not* substituted here. It is a different op with its
 * own output, and the chip flow already offers it as an explicit choice on an
 * empty tee ("peek instead"); performing it as the side effect of a delete
 * would put an op on the canvas that nobody picked.
 */
export function stepsWithBranchRemoved(
  steps: RecipeStep[],
  stem: number,
  branch: number
): { steps: RecipeStep[]; droppedStem: boolean } {
  const target = steps[stem];
  if (!target?.branches?.[branch]) return { steps, droppedStem: false };
  const branches = target.branches.filter((_, j) => j !== branch);
  if (!branches.length && !target.body?.length) {
    return { steps: steps.filter((_, i) => i !== stem), droppedStem: true };
  }
  return {
    steps: steps.map((s, i) => (i === stem ? { ...s, branches } : s)),
    droppedStem: false,
  };
}

/**
 * Remove one step from a tee/foreach body or a selector branch.
 *
 * The cascade is the point. A selector branch whose last step is removed
 * serializes to `- :public |`, which does not parse — "Expected a step name".
 * So deleting the last step of a branch takes the branch, and if that was the
 * tee's last branch `stepsWithBranchRemoved` takes the tee, on the same rule it
 * already applies. A delete the user asked for may never hand back a recipe
 * that no longer compiles.
 *
 * Body steps do not cascade: `tee` with an empty body but live branches is
 * valid, and `foreach` owns its body — an empty loop body is a recipe the user
 * can still finish typing.
 */
export function stepsWithNestStepRemoved(
  steps: RecipeStep[],
  stem: number,
  branch: number | null,
  bodyIndex: number
): { steps: RecipeStep[]; droppedBranch: boolean; droppedStem: boolean } {
  const target = steps[stem];
  if (!target) return { steps, droppedBranch: false, droppedStem: false };
  if (branch != null) {
    const body = target.branches?.[branch]?.body;
    if (!body?.[bodyIndex]) return { steps, droppedBranch: false, droppedStem: false };
    if (body.length === 1) {
      const dropped = stepsWithBranchRemoved(steps, stem, branch);
      return { ...dropped, droppedBranch: true };
    }
  } else if (!target.body?.[bodyIndex]) {
    return { steps, droppedBranch: false, droppedStem: false };
  }
  const next = steps.map((s, i) => {
    if (i !== stem) return s;
    const clone: RecipeStep = {
      ...s,
      body: s.body ? [...s.body] : undefined,
      branches: s.branches?.map((b) => ({ ...b, body: b.body ? [...b.body] : [] })),
    };
    if (branch != null) {
      const br = clone.branches?.[branch];
      if (!br?.body) return s;
      br.body = br.body.filter((_, j) => j !== bodyIndex);
    } else if (clone.body) {
      clone.body = clone.body.filter((_, j) => j !== bodyIndex);
    }
    return clone;
  });
  return { steps: next, droppedBranch: false, droppedStem: false };
}

/**
 * Replace one cell's steps, growing the notebook if the index is past the end.
 *
 * Exported and pure because it is the seam every chip mutation crosses. The
 * cell index arrives as an argument here and in every mutation that calls it —
 * *never* read from `focusedCell` — because `setFocusedCell` is a React state
 * setter and does not take effect until the next render. A handler that did
 * `setFocusedCell(i); removeStep(n)` therefore edited whichever cell was
 * focused *before* the click, so clicking a chip's × in one cell silently
 * deleted a step from another. Threading the cell makes that unrepresentable:
 * there is no ambient "current cell" for a mutation to read stale.
 *
 * **Everything about a cell except its steps is carried over**, here and for
 * the cell being edited. Rebuilding each chain as `{ steps }` dropped `peer`,
 * `publish` and the slots `publish` names from *every* cell in the notebook, so
 * clicking any chip's × unassigned the whole room — the same defect
 * `applyCellRecipeText` fixed for the text path and this seam still had. A
 * comment is now in that set too, which is why the copy is a spread rather
 * than a field list: a field added to `RecipeChain` must not need a second
 * edit here to survive being looked at sideways.
 */
export function chainsWithCellSteps(
  chains: RecipeChain[],
  cellIndex: number,
  nextSteps: RecipeStep[]
): RecipeChain[] {
  const copy: RecipeChain[] = chains.map((c) => ({ ...c, steps: [...(c.steps || [])] }));
  while (copy.length <= cellIndex) copy.push({ steps: [] });
  copy[cellIndex] = { ...(copy[cellIndex] || {}), steps: nextSteps };
  return copy;
}

/**
 * What **Upgrade recipe** would do to this text, or `null` for nothing.
 *
 * Pure, and separate from the hook, so the button's *availability* is one
 * node-testable question rather than a predicate each render site invents. The
 * rule is "the migrator would change something", not "the message mentioned
 * upgrading": the six messages that name the button are written by hand and a
 * seventh could be added without a rewrite behind it, which would put a button
 * on screen that does nothing when pressed — the failure this wiring exists to
 * remove, reintroduced one message later.
 */
export function recipeUpgrade(
  text: string
): { recipe: string; changes: { from: string; to: string; count: number }[] } | null {
  const before = String(text ?? "");
  const { recipe, changes } = migrateRecipe(before);
  if (recipe === before || !changes.length) return null;
  return { recipe, changes };
}

/** One validator complaint, anchored to a chip *within its own cell*. */
export type CellError = { message: string; stepIndex: number; when?: "compile" | "run" };

/** Same shape, lower weight: advisory, does not block Run. */
export type CellWarning = CellError;

/** What the kernel kept from a throw — see `cellRunErrorFrom`. */
export type CellRunError = { message: string; stepIndex: number; stepName: string };

/**
 * The rows a cell's error banner shows: what the run did, then what the
 * validator says.
 *
 * One list, one component, one weight. Runtime and compile failures are
 * different *sources* with the same destination — "this cell produced nothing,
 * here is why" — and giving the runtime one its own banner would have been the
 * third channel `dealByCell` was extracted to prevent: two surfaces free to
 * disagree about which chip a step is.
 *
 * The run row leads. It reports something that *happened*; a validator
 * complaint reports something that would happen. Ordering is close to
 * academic, though — `runFrom` refuses to start unless `validation.ok`, so a
 * cell that can show a run error has no compile errors to show beneath it.
 *
 * **The anchor is re-checked against the current recipe.** A compile error is
 * recomputed on every keystroke; a run error is a fact about a past run, and
 * chips renumber when you edit. So the chip lights only while the step at that
 * index still holds the op that threw. Otherwise the message stays and loses
 * its chip, which is the honest half: the run really did fail, and we no
 * longer know which chip is to blame.
 */
export function cellErrorRows(
  compileErrors: CellError[],
  runError: CellRunError | null | undefined,
  steps: StepTree[]
): CellError[] {
  if (!runError) return compileErrors || [];
  const at = runError.stepIndex;
  const host = at >= 0 ? steps?.[at] : undefined;
  // No name means the throw never reached `execStep` — `in $nope` resolves its
  // slot before dispatch. The engine's index is then the only word on the
  // subject and there is nothing to contradict it, so a live index is enough.
  const anchored = !!host && (!runError.stepName || holdsStep(host, runError.stepName));
  return [
    { message: runError.message, stepIndex: anchored ? at : -1, when: "run" },
    ...(compileErrors || []),
  ];
}

type StepTree = {
  name?: string;
  body?: StepTree[];
  branches?: { body?: StepTree[] }[];
};

/**
 * Does this top-level step still contain that op, at any depth?
 *
 * Recursive because the engine names the *innermost* thrower (`pem`) while
 * anchoring to the stem it hangs off (`tee`) — deliberately, since that is how
 * `validateRecipe` numbers a nested complaint, and the two channels have to
 * agree about which chip a step is. A flat name comparison would refuse the
 * anchor on every `foreach` and `tee` failure, which is most of the interesting
 * ones.
 */
function holdsStep(step: StepTree, name: string): boolean {
  if (!step) return false;
  if (step.name === name) return true;
  const nested = [
    ...(step.body || []),
    ...(step.branches || []).flatMap((b) => b?.body || []),
  ];
  return nested.some((k) => holdsStep(k, name));
}

/**
 * Per-cell validation errors for a whole notebook (§33c).
 *
 * Validated **in situ**: one `validateRecipe` over every cell at once, then the
 * errors are dealt back to the cell they came from. Cell-by-cell validation —
 * what this used to do — threw away the slot table each cell builds for the
 * ones below it, so a shipped multi-cell template greeted you with
 * `in $kp: unknown slot` on every `in` plus the cascade behind it (`"export"
 * needs an input`, …), before you had run anything and still after a wholly
 * successful run. That was the notebook's worst first impression, and it was
 * pure fiction: `$kp` is written one cell up.
 *
 * Validating the whole notebook is preferred over patching a producing context
 * into a per-cell call because it is *the same validation the run gate already
 * performs* (`compileRecipe(source).validation`) — so the banner and the Run
 * button can no longer hold two opinions about whether a cell is wired. It is
 * also what the engine does: `createSlotRegistry` is notebook-wide, for labels
 * and for numeric `in 1` alike, so cross-cell resolution here is not a
 * convenience but a match to runtime.
 *
 * Nothing is suppressed. A slot nothing ever writes still reports, with the
 * same wording, on the same chip: the validator sees every producer and still
 * does not find it.
 *
 * `stepIndex` anchoring is preserved exactly. `validateRecipe` numbers
 * top-level steps continuously across cells (nested body/branch errors carry
 * their top-level stem's number), so subtracting the cell's start offset
 * recovers the very index a per-cell call produced — the same chip lights up.
 */
export function cellErrorsForChains(chains: RecipeChain[]): CellError[][] {
  return dealByCell(chains, (v) => v.errors);
}

/**
 * Per-cell validation *warnings* for a whole notebook.
 *
 * The same pass, the same rebasing, one weight down. Warnings were computed on
 * every keystroke and read by nobody — including the §29f one that says an
 * `ssh.encode format=private` export is a bare private key on screen. Routing
 * them through `dealByCell` rather than a second hand-written walk is the
 * point: errors and warnings cannot land on different cells for the same
 * recipe, because there is only one implementation of "which cell is this".
 *
 * Warnings never gate Run — `validation.ok` is errors-only and stays that way.
 */
export function cellWarningsForChains(chains: RecipeChain[]): CellWarning[][] {
  return dealByCell(chains, (v) => v.warnings);
}

/**
 * Validate the whole notebook once and deal one complaint list back per cell.
 *
 * `pick` chooses which list (errors or warnings); both carry the same
 * `{ message, stepIndex }` shape and the same continuous top-level step
 * numbering, so the rebasing arithmetic is identical and lives here only.
 */
function dealByCell(
  chains: RecipeChain[],
  pick: (v: {
    errors?: { message: string; stepIndex?: number }[];
    warnings?: { message: string; stepIndex?: number }[];
  }) => { message: string; stepIndex?: number }[] | undefined
): CellError[][] {
  const out: CellError[][] = (chains || []).map(() => []);
  if (!chains?.some((c) => c?.steps?.length)) return out;

  /** Global index of each cell's first step; empty cells consume none. */
  const starts: number[] = [];
  let acc = 0;
  for (const c of chains) {
    starts.push(acc);
    acc += c?.steps?.length || 0;
  }
  const firstFilled = chains.findIndex((c) => !!c?.steps?.length);

  let items: { message: string; stepIndex?: number }[];
  try {
    items =
      pick(
        validateRecipe({ chains, steps: chains[firstFilled]?.steps || [], source: "" })
      ) || [];
  } catch {
    return out;
  }

  for (const e of items) {
    const global = typeof e.stepIndex === "number" ? e.stepIndex : -1;
    let cell = -1;
    if (global >= 0) {
      for (let i = 0; i < chains.length; i++) {
        const len = chains[i]?.steps?.length || 0;
        if (len && global >= starts[i] && global < starts[i] + len) {
          cell = i;
          break;
        }
      }
    }
    // A complaint the validator did not anchor ("Empty recipe") still has to be
    // seen — parking it unanchored on the first real cell beats dropping it.
    if (cell < 0) {
      out[firstFilled]?.push({ message: String(e.message), stepIndex: -1 });
      continue;
    }
    out[cell].push({ message: String(e.message), stepIndex: global - starts[cell] });
  }
  return out;
}

export function useNotebook() {
  const kernelRef = useRef(createKernel());
  const [title, setTitle] = useState("Untitled notebook");
  const [chains, setChains] = useState<RecipeChain[]>(emptyChains);
  const [focusedCell, setFocusedCell] = useState(0);
  const [inputText, setInputText] = useState("");
  const [ciphertext, setCiphertext] = useState("");
  const [shareRows, setShareRows] = useState<string[]>([""]);
  const [sharePassphrase, setSharePassphrase] = useState("");
  /**
   * The OpenPGP S2K passphrase — the `gpgPass` input panel.
   *
   * `input-needs.js` has derived this need since it was written, `agent.unlock`
   * and `resolveGpgPrivateKey` both read `inputs.gpg.passphrase`, and
   * `agent.save`'s refusal names "the Inputs panel" by name. Nothing ever wrote
   * it: there was no field, so a passphrase-protected key — the protection this
   * app recommends — could not sign anything here.
   */
  const [gpgPassphrase, setGpgPassphrase] = useState("");
  const [envelopeArmored, setEnvelopeArmored] = useState("");
  /** §31c — pasted JWK/PEM for `keypair`. Runtime-only, never serialized. */
  const [keypairMaterial, setKeypairMaterial] = useState("");
  const [pgpMode, setPgpMode] = useState<PgpMode>("auto");
  const [vaultKeys, setVaultKeys] = useState<VaultKeyRow[]>([]);
  const [sessionTick, setSessionTick] = useState(0);
  const [opsFilter, setOpsFilter] = useState("");
  const [runStatus, setRunStatus] = useState("");
  const [runError, setRunError] = useState("");
  const [busy, setBusy] = useState(false);
  /**
   * What a screen reader is told — deliberately a **subset** of what the run
   * status line says, and the reason it is separate state rather than a live
   * region wrapped around that line.
   *
   * The status line carries two kinds of sentence that happen to share a
   * paragraph. One is the *ticker*: `Running…`, `Running cell 3…`, rewritten
   * once per cell for as long as a run lasts. The other is *news*: the room
   * moved, a peer is no longer in it, a cell was handed over or refused, the
   * run failed and here is why. A live region around the paragraph would
   * announce both, and a twelve-cell run would interrupt a reader twelve times
   * with a fact they cannot act on — drowning the one announcement in the
   * sequence that mattered. So the ticker writes `runStatus` and nothing else,
   * and `narrate`/`refuse` below are the only doors into this.
   *
   * The counter is not decoration. A live region announces when its contents
   * *change*, so a second run ending in the same word — two `Done`s, two
   * identical refusals — would render byte-identical text and be silent the
   * second time. `ToolkitShell` re-keys the region's child on `n`, which makes
   * the repeat a real DOM mutation and therefore a real announcement.
   */
  const [announcement, setAnnouncement] = useState<{ text: string; n: number }>({
    text: "",
    n: 0,
  });
  /**
   * Announce and write nothing visible.
   *
   * The narrow door, for the two callers that append to a status line already
   * on screen: what is *new* is the appended clause, and announcing the whole
   * rebuilt line would make a reader sit through a verdict they have already
   * been told before reaching the part that is news.
   */
  const announce = useCallback((text: string) => {
    setAnnouncement((prev) => ({ text, n: prev.n + 1 }));
  }, []);
  /**
   * Say something on the status line *and* to a screen reader.
   *
   * Every caller is an event a person either caused or needs to know about:
   * the room moving, a rotation dropping a placement, an offer's outcome, a
   * run finishing. Anything that is merely where a run has got to calls
   * `setRunStatus` directly and is not announced.
   */
  const narrate = useCallback(
    (text: string) => {
      setRunStatus(text);
      announce(text);
    },
    [announce]
  );
  /**
   * The same for a refusal. Split from `narrate` only because the two write
   * different state — the shell draws `runError` in the error colour and
   * prefers it over `runStatus` — and identical because a refusal a sighted
   * reader gets is a refusal a screen-reader user gets.
   */
  const refuse = useCallback(
    (text: string) => {
      setRunError(text);
      announce(text);
    },
    [announce]
  );
  const [runProgress, setRunProgress] = useState<{ cell: number; total: number } | null>(
    null
  );
  const stopRunRef = useRef(false);
  /** Live p2p exchange snapshot (design v2 §21a) — fed by quorum-ops via window events. */
  const [quorumState, setQuorumState] = useState<QuorumUiState>({
    phase: "idle",
    room: "",
    role: "",
    invite: "",
    audience: [],
    epoch: 0,
    connected: 0,
    expected: 0,
    status: "",
    peers: [],
  });
  /**
   * Bumped whenever the pending-handoff list changes.
   *
   * A counter rather than a mirror of the list: `getPendingHandoffs` copies and
   * `takeHandoff` is the only way to remove one, so a second copy living in
   * React state would be a second place for a queue whose whole point is that
   * each document can be taken exactly once to be wrong. This says *look
   * again*; the list itself is still read from the exchange.
   */
  const [handoffTick, setHandoffTick] = useState(0);
  useEffect(() => {
    const onHandoffs = () => setHandoffTick((n) => n + 1);
    window.addEventListener("basilisk:quorum-handoffs", onHandoffs);
    return () => window.removeEventListener("basilisk:quorum-handoffs", onHandoffs);
  }, []);
  const [peerLinks, setPeerLinks] = useState<PeerLinkRow[]>([]);
  /** Cell index currently executing — lets the shell pin SessionStrip to it. */
  const [runningCell, setRunningCell] = useState<number | null>(null);
  useEffect(() => {
    const onState = (ev: Event) => {
      const detail = (ev as CustomEvent<QuorumUiState>).detail;
      if (detail) setQuorumState(detail);
    };
    window.addEventListener("basilisk:quorum-state", onState);
    return () => window.removeEventListener("basilisk:quorum-state", onState);
  }, []);
  useEffect(() => {
    const onLinks = (ev: Event) => {
      const detail = (ev as CustomEvent<{ links?: PeerLinkRow[] }>).detail;
      setPeerLinks(detail?.links || []);
    };
    window.addEventListener("basilisk:peer-links", onLinks);
    return () => window.removeEventListener("basilisk:peer-links", onLinks);
  }, []);
  const cancelQuorum = useCallback(() => {
    window.dispatchEvent(new CustomEvent("basilisk:quorum-cancel"));
  }, []);
  const [sheet, setSheet] = useState<
    "workspace" | "prefs" | "ceremony" | "sharecheck" | "integrity" | "session" | null
  >(null);
  const [kernelEpoch, setKernelEpoch] = useState(0);
  const [toolkitPrefs, setToolkitPrefsState] = useState<ToolkitPrefs>(() => getToolkitPrefs());
  const boundRecipientsRef = useRef<ResolvedRecipient[]>([]);

  const refreshVault = useCallback(async () => {
    try {
      const keys = await listKeys();
      // Inferred, not annotated: `listKeys` returns the vault's own VaultKeyMeta
      // and this narrows it to the row the notebook shows. Naming the *result*
      // type on the parameter claimed the projection was its own input.
      const rows: VaultKeyRow[] = (keys || []).map((k) => ({
        fingerprint: k.fingerprint,
        uid: k.uid,
        email: k.email,
        protection: k.protection,
        // Absent on legacy records, which are pgp — the reading `agent-ops.js`
        // and `keyring-service.js` both give it. The projection dropped this
        // and the Keyring cast it back out of a type that never had it.
        kind: k.kind || "pgp",
        // Carried so GpgKeyBinder (§39b) can warn before you sign with a key
        // that is about to expire — the vault has always known this, the
        // projection just dropped it.
        expires: k.expires ?? null,
        // §28b: the OpenSSH public line is public material and the single most
        // common thing anybody does with an ssh key. `/my-keys` offered it on
        // the row from the moment kinds landed; the notebook's projection
        // dropped it, so the Keys tray could not — and the tray is the only
        // surface now.
        publicLine: k.publicLine,
      }));
      // Session-only keys (unlocked/minted in memory, never persisted) are
      // still keys the user holds — the binder lists them so recipes can sign
      // with one. They expire with the session, which the row says plainly.
      const inVault = new Set(rows.map((r) => r.fingerprint));
      for (const s of sessionList()) {
        if (!inVault.has(s.fingerprint)) {
          rows.push({
            fingerprint: s.fingerprint,
            uid: "Session-only key",
            email: "",
            protection: "session",
            expires: s.expiresAt,
            // No vault record to read a kind from, so the id shape answers it.
            kind: vaultKindFromId(s.fingerprint),
          });
        }
      }
      setVaultKeys(rows);
    } catch {
      setVaultKeys([]);
    }
  }, []);

  useEffect(() => {
    void refreshVault();
  }, [refreshVault, sessionTick]);

  /**
   * The chain list as it stands right now, for a caller that must not be
   * rebuilt between keystrokes.
   *
   * `notebookRef` further down keeps `{title, source}` for the arrival path and
   * gives the argument at length; this is the same trick for the same reason,
   * over the structure the rewrites below actually edit. Text would not do:
   * `dropDepartedPlacements` produces `setCellPeer` edits addressed by cell index, and
   * re-deriving the chains from source to find those indices would be a second
   * parse of a notebook this hook already holds parsed.
   *
   * **It is declared here, above `loadRecipeText`, and that position is
   * load-bearing** for the same reason `handoffWho`'s is: it sat six hundred
   * lines down, beside `dropDepartedPlacements`, and the loader below needs to know how
   * many cells the *outgoing* notebook had. Reading `chains` there instead would
   * put the whole notebook in `loadRecipeText`'s dependency list, and that
   * callback is what `considerProposal` is built on — so every keystroke would
   * re-decide a peer's pending proposal.
   */
  const chainsRef = useRef(chains);
  useEffect(() => {
    chainsRef.current = chains;
  });

  /**
   * Compile `text` and replace the notebook's title/chains with it. Returns
   * whether it parsed.
   *
   * **This opens a different notebook, so the kernel's per-cell state goes with
   * the old one.** It used to replace `chains` and tell the kernel nothing,
   * which left every status, timing, run error and artifact tile attached to
   * its *index* while the cell underneath that index became somebody else's.
   * The visible form was a freshly adopted cell reading "ran 0s ago · 293ms"
   * with the previous notebook's `$session` tile under it, on a machine that
   * had never run it — see `placed-journey.e2e.js` step 6, which is where it
   * was found.
   *
   * `clearCellOutputs` rather than `markAllWithOutputsStale` or `remapCells`,
   * and the difference is what each of the three claims. Stale says "this was
   * computed from something that has since changed", which presumes the tile is
   * still *this cell's* answer; it is not, and marking it would leave the same
   * lie one shade quieter. A remap presumes a correspondence between old index
   * and new, and there is none — index 1 was `quorum.join` a second ago and is a
   * placed cell now. Clearing says the only true thing: this cell has no last
   * run here. It is also the one of the three that wipes the artifacts it drops.
   *
   * Slots are deliberately untouched. They are values this machine holds, not
   * claims about cells — the joiner's own `$me` is still theirs after adopting,
   * and `acceptHandoff` registers into the same registry. Discarding those is
   * Clear session's job and it says so.
   *
   * The sweep runs past the incoming notebook's length because a shorter one
   * would leave the tail buckets alive and invisible, waiting for the notebook
   * to grow back into them — the same defect, deferred.
   */
  const loadRecipeText = useCallback((title: string, text: string) => {
    const { ast } = compileRecipe(text);
    if (!ast) return false;
    const next = ast.chains?.length ? ast.chains : [{ steps: ast.steps || [] }];
    for (let i = 0; i < Math.max(chainsRef.current.length, next.length); i++) {
      kernelRef.current.clearCellOutputs?.(i);
    }
    setKernelEpoch((n) => n + 1);
    setTitle(title);
    setChains(next);
    setFocusedCell(0);
    return true;
  }, []);

  const loadFromHash = useCallback(() => {
    const action = parseToolkitHash(window.location.hash || "");
    // `unknown` alongside `empty`: a hash this build does not recognise names
    // nothing to load, and neither carries a seed. Stated rather than left to
    // fall past the three branches, so the seed below can read `inputs` at all.
    //
    // `join` is here for a stronger reason than "carries no seed": an invite
    // must never load a notebook. Both ends holding the same text and proving it
    // by digest is what makes a shared run a reproducible build, and a link that
    // opened a session *and* replaced your notebook would decide that for you
    // while you were clicking something else. The shell reads `#j=` for itself
    // and opens the session sheet; nothing here does.
    //
    // The recipe does now travel — signed, over the session, and adopted through
    // `considerProposal` below. That is not this rule being relaxed: it is the
    // mechanism the rule always presumed and never had. A joiner used to arrive
    // with an empty notebook and refuse every cell handed to them, against a
    // manifest derived from the emptiness. What changed is that one end may
    // receive the text, from a named peer, visibly; the digest check on every
    // handed-over cell is untouched.
    //
    // `tray` for the milder version of the same rule: `#keys` asks for a panel,
    // and opening the vault is not a reason to discard the notebook somebody
    // was already writing. The shell reads it, as it does `#j=`.
    if (
      !action ||
      action.kind === "empty" ||
      action.kind === "unknown" ||
      action.kind === "join" ||
      action.kind === "tray"
    ) {
      return;
    }
    /**
     * The `ct=` seed, applied whatever the link named.
     *
     * `attachCiphertextSeed` in `fragment.js` hangs `inputs` off *any* action,
     * so `#preset=gpg-decrypt&ct=…` carries a ciphertext exactly as
     * `#decrypt&ct=…` does. This used to live inside the starter branch, which
     * returns before the other two run, so every non-starter link dropped it.
     *
     * It is also spelled the way the writer spells it. The read was
     * `inputs.ciphertext` and nothing has ever written that field, so the seed
     * did not arrive even for a starter — the one case this branch handled.
     */
    const ctSeed = String(action.inputs?.ctArmored || "");
    const seedCiphertext = () => {
      if (ctSeed) setCiphertext(ctSeed);
    };
    if (action.kind === "starter") {
      const starter = MESSAGING_STARTERS[action.starter];
      if (!starter) return;
      loadRecipeText(starter.title, starter.recipe);
      seedCiphertext();
      return;
    }
    if (action.kind === "preset") {
      const p = PRESETS.find((x: { id: string }) => x.id === action.id);
      if (!p) return;
      loadRecipeText(p.title, p.recipe);
      seedCiphertext();
      return;
    }
    if (action.kind === "recipe") {
      loadRecipeText("Shared notebook", action.recipe);
      seedCiphertext();
    }
  }, [loadRecipeText]);

  useEffect(() => {
    loadFromHash();
    const onHash = () => loadFromHash();
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, [loadFromHash]);

  const source = useMemo(() => serializeRecipe(chains), [chains]);

  const compiled = useMemo(() => compileRecipe(source), [source]);

  const unmetForCell = useCallback(
    (cellIndex: number): string[] => {
      const chain = chains[cellIndex];
      if (!chain?.steps?.length) return [];
      const badges: string[] = [];
      const needs = cellInputNeeds(chain);
      // A need an earlier cell's outputs can satisfy is wired, not missing —
      // running the cells above materializes it (slot-graph checkpoint
      // semantics). Only genuinely unproducible inputs gate.
      const { wiredNeeds } = wiredForCell(chains, cellIndex);
      if (needs.includes("text") && !inputText.trim()) badges.push("needs input");
      if (needs.includes("gpg") && !ciphertext.trim()) badges.push("needs ciphertext");
      if (needs.includes("key")) badges.push("needs key");
      if (
        needs.includes("shares") &&
        !shareRows.some((s) => s.trim()) &&
        !wiredNeeds.has("shares")
      ) {
        badges.push("needs shares");
      }
      if (needs.includes("envelope") && !envelopeArmored.trim()) {
        badges.push("needs envelope");
      }
      if (needs.includes("keypair") && !keypairMaterial.trim()) {
        badges.push("needs key material");
      }
      const slots = cellRecipientSlots(chain);
      const filled = boundRecipientsRef.current.filter((r) => r?.fingerprint).length;
      if (slots > 0 && filled < slots) badges.push("needs recipients");
      return badges;
    },
    [
      chains,
      inputText,
      ciphertext,
      shareRows,
      envelopeArmored,
      keypairMaterial,
      sessionTick,
      kernelEpoch,
    ]
  );

  const blockerTextFor = (badge: string): string =>
    badge === "needs input"
      ? "Add input text before running"
      : badge === "needs ciphertext"
        ? "Paste OpenPGP ciphertext before running"
        : badge === "needs recipients"
          ? "Add recipients before running"
          : badge;

  // Only the FIRST runnable cell can block starting a run. Later cells are
  // checkpoints: runFrom executes up to the first cell whose needs are still
  // unmet at that moment and pauses there, keeping everything already
  // produced — a companion cell waiting on inputs must never prevent the
  // cell that would produce them from running.
  const readinessBlocker = useMemo(() => {
    for (let i = 0; i < chains.length; i++) {
      if (!chains[i]?.steps?.length) continue;
      const u = unmetForCell(i);
      return u[0] ? blockerTextFor(u[0]) : "";
    }
    return "";
  }, [chains, unmetForCell]);

  const slotMetas: SlotMeta[] = useMemo(() => {
    void kernelEpoch;
    return (kernelRef.current.listSlots?.() || []).map(
      (m: {
        label: string;
        type?: string;
        fingerprint?: string;
        sensitive?: boolean;
        recipients?: number;
        length?: number;
      }) => ({
        label: String(m.label || "").replace(/^\$/, ""),
        type: String(m.type || "unknown"),
        fingerprint: m.fingerprint,
        sensitive: !!m.sensitive,
        recipients: m.recipients,
        length: m.length,
      })
    );
  }, [kernelEpoch]);

  const cellStatuses: CellStatus[] = useMemo(() => {
    void kernelEpoch;
    return chains.map((_, i) => kernelRef.current.getCellStatus(i) as CellStatus);
  }, [chains, kernelEpoch]);

  /**
   * Why the last run of each cell failed — the runtime half of the cell's
   * error banner. Read off the kernel on `kernelEpoch` like the statuses and
   * timings beside it, which `runFrom` already bumps in its catch.
   */
  const cellRunErrors: (CellRunError | null)[] = useMemo(() => {
    void kernelEpoch;
    return chains.map((_, i) => kernelRef.current.getCellRunError?.(i) ?? null);
  }, [chains, kernelEpoch]);

  /** Last successful run's timestamp/duration per cell — drives the status-dot line. */
  const cellTimings: ({ ranAt: number; durationMs: number } | null)[] = useMemo(() => {
    void kernelEpoch;
    return chains.map((_, i) => kernelRef.current.getCellTiming?.(i) ?? null);
  }, [chains, kernelEpoch]);

  /**
   * What each cell's last run here read, wrote and received — the kernel's
   * per-cell record, read on `kernelEpoch` like the statuses and timings
   * beside it. The cell draws its provenance line from this (finding 7a: a
   * recovering machine must be able to say whose shares rebuilt the secret,
   * and this is where the senders' fingerprints reach something on screen).
   */
  const cellProvenance: (CellProvenance | null)[] = useMemo(() => {
    void kernelEpoch;
    return chains.map((_, i) => kernelRef.current.getCellProvenance?.(i) ?? null);
  }, [chains, kernelEpoch]);

  /**
   * Type/validation errors per cell (§33c).
   *
   * These were previously only reachable by running: the validator knew the
   * pipeline was ill-typed, but nothing surfaced it until the engine threw.
   * `stepIndex` anchors each error to the chip that caused it, so the banner
   * can name the step rather than describing the cell.
   *
   * See `cellErrorsForChains` for why the notebook is validated whole.
   */
  const cellErrors: CellError[][] = useMemo(() => {
    void kernelEpoch;
    return cellErrorsForChains(chains);
  }, [chains, kernelEpoch]);

  /**
   * Advisory warnings per cell — the same validator pass, one weight down.
   *
   * Deliberately *not* folded into `cellErrors`: an error blocks Run and a
   * warning does not, and a channel that shows both at the same weight teaches
   * that neither needs reading. Kept as its own list so the presentation can
   * differ and so nothing here can ever reach `validation.ok`.
   */
  const cellWarnings: CellWarning[][] = useMemo(() => {
    void kernelEpoch;
    return cellWarningsForChains(chains);
  }, [chains, kernelEpoch]);

  const cellOutputs: ArtifactTile[][] = useMemo(() => {
    void kernelEpoch;
    return chains.map((_, i) =>
      (kernelRef.current.getCellOutputs(i) || []).map((a: ArtifactTile) => ({
        label: a.label,
        filename: a.filename,
        content: String(a.content ?? ""),
        sensitive: !!a.sensitive,
        // Carried through explicitly: this projection copies named fields, so
        // anything the engine adds is dropped here until it is listed.
        revealable: !!a.revealable,
        role: a.role,
        traits: a.traits,
        publishedAs: a.publishedAs,
        directoryUrl: a.directoryUrl,
        netType: a.netType,
        netKind: a.netKind,
        netData: a.netData,
        // Structured `inspect` body. The engine withholds this for sensitive
        // tips on purpose (a snapshot would retain raw private JWK fields the
        // masked text dump does not), so its absence is meaningful, not a gap.
        inspectSnapshot: a.inspectSnapshot,
        jose: a.jose,
        // The decrypt verdict, for `jose`'s reason. Named here as well as in
        // the shell's two projections because that is what it takes to reach a
        // tile — the OTP fields shipped through one of the three and rendered
        // nowhere.
        signature: a.signature,
        // §32/1.4: the fields the kind registry matches and renders on. The
        // refined type has ridden on every artifact as `pipeType` since the
        // type system landed, and this projection dropped it — which is why
        // the UI grew `netType`/`jose`/`inspectSnapshot` as parallel
        // discriminators for a discriminator it already had.
        pipeType: a.pipeType,
        tags: a.tags,
        shareIndex: a.shareIndex,
        mime: a.mime,
        encoding: a.encoding,
        bytes: a.bytes,
        stepName: a.stepName,
        disposition: a.disposition,
      }))
    );
  }, [chains, kernelEpoch]);

  /**
   * Publish a key-export output to This site's directory (design v2 §21b).
   * Only meaningful for `role: "public-key"` tiles. Mutates the kernel-held
   * artifact tile in place (not local UI state) so `publishedAs`/`directoryUrl`
   * survive re-renders same as any other cell-output field; cleared on
   * Clear session same as the rest of `cellOutputs`.
   */
  const publishArtifact = useCallback(async (cellIndex: number, outputIndex: number) => {
    const tile = kernelRef.current.getCellOutputs(cellIndex)?.[outputIndex] as
      | ArtifactTile
      | undefined;
    if (!tile) throw new Error("publishArtifact: unknown output");
    // `public-key` is now every public half's role, not OpenPGP's alone, so
    // the role on its own no longer implies "armored and publishable". The
    // `openpgp` tag is what narrows it back to the one kind that declares
    // `key.publish`; `publishArmoredKey` refuses non-armor after this, so the
    // two guards still agree in two places rather than one.
    if (tile.role !== "public-key" || !(tile.tags || []).includes("openpgp")) {
      throw new Error("publishArtifact: only OpenPGP public keys are publishable");
    }
    const { publishArmoredKey } = await import("../lib/toolkit/hkp-ops.js");
    const { fingerprint, directoryUrl } = await publishArmoredKey(tile.content);
    tile.publishedAs = fingerprint ? `@${fingerprint.slice(-8)}` : "$pub";
    tile.directoryUrl = directoryUrl;
    setKernelEpoch((n) => n + 1);
    // Returned, not just stored: the Activity log records where an outward
    // action *went* (§36), and a log that says "Published" without naming the
    // directory answers the wrong half of the question at 2am.
    return { fingerprint, directoryUrl };
  }, []);

  const setCellSteps = useCallback((cellIndex: number, nextSteps: RecipeStep[]) => {
    setChains((prev) => chainsWithCellSteps(prev, cellIndex, nextSteps));
  }, []);

  /**
   * The steps of a *named* cell. Every mutation below starts here rather than
   * from a `steps` projection of `focusedCell`: the caller says which cell it
   * means, so a mutation can no longer land on whichever cell happened to be
   * focused when its closure was made. Callers that genuinely mean "wherever
   * the caret is" pass `focusedCell` themselves, at the call site, where it is
   * read from the current render rather than from a setter that has not run.
   */
  const stepsAt = useCallback(
    (cell: number): RecipeStep[] => chains[cell]?.steps || [],
    [chains]
  );

  const makeStep = useCallback(
    (opName: string, opts?: { decode?: boolean; params?: RecipeParams }) => {
      const spec = getStep(opName);
      if (!spec) return null;
      const step: RecipeStep = { name: opName, params: { ...(opts?.params || {}) } };
      for (const p of spec.params || []) {
        if (step.params![p.name] === undefined && p.default !== undefined) {
          step.params![p.name] = p.default;
        }
      }
      if (opts?.decode) step.params!.decode = true;
      return step;
    },
    []
  );

  const appendOp = useCallback(
    (
      cell: number,
      opName: string,
      opts?: { decode?: boolean; params?: RecipeParams }
    ) => {
      const step = makeStep(opName, opts);
      if (!step) return;
      setCellSteps(cell, [...stepsAt(cell), step]);
    },
    [makeStep, setCellSteps, stepsAt]
  );

  const insertOpAt = useCallback(
    (
      cell: number,
      index: number,
      opName: string,
      opts?: { decode?: boolean; params?: RecipeParams }
    ) => {
      const step = makeStep(opName, opts);
      if (!step) return;
      const steps = stepsAt(cell);
      const at = Math.max(0, Math.min(steps.length, index));
      const next = [...steps.slice(0, at), step, ...steps.slice(at)];
      setCellSteps(cell, next);
    },
    [makeStep, setCellSteps, stepsAt]
  );

  /** Append (or insert at body index) inside a tee/foreach nest. */
  const nestOp = useCallback(
    (
      cell: number,
      stem: number,
      branch: number | null,
      opName: string,
      opts?: { decode?: boolean; params?: RecipeParams; at?: number }
    ) => {
      // Nested tee/foreach/scatter is rejected by the parser (RECIPE.md, v1).
      // The shelf already hides them for nested carets; this catches drag-drops.
      if (opName === "tee" || opName === "foreach" || opName === "scatter") return;
      const step = makeStep(opName, opts);
      if (!step) return;
      const next = stepsAt(cell).map((s, i) => {
        if (i !== stem) return s;
        const clone: RecipeStep = {
          ...s,
          body: s.body ? [...s.body] : undefined,
          branches: s.branches?.map((b) => ({
            ...b,
            body: b.body ? [...b.body] : [],
          })),
        };
        if (branch != null) {
          const br = clone.branches?.[branch];
          if (!br) return s;
          const body = [...(br.body || [])];
          const at =
            opts?.at != null
              ? Math.max(0, Math.min(body.length, opts.at))
              : body.length;
          body.splice(at, 0, step);
          br.body = body;
        } else {
          const body = [...(clone.body || [])];
          const at =
            opts?.at != null
              ? Math.max(0, Math.min(body.length, opts.at))
              : body.length;
          body.splice(at, 0, step);
          clone.body = body;
        }
        return clone;
      });
      setCellSteps(cell, next);
    },
    [makeStep, setCellSteps, stepsAt]
  );

  /**
   * Create a selector branch on a tee *together with* its first step. A branch
   * is not valid recipe text until it has a step (`- :public |` alone doesn't
   * parse), so the two land as one mutation — the UI "arms" the branch
   * client-side until then, same as activeGap.
   */
  const addBranchWithStep = useCallback(
    (
      cell: number,
      stem: number,
      selector: string,
      opName: string,
      opts?: { decode?: boolean; params?: RecipeParams }
    ) => {
      const step = makeStep(opName, opts);
      if (!step) return;
      // A keypair half is a step, so the menu writes a step. Anything else is
      // still a branch prefix — the same split the parser makes, and it has to
      // be the same one or a branch inserted here would re-shape itself the
      // first time the cell was parsed back from its own text.
      const folded = selector === ":public" || selector === ":private";
      const next = stepsAt(cell).map((s, i) => {
        if (i !== stem) return s;
        const branches = [...(s.branches || [])];
        branches.push(
          folded
            ? { member: "", body: [{ name: "select", params: { selector } }, step] }
            : { selector, member: selector.replace(/^:/, ""), body: [step] }
        );
        return { ...s, branches };
      });
      setCellSteps(cell, next);
    },
    [makeStep, setCellSteps, stepsAt]
  );

  /** Swap one stem step for another op ("peek instead of an empty tee"). */
  const replaceStep = useCallback(
    (cell: number, stem: number, opName: string) => {
      const steps = stepsAt(cell);
      const step = makeStep(opName);
      if (!step || !steps[stem]) return;
      setCellSteps(
        cell,
        steps.map((s, i) => (i === stem ? step : s))
      );
    },
    [makeStep, setCellSteps, stepsAt]
  );

  const updateNestStepParams = useCallback(
    (
      cell: number,
      stem: number,
      branch: number | null,
      bodyIndex: number,
      name: string,
      value: string | number | boolean
    ) => {
      const next = stepsAt(cell).map((s, i) => {
        if (i !== stem) return s;
        const clone: RecipeStep = {
          ...s,
          body: s.body ? [...s.body] : undefined,
          branches: s.branches?.map((b) => ({
            ...b,
            body: b.body ? [...b.body] : [],
          })),
        };
        const list =
          branch != null ? clone.branches?.[branch]?.body : clone.body;
        if (!list || !list[bodyIndex]) return s;
        list[bodyIndex] = {
          ...list[bodyIndex],
          params: { ...(list[bodyIndex].params || {}), [name]: value },
        };
        return clone;
      });
      setCellSteps(cell, next);
    },
    [setCellSteps, stepsAt]
  );

  /**
   * Remove one nested step. Returns what else went with it — a branch left with
   * no steps cannot be serialized, so it cascades (see
   * `stepsWithNestStepRemoved`) and the caller says so out loud.
   */
  const removeNestStep = useCallback(
    (cell: number, stem: number, branch: number | null, bodyIndex: number) => {
      const steps = stepsAt(cell);
      const next = stepsWithNestStepRemoved(steps, stem, branch, bodyIndex);
      if (next.steps === steps) return { droppedBranch: false, droppedStem: false };
      setCellSteps(cell, next.steps);
      return { droppedBranch: next.droppedBranch, droppedStem: next.droppedStem };
    },
    [setCellSteps, stepsAt]
  );

  /**
   * Remove a whole selector branch from a tee. Returns true when the tee stem
   * was dropped along with its last branch (see `stepsWithBranchRemoved`), so
   * the caller can say that out loud and offer the undo.
   */
  const removeBranch = useCallback(
    (cell: number, stem: number, branch: number) => {
      const steps = stepsAt(cell);
      const next = stepsWithBranchRemoved(steps, stem, branch);
      if (next.steps === steps) return false;
      setCellSteps(cell, next.steps);
      return next.droppedStem;
    },
    [setCellSteps, stepsAt]
  );

  const reorderStem = useCallback(
    (cell: number, from: number, to: number) => {
      const steps = stepsAt(cell);
      if (from === to || from < 0 || from >= steps.length) return;
      const next = [...steps];
      const [moved] = next.splice(from, 1);
      let insertAt = to;
      if (from < to) insertAt = to - 1;
      insertAt = Math.max(0, Math.min(next.length, insertAt));
      next.splice(insertAt, 0, moved);
      setCellSteps(cell, next);
    },
    [setCellSteps, stepsAt]
  );

  /** Reorder within a tee/foreach body or selector branch. `toBody` is gap splice index. */
  const reorderNest = useCallback(
    (
      cell: number,
      stem: number,
      branch: number | null,
      fromBody: number,
      toBody: number
    ) => {
      if (fromBody === toBody) return;
      const next = stepsAt(cell).map((s, i) => {
        if (i !== stem) return s;
        const clone: RecipeStep = {
          ...s,
          body: s.body ? [...s.body] : undefined,
          branches: s.branches?.map((b) => ({
            ...b,
            body: b.body ? [...b.body] : [],
          })),
        };
        const list =
          branch != null ? clone.branches?.[branch]?.body : clone.body;
        if (!list || fromBody < 0 || fromBody >= list.length) return s;
        const body = [...list];
        const [moved] = body.splice(fromBody, 1);
        let insertAt = toBody;
        if (fromBody < toBody) insertAt = toBody - 1;
        insertAt = Math.max(0, Math.min(body.length, insertAt));
        body.splice(insertAt, 0, moved);
        if (branch != null && clone.branches?.[branch]) {
          clone.branches[branch].body = body;
        } else {
          clone.body = body;
        }
        return clone;
      });
      setCellSteps(cell, next);
    },
    [setCellSteps, stepsAt]
  );

  const updateStepParams = useCallback(
    (
      cell: number,
      stepIndex: number,
      name: string,
      value: string | number | boolean
    ) => {
      const next = stepsAt(cell).map((s, i) =>
        i === stepIndex
          ? { ...s, params: { ...(s.params || {}), [name]: value } }
          : s
      );
      setCellSteps(cell, next);
    },
    [setCellSteps, stepsAt]
  );

  const removeStep = useCallback(
    (cell: number, stepIndex: number) => {
      setCellSteps(
        cell,
        stepsAt(cell).filter((_, i) => i !== stepIndex)
      );
    },
    [setCellSteps, stepsAt]
  );

  const insertMessaging = useCallback((kind: "encrypt" | "decrypt" | "symencrypt") => {
    const starter = MESSAGING_STARTERS[kind];
    if (!starter) return;
    const { ast } = compileRecipe(starter.recipe);
    if (!ast) return;
    setTitle(starter.title);
    setChains(ast.chains?.length ? ast.chains : [{ steps: ast.steps || [] }]);
    setFocusedCell(0);
    window.location.hash = `#${kind}`;
  }, []);

  const loadPreset = useCallback((id: string) => {
    const p = PRESETS.find((x: { id: string }) => x.id === id);
    if (!p) return;
    const { ast } = compileRecipe(p.recipe);
    if (!ast) return;
    setTitle(p.title);
    setChains(ast.chains?.length ? ast.chains : [{ steps: ast.steps || [] }]);
    setFocusedCell(0);
  }, []);

  /** Restore an exact prior title/chains snapshot — used by the one-shot "Undo" after Load. */
  const restoreNotebook = useCallback((title: string, chains: RecipeChain[]) => {
    setTitle(title);
    setChains(chains);
    setFocusedCell(0);
  }, []);

  const appendPreset = useCallback((id: string) => {
    const p = PRESETS.find((x: { id: string }) => x.id === id);
    if (!p) return;
    const { ast } = compileRecipe(p.recipe);
    if (!ast) return;
    const loaded: RecipeChain[] = (ast.chains?.length
      ? ast.chains
      : [{ steps: ast.steps || [] }]
    ).map((c: RecipeChain) => ({ ...c, steps: [...(c.steps || [])] }));
    if (!loaded.length) return;
    setChains((prev) => {
      if (prev.length === 1 && !(prev[0].steps || []).length) {
        setFocusedCell(0);
        return loaded;
      }
      const start = prev.length;
      setFocusedCell(start);
      return [...prev, ...loaded];
    });
    if (!title || title === "Untitled notebook") setTitle(p.title);
  }, [title]);

  const appendPresetPair = useCallback((pairId: string) => {
    const pair = resolvePresetPair(pairId);
    if (!pair) return null;
    const st = stitchPresetPair(pair.forward, pair.reverse);
    if (st.errors?.length) {
      refuse(st.errors.join(" · "));
      return null;
    }
    const { ast } = compileRecipe(st.recipe);
    if (!ast) return null;
    const loaded: RecipeChain[] = (ast.chains?.length
      ? ast.chains
      : [{ steps: ast.steps || [] }]
    ).map((c: RecipeChain) => ({ ...c, steps: [...(c.steps || [])] }));
    if (!loaded.length) return null;
    const pairTitle = `${pair.forward.title} ⇄ ${pair.reverse.title}`;
    setChains((prev) => {
      if (prev.length === 1 && !(prev[0].steps || []).length) {
        setFocusedCell(0);
        return loaded;
      }
      const start = prev.length;
      setFocusedCell(start);
      return [...prev, ...loaded];
    });
    setTitle(pairTitle);
    const meta = bridgeModeMeta(st.mode, st.bridge);
    narrate(meta.toast);
    setRunError("");
    return st;
  }, [narrate, refuse]);

  const applyCellRecipeText = useCallback((cellIndex: number, text: string) => {
    const { ast, validation } = compileRecipe(text);
    // Only a *parse* failure is refused. A recipe that parses but does not
    // type-check is still the recipe the author wrote, and rejecting it
    // wholesale meant you could not type an ill-typed pipeline at all — the
    // edit silently reverted and a page-level line explained why. That made
    // the per-cell type-error banner unreachable from the Source view by
    // construction: there was no way to *be* in the state it describes.
    // Accept it, let it sit there, and let the banner name the problem.
    if (!ast) {
      refuse(
        (validation?.errors || [])
          .map((e: { message?: string }) => e.message || String(e))
          .join(" · ") || "Recipe parse failed"
      );
      return false;
    }
    // Validation errors now belong to the cell's own banner, so clear the
    // page-level line rather than saying the same sentence in two places.
    setRunError("");
    const chain = ast.chains?.[0] || { steps: ast.steps || [] };
    setChains((prev) => {
      const next = [...prev];
      // `peer` comes with the chain and has to be carried over. Rebuilding from
      // `steps` alone dropped it, which made a `@peer` header impossible to
      // write anywhere in the product: the grammar reads it
      // (`recipe-parse.js` sets `chain.peer`), `serializeChain` writes it back
      // out, `planRun` places cells by it and `placementGate` enforces it — and
      // this one assignment threw it away between the parse and the state, so
      // typing `@mara` parsed cleanly and then vanished. What the cell
      // publishes needs no such care any more: it is a `publish` step, so it
      // rides in `steps` like every other step.
      next[cellIndex] = {
        steps: [...(chain.steps || [])],
        ...(chain.peer == null ? {} : { peer: chain.peer }),
        // The `#` lines the author just typed. They come off the parse like the
        // header does, and dropping them here would mean a comment survived
        // `serializeRecipe` and died on the way back into the notebook — the
        // same round trip, one layer out.
        ...(chain.comments?.length ? { comments: [...chain.comments] } : {}),
      };
      return next;
    });
    setRunError("");
    return true;
  }, [refuse]);

  /**
   * Assign a cell to a peer, or take the assignment off.
   *
   * The header was reachable only by typing it, which made placement a feature
   * you had to already know the grammar to use. This is the same edit the text
   * makes — it sets the field `serializeChain` writes as `@peer`, and the
   * steps it writes as `publish` — so the two views cannot drift: there is one
   * representation and both surfaces move it.
   *
   * `peer: null` clears the header rather than writing an empty one. An
   * unassigned cell has no `peer` field at all, which is what `planRun` reads
   * as "everyone", and a `@` with nothing after it is not a recipe.
   *
   * `publishSlots` says which of the cell's `out` slots leave, and it is
   * written into the **steps** — one `publish` after each named `out` — because
   * that is where the claim lives now. `setPublishedSlots` makes the edit so
   * that this and the source view make the identical one; a second walk here
   * would be a second opinion about what a cell discloses.
   *
   * Publishing is only meaningful alongside a peer — it says this cell's output
   * may leave the machine that made it — so clearing the peer clears every
   * `publish` step with it rather than leaving a claim attached to nobody, and
   * a cell that kept one would not compile.
   */
  const setCellPeer = useCallback(
    (cellIndex: number, peer: string | null, publishSlots: string[] = []) => {
      setChains((prev) => {
        const next = [...prev];
        const chain = next[cellIndex];
        if (!chain) return prev;
        const { peer: _p, ...rest } = chain;
        const steps = setPublishedSlots(chain.steps || [], peer ? publishSlots : []);
        next[cellIndex] = peer ? { ...rest, steps, peer } : { ...rest, steps };
        return next;
      });
    },
    []
  );

  /**
   * Apply **Upgrade recipe** to one cell, from either view.
   *
   * `migrateRecipe` had no caller in the UI at all, while six error messages
   * — `legacyRemovalHint`'s five and `RETIRED_PARAM_VALUES`' one — told the
   * reader to "Upgrade recipe to migrate". That is the defect `723b95b` fixed
   * for the SSH passphrase message, which named a field in the Inputs panel
   * that did not exist: a remedy pointing at a control nobody can press is
   * worse than no remedy, because the reader spends their time hunting for it.
   *
   * `text` is passed when the source view holds an unapplied draft — the
   * legacy tokens are in the textarea and were *refused* by
   * `applyCellRecipeText`, so they are not in `chains` and `cellRecipeSource`
   * cannot see them. Omit it in the chip view, where the cell parsed and the
   * complaint is a retired *param value* (`file.read as=auto`) that survives
   * a round trip through `serializeRecipe`.
   *
   * Returns the changes so the caller can say what it did; `null` when there
   * was nothing to rewrite, so the button is never offered on a recipe the
   * migrator would leave alone.
   */
  const upgradeCellRecipe = useCallback(
    (cellIndex: number, text?: string) => {
      const before =
        text ?? serializeRecipe([chains[cellIndex] || { steps: [] }]);
      const upgrade = recipeUpgrade(before);
      if (!upgrade) return null;
      if (!applyCellRecipeText(cellIndex, upgrade.recipe)) return null;
      // Named, not silent. A migration that renamed four steps and said
      // nothing is indistinguishable from a button that did not work, and the
      // rewrite is exactly the kind of change a reader wants to audit before
      // pressing Run — `migrateRecipe` returns the counts for this.
      narrate(
        `Upgraded: ${upgrade.changes
          .map((c) => `${c.from} → ${c.to}${c.count > 1 ? ` ×${c.count}` : ""}`)
          .join(", ")}`
      );
      return upgrade;
    },
    [chains, applyCellRecipeText, narrate]
  );

  const cellRecipeSource = useCallback(
    (cellIndex: number) =>
      serializeRecipe([chains[cellIndex] || { steps: [] }]),
    [chains]
  );

  const addCell = useCallback(() => {
    setChains((prev) => {
      const next = [...prev, { steps: [] }];
      setFocusedCell(next.length - 1);
      return next;
    });
  }, []);

  /**
   * Append `text` as one or more cells and focus the first of them.
   *
   * Appends rather than replacing, because the caller has something to add to
   * the notebook rather than a notebook to open — `loadRecipeText` is the other
   * one. It exists so a surface can put a recipe in front of a person **without
   * running it**: writing a playbook means signing, and `attest.js` states the
   * rule this follows — the recipe is the thing somebody reads before pressing
   * Run, and a signer buried behind a button signs without anybody having read
   * one. So the button writes the cell and the person presses Run.
   *
   * Returns false when the text does not parse, leaving the notebook alone.
   */
  const appendRecipeCell = useCallback((text: string) => {
    const { ast } = compileRecipe(text);
    const added = ast?.chains?.length ? ast.chains : ast ? [{ steps: ast.steps || [] }] : [];
    if (!added.length) return false;
    setChains((prev) => {
      // A single empty cell is what a fresh notebook is, and appending after it
      // would leave a blank cell above the thing the person just asked for.
      const base = prev.length === 1 && !prev[0]?.steps?.length ? [] : prev;
      const next = [...base, ...added.map((c) => ({ ...c, steps: [...(c.steps || [])] }))];
      setFocusedCell(base.length);
      return next;
    });
    return true;
  }, []);

  /**
   * Remove one cell, and move the kernel's per-cell buckets up behind it.
   *
   * **Both halves, because the notebook renumbers and the kernel does not.**
   * This used to clear the deleted index and stop, which is right for the cell
   * that went and wrong for every cell under it: outputs, status, timing and run
   * error are keyed by index, so deleting cell 0 of a three-cell notebook that
   * had run left the cell now drawn as `[0]` reading "never run" and the cell
   * now drawn as `[1]` reading "ran 0s ago · 7ms" with the tile `@b` under a
   * recipe that says `out $c` — the cell above's answer, on a cell that never
   * produced it. The third bucket was orphaned at an index the notebook no
   * longer had, wiped by nothing. It is the drift `f990efd` fixed for adoption,
   * arriving through the other mutation that changes what index means.
   *
   * `clearCellOutputs` **then** `remapCells`, and the order is the argument for
   * using both rather than either. `remapCells` moves buckets and does not wipe
   * them — a mapping that dropped the deleted index would release the artifacts
   * at it without zeroizing the bytes they own, which for a cell that produced a
   * share is the one thing this kernel is careful about. So the clear does the
   * wiping first and the remap does the arithmetic after, on a map the deleted
   * bucket has already left. The `null` arm is kept even though it can no longer
   * fire: without it a bucket at `index` would map to `index` and collide with
   * the one shifting down into it, and that is a property of the mapping rather
   * than of what ran before it.
   *
   * Nothing is marked stale. A cell that moved up is still holding *its own*
   * last answer, computed here, from inputs this delete did not touch — that is
   * exactly what `markAllWithOutputsStale` is for after a *reorder*, where the
   * pipeline above a cell changes. Deleting a producer can invalidate what a
   * cell below it read, but the honest report of that is the validator's unknown
   * slot on the next keystroke, not a status dot claiming the tile was recomputed.
   *
   * The remap is skipped when nothing was removed: a notebook is never zero
   * cells, so deleting the only one empties it in place (the ✕ is inert then and
   * says why), and shifting indices down for a notebook that did not shrink
   * would be the same defect written the other way round.
   */
  const deleteCell = useCallback((index: number) => {
    // Read off `chainsRef` rather than from inside the updater below: the kernel
    // is not React state, and a mutation performed inside a state updater runs
    // however many times React chooses to call it.
    const shrinks = chainsRef.current.length > 1;
    setChains((prev) => {
      if (prev.length <= 1) return [{ steps: [] }];
      const next = prev.filter((_, i) => i !== index);
      setFocusedCell((f) => Math.min(f, next.length - 1));
      return next;
    });
    kernelRef.current.clearCellOutputs?.(index);
    if (shrinks) {
      kernelRef.current.remapCells?.((i) => (i === index ? null : i > index ? i - 1 : i));
    }
    setKernelEpoch((n) => n + 1);
  }, []);

  const buildBindings = useCallback(() => {
    const needs = cellInputNeeds(chains[focusedCell] || { steps: [] });
    /** @type {import("../lib/toolkit/engine.js").RuntimeBindings} */
    const bindings: Record<string, unknown> = {
      encryption: { profile: profileForMode(pgpMode) },
      inputs: {},
    };
    const inputs: Record<string, unknown> = {};
    if (needs.includes("text") || inputText.trim()) {
      inputs.text = { value: inputText };
    }
    // `gpgPass` is its own need — it is what a bound `key=$slot` still leaves
    // owed — so a notebook that needs only the passphrase still gets the
    // binding built for it.
    if (needs.includes("gpg") || needs.includes("gpgPass") || ciphertext.trim() || gpgPassphrase) {
      inputs.gpg = {
        armoredMessages: ciphertext.trim() ? [ciphertext.trim()] : [],
        ...(gpgPassphrase ? { passphrase: gpgPassphrase } : {}),
      };
    }
    const mnemonics = shareRows.map((s) => s.trim()).filter(Boolean);
    if (needs.includes("shares") || mnemonics.length) {
      inputs.shares = {
        mnemonics,
        ...(sharePassphrase.trim() ? { passphrase: sharePassphrase } : {}),
      };
    }
    if (needs.includes("envelope") || envelopeArmored.trim()) {
      inputs.envelope = { armored: envelopeArmored.trim() };
    }
    if (needs.includes("keypair") || keypairMaterial.trim()) {
      inputs.keypair = { value: keypairMaterial.trim() };
    }
    bindings.inputs = inputs;
    // Context `run.receipt` cannot see for itself: the whole notebook's source
    // (it only ever receives one cell) and the human name for the ceremony.
    // Through bindings, not the recipe text — a ceremony label is metadata, and
    // putting it in the recipe would push it into share links and saved
    // workspaces.
    //
    // `chains` is the notebook itself, and it is here because the source is not
    // a faithful copy of it: `serializeRecipe` has no spelling for an empty
    // cell, so a notebook of `[cell, blank, cell]` round-trips through text as
    // two cells numbered 0 and 1 while this array — and the cell headers on
    // screen, and every index the kernel keys its outputs by — numbers them 0
    // and 2. `run.manifest` commits to the cells the person is looking at, so
    // it needs the list they are looking at.
    bindings.receipt = { recipeSource: source, label: title, chains };
    const recs = boundRecipientsRef.current.filter((r) => r?.fingerprint);
    if (recs.length) {
      bindings.recipientKeysArmored = recs.map((r) => r.armoredKey);
      bindings.recipientFingerprints = recs.map((r) => r.fingerprint);
    }
    return bindings;
  }, [
    chains,
    focusedCell,
    pgpMode,
    inputText,
    ciphertext,
    shareRows,
    sharePassphrase,
    gpgPassphrase,
    envelopeArmored,
    keypairMaterial,
    source,
    title,
  ]);

  /**
   * The roster and which label this browser is, from the live exchange.
   *
   * One derivation, used by every handoff step and by the plan the Connections
   * tab draws. Two of them disagreeing about who "me" is would be an offer
   * addressed to the wrong half of the notebook.
   *
   * **Not a search of `quorumState.peers`.** It used to be one — the rows were
   * scanned for this browser's own fingerprint — and that could never match:
   * `session.peers` is the audience minus self, on purpose, because a session is
   * never its own peer. So `me` was always `""`, every cell planned as somebody
   * else's, `planRun` refused this browser's own key as a peer nobody answers
   * to, and the placed-run gate `runFrom` builds from `me` was never built.
   *
   * `roomRoster` answers it over the audience the room was derived from — see
   * its own note for why the audience rather than who has arrived, and why self
   * is still not a peer. The answer is this browser's own fingerprint, but it is
   * a *lookup* and not an echo: a key the audience does not contain gets "",
   * which is what leaves `planRun`'s `who-am-i` question standing.
   *
   * **It is declared here, above `runFrom`, and that position is load-bearing.**
   * It used to sit six hundred lines down among the handoff calls, which meant
   * `runFrom` could close over it but could not name it in a dependency list —
   * a `const` referenced before its own declaration is a temporal dead zone
   * error at the moment the hook runs, so the omission was not an oversight
   * that could simply be corrected in place. See `runFrom`'s dependency list
   * for what the omission cost.
   */
  const handoffWho = useCallback(
    () =>
      roomRoster(
        quorumState.audience || [],
        (quorumState.peers || []).map((p) => p.fingerprint),
        quorumState.self || ""
      ),
    [quorumState]
  );

  /**
   * One press, one run — whatever the press decided the run may touch.
   *
   * Split out of `runFrom` when the notebook grew a second control. The loop
   * below never knew its own bound: it walked `cellsInScope(run.scope, chains)`
   * and `run.js` had already made the scope a stated field rather than an
   * implied one, so the *only* thing standing between "run this and everything
   * under it" and "run exactly this" was that one caller minted one shape of
   * scope. Nothing about the engine changes here; the two exported callbacks
   * below hand this different scopes and different causes, and the record says
   * which press it was.
   */
  const startRun = useCallback(
    async (cause: RunCause, scope: { from: number; to: number }) => {
      if (!compiled.validation?.ok) {
        refuse(
          (compiled.validation?.errors || []).map((e: { message: string }) => e.message).join(" · ") ||
            "Recipe invalid"
        );
        return;
      }
      /**
       * The run, as a thing — `lib/toolkit/run.js` holds the argument. The
       * cause is the press and where it landed; the scope is that press's
       * bound, stated rather than implied, and `cellsInScope` is what walks
       * it, so the record and the loop cannot disagree about what this run was
       * allowed to touch. Everything below that used to be its own ref — the
       * declined list, the plan, the sent-offers bound, the sequence number —
       * is a field of this object now: one identity, so a decline and the plan
       * that declined it, or an offer and the run that bounds it, can never
       * come from different runs.
       */
      const run = createRun({ cause, scope });
      const runnable = cellsInScope(run.scope, chains);
      setBusy(true);
      setRunError("");
      // `setRunStatus`, never `narrate`: this and `Running cell n…` below are
      // the ticker, and the ticker is the one thing on this line a screen
      // reader is deliberately not told. See `announcement`.
      setRunStatus("Running…");
      stopRunRef.current = false;
      // §27d: per-run approval state (request counter, batch grants) starts
      // fresh every run — a batch must never outlive the run that minted it.
      beginApprovalRun();
      /**
       * Which cell the loop is on, for the run bar's copy.
       *
       * A local, not `runningCell`: that is React state, so it is not readable
       * in this closure until the next render (`49cd286` — every mutation here
       * takes its cell index explicitly, and nothing reads an ambient one).
       */
      let at = -1;
      // Installing the fresh run is what retires the last one: `runRef` is the
      // one place a "current run" exists, so replacing it here — before the
      // loop, not after — means a run that throws still leaves the next one a
      // clean bound, and the throwing run is the *usual* one, since a cell
      // reading a slot somebody else's cell writes is what stops a placed run
      // in the first place. A pending hand-over pass for the old run finds
      // itself outdated by identity (`handOffPlaced` checks the ref) rather
      // than by a number it has to keep in step.
      runRef.current = run;
      // Cleared with it, so the queue never annotates this run's declined
      // cells with what happened to the last one's. The record's own offer
      // list starts empty on the fresh object; this clears the rendered copy.
      setAutoOffered([]);
      /**
       * Who runs what, for this run.
       *
       * Built only when the room can bind the labels — a plan whose peers mean
       * nobody would place every cell on nobody. Absent, `runCell` builds no
       * gate and this is the run it has always been, which `placement.js`
       * insists is a different thing from a gate that admits everything.
       */
      const { roster, me } = handoffWho();
      let placement: any;
      if (me && Object.keys(roster).length) {
        try {
          const plan = planRun(compileRecipe(source), { me, roster });
          if (plan.ok && plan.play === "placed") {
            // The plan and the declines it produces are fields of one run —
            // the plan is what says whether a declined cell is owed an offer,
            // and a plan from one run beside another run's declines would
            // answer that question about a notebook not on screen.
            run.plan = plan;
            placement = { plan, onSkip: (sk: any) => run.record.declined.push(sk) };
          }
        } catch {
          /* an uncompilable notebook is the editor's complaint, not the gate's */
        }
      }
      try {
        const bindings = buildBindings();
        for (let n = 0; n < runnable.length; n++) {
          if (stopRunRef.current) {
            narrate("Stopped");
            return;
          }
          const i = runnable[n];
          // Checkpoint: gate each cell as it comes up, not the notebook as a
          // whole. A later cell's unmet inputs pause the run *there* — with
          // everything above it already produced — instead of preventing the
          // producing cells from running at all.
          const unmet = unmetForCell(i);
          if (unmet.length) {
            const msg = blockerTextFor(unmet[0]);
            // This is the *Inputs tray* gate, not the slot gate: `unmetForCell`
            // asks whether a value the tray supplies is missing, and both Run
            // controls in the cell header are already absent-or-refused on
            // exactly this list, so a one-cell run cannot arrive here. A cell
            // whose inputs are not in *slots* fails in `runCell` below and is
            // reported as `Cell [i] — …`, which names the cell either way.
            if (n === 0) {
              refuse(msg);
              setRunStatus("Blocked");
              return;
            }
            setKernelEpoch((x) => x + 1);
            narrate(
              `Paused before cell [${i}] — ${msg}. Cells above it ran; Run from here once its inputs are in.`
            );
            return;
          }
          setRunProgress({ cell: n + 1, total: runnable.length });
          setRunningCell(i);
          // The ticker. Silent by design — announcing it would interrupt a
          // screen reader once per cell for a fact the reader cannot act on,
          // and the outcome below is the one they came for.
          setRunStatus(`Running cell ${i}…`);
          at = i;
          await kernelRef.current.runCell(i, chains[i], bindings, placement, run);
        }
        setKernelEpoch((n) => n + 1);
        narrate("Done");
      } catch (err) {
        setKernelEpoch((n) => n + 1);
        // The cell now carries this message too, and that repetition is the
        // point: the run bar is the only line that is always on screen, so a
        // failure in cell 9 of a long notebook must still be readable without
        // scrolling. What it adds over the cell is *where* — the run bar
        // answers "did the notebook run, and how far did it get", the cell
        // answers "what happened here". Prefixed, never reworded: the thrown
        // sentence is the part that names the remedy.
        const msg = err instanceof Error ? err.message : String(err);
        refuse(at >= 0 ? `Cell [${at}] — ${msg}` : msg);
        setRunStatus("Failed");
      } finally {
        setBusy(false);
        setRunProgress(null);
        setRunningCell(null);
        // The run is over however it got here, and its record now holds what
        // it declined. Handing those over is asked for as *state* rather than
        // done on this line, for `finishedRun`'s reason one screen down:
        // `offerCell` reads `source`, `title` and the roster through closures
        // this callback does not depend on, so calling it here would offer the
        // notebook as it stood when `runFrom` was built. The effect below fires
        // after the re-render, where the `offerCell` in scope is the one built
        // from what is on screen.
        //
        // **Not after a Stop.** The argument for sending without a press is
        // that it only restates the decision Run already made; a reader who
        // pressed Stop has taken that decision back, and an outward document
        // sent on the strength of a press they withdrew would be the one act
        // here nobody asked for. Their cells stay in the queue with the press
        // still on them, and `runStatus` says so rather than going quiet.
        //
        // What it names is what this run *would* have sent — `owed`, not every
        // cell the gate declined. A Stop takes back the press; it does not make
        // the creator's own session cells this machine's to hand over, and a
        // sentence promising to hand them over "in one press" would be inviting
        // the reader to send the very documents the rule above exists to stop.
        if (stopRunRef.current) {
          const { owed: waiting } = offersOwed(
            run.record.declined,
            run.record.sent,
            run.plan ?? undefined
          );
          if (waiting.length) {
            narrate(
              `Stopped — nothing was handed over. ${waiting.length === 1 ? "Cell" : "Cells"} ` +
                `${waiting.map((o) => o.cell).join(", ")} ${
                  waiting.length === 1 ? "is" : "are"
                } still theirs, and handing ${
                  waiting.length === 1 ? "it" : "them"
                } over is one press in Connections.`
            );
          }
        } else {
          setFinishedRun(run);
        }
      }
    },
    // `handoffWho` was missing, and its absence was the gate quietly not
    // existing. It is rebuilt from `quorumState`, so a `runFrom` that does not
    // depend on it keeps whichever roster was current the last time `chains`
    // changed — which for the flow `96dde48` opened up (place the cells, *then*
    // press Start) is the roster from before anybody was in the room. `me` is
    // "" there, no plan is built, `runCell` is handed no placement, and the
    // notebook runs every cell locally including the ones belonging to other
    // people: no decline, an empty record, and nothing for this run to
    // hand over. Reproduced in the browser — the same notebook and the same
    // room gated only after a keystroke made the callback fresh.
    //
    // Listing it needed `handoffWho` moved above this callback first. It was
    // declared six hundred lines down, so naming it here threw "cannot access
    // 'handoffWho' before initialization" the moment the page mounted — which
    // is presumably how it came to be closed over silently instead.
    //
    // `source` is not listed because it is `serializeRecipe(chains)` and cannot
    // move without `chains` moving; adding it would be a second name for a
    // dependency already here.
    [buildBindings, chains, compiled.validation, handoffWho, narrate, refuse, unmetForCell]
  );

  /**
   * Run this cell and everything under it — the notebook's Run, unchanged.
   *
   * Kept as its own name and its own shape because it is the muscle memory:
   * the header button on every cell, the run bar's *Run from [n]*, and Run all
   * at index 0 all still mean "from here to the end of the notebook".
   */
  const runFrom = useCallback(
    (from: number) =>
      startRun({ kind: "press", press: "run-from", cell: from }, {
        from,
        to: chains.length - 1,
      }),
    [chains.length, startRun]
  );

  /**
   * Run exactly one cell — the consumer `run.js` said it was not going to
   * invent.
   *
   * `scope` was built as a capability with no control behind it, and the module
   * note was explicit that "whether a per-cell button should exist is a product
   * decision this module does not make". It exists now, and this is the whole
   * of what it took: a scope both of whose ends are the same cell. No engine
   * semantics are added — the same loop, the same gate, the same record —
   * which is exactly why this is safe as a *secondary* control rather than a
   * replacement. What differs is the record: the cause says `run-cell`, so a
   * receipt can tell a one-cell run apart from a walk that happened to have
   * one cell left in it.
   */
  const runCellOnly = useCallback(
    (cell: number) => startRun({ kind: "press", press: "run-cell", cell }, { from: cell, to: cell }),
    [startRun]
  );

  /**
   * Guided key ceremony (CeremonySheet).
   *
   * The ceremony builds ordinary notebook cells and runs them on the same
   * kernel the Run button uses — same slots, same per-cell outputs, same
   * receipt run log. What it does *not* do is go through `runFrom`: that runs
   * every cell from an index onward, so a notebook holding the receipt cell
   * would mint a receipt the moment the verify step ran. Each stage appends its
   * own cell and runs exactly that one.
   */
  const [ceremonyStage, setCeremonyStage] = useState<CeremonyStageId>("setup");
  const [ceremonyParams, setCeremonyParams] = useState({
    threshold: 2,
    shares: 3,
    label: "",
    qr: true,
    signWith: "",
  });
  const [ceremonyRun, setCeremonyRun] = useState<"idle" | "running" | "done" | "error">(
    "idle"
  );
  const [ceremonyError, setCeremonyError] = useState("");

  const updateCeremonyParams = useCallback(
    (patch: Partial<typeof ceremonyParams>) => {
      setCeremonyParams((prev) => ({ ...prev, ...patch }));
    },
    []
  );

  const openCeremony = useCallback(() => {
    setCeremonyStage("setup");
    setCeremonyRun("idle");
    setCeremonyError("");
    setSheet("ceremony");
  }, []);

  /**
   * The split id of the ceremony that has already run, or "".
   *
   * Derived from the split cell's own tiles through `collectShareCards`, which
   * is where the derivation lives — the cards print this label and the playbook
   * has to name the same one, and two derivations of one label is how two
   * documents come to disagree about which envelope they belong to.
   *
   * Empty until the split has run, and empty for a plain (unverifiable) split,
   * which is correct: there is no split to name.
   */
  const ceremonySplitId = useCallback((splitCellIndex: number) => {
    if (splitCellIndex < 0) return "";
    const outs = kernelRef.current.getCellOutputs(splitCellIndex) as ArtifactTile[];
    if (!outs.length) return "";
    const cards = collectShareCards(outs, {});
    return String(cards[0]?.splitId || "");
  }, []);

  const runCeremonyStage = useCallback(
    async (stage: CeremonyStageId) => {
      // The cards cell names the split that just ran, so the params it is built
      // from are the ceremony's plus that label. Indices are unaffected — the
      // label changes one cell's text, never how many there are.
      const shape = ceremonyCells(ceremonyParams);
      const splitId = ceremonySplitId(shape.findIndex((c) => c.stage === "split"));
      const cells = splitId
        ? ceremonyCells({ ...ceremonyParams, splitId })
        : shape;
      const at = cells.findIndex((c) => c.stage === stage);
      if (at < 0) return;
      const compiled = cells.slice(0, at + 1).map((c) => {
        const { ast } = compileRecipe(c.recipe);
        if (!ast?.chains?.length) throw new Error(`Ceremony cell failed to compile: ${c.stage}`);
        return ast.chains[0] as RecipeChain;
      });
      setCeremonyRun("running");
      setCeremonyError("");
      try {
        // Show the cells in the notebook as they are added, so the ceremony is
        // never doing something the user cannot see in Source view.
        setTitle(ceremonyTitle(ceremonyParams));
        setChains(compiled.map((c) => ({ ...c, steps: [...(c.steps || [])] })));
        setFocusedCell(at);
        const bindings = {
          ...buildBindings(),
          receipt: {
            recipeSource: cells.map((c) => c.recipe).join("\n\n"),
            label: ceremonyParams.label || ceremonyTitle(ceremonyParams),
          },
        };
        // The stage's own run: caused by this stage's button, scoped to the
        // one cell it appends — which is the ceremony's whole contract ("each
        // stage appends its own cell and runs exactly that one"), now stated
        // on the object the kernel records under rather than implied by the
        // call shape. Deliberately *not* installed as `runRef.current`: that
        // ref is the notebook run whose declined cells the queue is about,
        // a stage declines nothing, and replacing the ref here would retire
        // a hand-over pass the previous notebook run may still be owed.
        const run = createRun({
          cause: { kind: "press", press: "ceremony-stage", stage },
          scope: { from: at, to: at },
        });
        await kernelRef.current.runCell(at, compiled[at], bindings, undefined, run);
        setKernelEpoch((n) => n + 1);
        setCeremonyRun("done");
      } catch (err) {
        setKernelEpoch((n) => n + 1);
        setCeremonyError(err instanceof Error ? err.message : String(err));
        setCeremonyRun("error");
      }
    },
    [buildBindings, ceremonyParams, ceremonySplitId]
  );

  /** Which notebook cell each ceremony stage's outputs live in. */
  const ceremonyCellIndex = useMemo(() => {
    const cells = ceremonyCells(ceremonyParams);
    return {
      split: cells.findIndex((c) => c.stage === "split"),
      verify: cells.findIndex((c) => c.stage === "verify"),
      cards: cells.findIndex((c) => c.stage === "cards"),
      receipt: cells.findIndex((c) => c.stage === "receipt"),
    };
  }, [ceremonyParams]);

  const ceremonyView = useMemo(() => {
    void kernelEpoch;
    const outs = (i: number) =>
      (i >= 0 ? kernelRef.current.getCellOutputs(i) : []) as ArtifactTile[];
    const splitOut = outs(ceremonyCellIndex.split);
    return {
      expectedDigest: tileForSlot(splitOut, "expected"),
      recoveredDigest: tileForSlot(outs(ceremonyCellIndex.verify), "recovered"),
      // The public half. Kept separate from `shareArtifacts` rather than left
      // in the pile: it is the one output of this ceremony that is meant to be
      // published, and every surface that shows it says so.
      commitmentsText: tileForSlot(splitOut, "commitments"),
      // Only the share/QR tiles — the digest tile is not a card.
      shareArtifacts: splitOut.filter(
        (a) => a.role === "share" || a.role === "qr"
      ) as ArtifactTile[],
      // The sheet that goes in the envelope with the cards. Shown at the cards
      // stage rather than kept for the receipt, because it is a thing to print
      // and hand over, not a record of what happened.
      playbookText: tileForSlot(outs(ceremonyCellIndex.cards), "playbook"),
      receiptText: tileForSlot(outs(ceremonyCellIndex.receipt), "receipt"),
    };
  }, [ceremonyCellIndex, kernelEpoch]);

  const stopRun = useCallback(() => {
    stopRunRef.current = true;
    // A run paused inside quorum.offer/join only unblocks when the exchange dies.
    window.dispatchEvent(new CustomEvent("basilisk:quorum-cancel"));
  }, []);

  const clearSensitive = useCallback(() => {
    kernelRef.current.clearSensitive?.();
    for (const e of sessionList()) sessionEvict(e.fingerprint);
    // §36: the Activity log holds no values, but it names key ids and
    // destinations — which is exactly the shape of thing this button exists
    // to remove. It goes with the outputs, not after them.
    clearActivity();
    clearApprovalGrants();
    setInputText("");
    setCiphertext("");
    setShareRows([""]);
    setSharePassphrase("");
    setGpgPassphrase("");
    setEnvelopeArmored("");
    boundRecipientsRef.current = [];
    setSessionTick((n) => n + 1);
    setKernelEpoch((n) => n + 1);
    narrate("Cleared sensitive data");
    setRunError("");
  }, [narrate]);

  const updateToolkitPrefs = useCallback((patch: Partial<ToolkitPrefs>) => {
    setToolkitPrefsState(setToolkitPrefs(patch));
  }, []);

  // The relay fallback is armed by the preference and by nothing else. Both
  // halves go through here together — consent, and the credential source it
  // consents to — so a deployment that configures a relay cannot switch one on
  // for a user who did not ask, and a user who asks on a deployment with no
  // relay gets a 503 reported as "no relay available" rather than a failure.
  // Links opened while it is off have no supervisor at all: turning it on
  // arms the next connection, not the ones already up.
  useEffect(() => {
    configureRelayFallback({
      enabled: toolkitPrefs.relayFallback,
      source: toolkitPrefs.relayFallback ? fetchRelayCredentials : null,
    });
  }, [toolkitPrefs.relayFallback]);

  // Idle auto-scrub: wipe secrets/inputs/outputs (not the recipe) after N
  // minutes of no pointer/key activity, matching toolkit-legacy.js's
  // idleClearMinutes preference.
  useEffect(() => {
    const ms = toolkitPrefs.idleClearMinutes > 0 ? toolkitPrefs.idleClearMinutes * 60_000 : 0;
    if (!ms) return;
    let timer: number | undefined;
    const reset = () => {
      if (timer != null) window.clearTimeout(timer);
      timer = window.setTimeout(() => clearSensitive(), ms);
    };
    const events: (keyof DocumentEventMap)[] = ["pointerdown", "keydown"];
    events.forEach((ev) => document.addEventListener(ev, reset));
    reset();
    return () => {
      if (timer != null) window.clearTimeout(timer);
      events.forEach((ev) => document.removeEventListener(ev, reset));
    };
  }, [toolkitPrefs.idleClearMinutes, clearSensitive]);

  const resetNotebook = useCallback(() => {
    clearSensitive();
    setTitle("Untitled notebook");
    setChains(emptyChains());
    setFocusedCell(0);
    window.location.hash = "";
  }, [clearSensitive]);

  /**
   * Open a shared session, leaving the notebook alone.
   *
   * **It used to append two cells and run them** — `agent.unlock <me> | out
   * $me`, then `quorum.offer`/`quorum.join` over the audience — on the argument
   * that a session started by a hidden code path would be the one thing in this
   * app that happened without a recipe saying so. `session-flow.js`'s
   * `START_OPENS` carries the argument for why that stopped: a run walks to the
   * end of the notebook, so the notebook a session left behind was the only one
   * here that could not be run, and "reproducible" is exactly the property a
   * once-only step does not have.
   *
   * `openQuorumSession` is the whole of what replaced them, and it makes the
   * same two calls the engine made — the vault unlock, then `execQuorumOpen` —
   * so there is no second opinion anywhere about what opening a key means.
   *
   * **`busy` is held for the duration, and that is not bookkeeping.** The room
   * blocks until somebody meshes or the wait expires, and `busy` plus a
   * `waiting`/`offering` phase is what `ToolkitShell` reads as `waiting-peer`:
   * the state with Cancel and Copy invite on it. Without it the run bar would
   * sit idle through the one stretch where a person most needs a way out, and
   * `cancelQuorum` — the event that bar's Cancel dispatches — is what ends the
   * await.
   */
  const startSession = useCallback(
    async (draft: { audience: string[]; keyFingerprint: string; role?: "offer" | "join" }) => {
      setSheet(null);
      setRunError("");
      setBusy(true);
      setRunStatus(
        draft.role === "join" ? "Joining the room…" : "Opening the room…"
      );
      try {
        await openQuorumSession({
          audience: draft.audience,
          keyFingerprint: draft.keyFingerprint,
          role: draft.role,
          // The same field `agent.unlock` read when this was a cell. An unbound
          // passphrase is refused before the press by `startIssues`, so an
          // empty string here means the key does not owe one.
          passphrase: gpgPassphrase,
        });
        return true;
      } catch (err) {
        // The transport's own sentence. It names the room, the audience or the
        // key it refused, and paraphrasing it here would be this hook giving a
        // second account of a failure it did not observe.
        refuse(err instanceof Error ? err.message : String(err));
        return false;
      } finally {
        setBusy(false);
        setRunStatus("");
      }
    },
    [gpgPassphrase, refuse]
  );

  /**
   * Leave somebody behind by moving the room.
   *
   * The name says what happens rather than what was wanted: there is no
   * eviction to be had. The signalling service has no membership this
   * application can enumerate and no connection it can close, so the room moves
   * to a name derived from a new epoch and a secret the remaining members are
   * sent sealed, and the removed key is left holding a token for a group nobody
   * is in.
   *
   * **The notebook's placements are not rewritten here**, though this is where
   * the removal is asked for and the drift it causes starts. See
   * `dropDepartedPlacements` below for why the press is the wrong thing to hang the
   * rewrite off.
   */
  const removeFromRoom = useCallback(async (fingerprint: string) => {
    try {
      const out = await rotateQuorumRoom([fingerprint]);
      narrate(`Room moved to epoch ${out.epoch} — ${out.audience.length} keys remain`);
      return { ok: true as const };
    } catch (err) {
      const why = err instanceof Error ? err.message : String(err);
      refuse(why);
      return { ok: false as const, why };
    }
  }, [narrate, refuse]);

  /**
   * The audience the placements in this notebook were written against.
   *
   * Null until there is a live room to be written against. Held as a ref rather
   * than state because writing it must not itself cause a render — it is
   * updated on every snapshot the exchange emits, which is several a second
   * while a mesh is coming up.
   */
  const placedAgainst = useRef<{ epoch: number; audience: string[] } | null>(null);

  /**
   * Unassign the notebook's cells when the room moves out from under them.
   *
   * ## What this used to be
   *
   * A renumbering. Peers were positions in the sorted audience, so removing
   * anybody shifted every label below them and this callback rewrote each
   * header to follow the person it named. A peer is the whole fingerprint now,
   * so nobody is renumbered by anybody else leaving and there is nothing to
   * follow — what is left is the case that was never about numbering: a cell
   * placed on somebody who has gone.
   *
   * ## Why this is an observation and not a handler
   *
   * `removeFromRoom` is the obvious place and it is the wrong one. A rotation
   * is ordered on one machine and *happens* on all of them: the initiator calls
   * `rotateRoom`, everybody else reaches the identical state through the
   * `rotate` branch of `_handleSignal`, and on those machines nobody pressed
   * anything. An edit hung off the press would fire on exactly one member of
   * the room and leave the rest holding cells addressed to a key that is no
   * longer in the audience — so one member's notebook would plan and the
   * others' would refuse, from one removal.
   *
   * So it hangs off the audience changing, which is the fact the whole room
   * shares. `onRotate` is what makes that fact reach this layer at all — see
   * `quorum-ops.js`, where the room, the audience and the epoch used to be
   * patched only on the machine that ordered the move.
   *
   * ## Why the edit is local, and not carried in the rotation
   *
   * The `rotate` envelope could have carried the new placements and it must
   * not. Who left is a pure function of the two audiences; every member that
   * stays holds the *same* before-audience (the room id is a one-way digest of
   * it, so a member holding a different one was never in this room) and applies
   * the *same* `remove` list, from a single sender `_handleSignal` insists is
   * the initiator and key-confirmed. Both inputs are already identical on every
   * machine, so the answer is derived, not delivered — and a delivered copy
   * would put one member in charge of what another member's notebook says,
   * which is the opposite of the arrangement `notebook-share.js` protects: text
   * is adopted by a person, never pushed.
   *
   * ## Two notebooks that are not the same notebook
   *
   * The edit is per-notebook: each member applies the same set difference to
   * its own chains. Peers whose text has diverged — `notebook-share.js` allows
   * it, adoption being a person's decision — stay diverged and were already
   * refusing each other's offers on `recipeSha`. What no longer needs
   * converging is the *binding*: a peer is a key, so both notebooks meant the
   * same person before this ran and mean the same person after.
   *
   * ## The window where one has moved and one has not
   *
   * Rotations do not arrive everywhere at once, and the audience is what
   * `buildRunManifest` digests, so between them the two ends derive different
   * rosters and `acceptHandoffOffer` refuses with `unknown-manifest` — an
   * accurate refusal naming a state that is true, and it heals as soon as the
   * second machine applies the same rotation. A member that never gets the
   * announce cannot get the next one either: it is published into the room the
   * announce is moving *away* from, so a peer that missed one is not in the
   * room the next is sent to. Nobody skips a step in this sequence and quietly
   * lands somewhere else.
   *
   * ## What counts as a rotation
   *
   * The epoch, not the audience. A fresh exchange opens at epoch 0 with a
   * different audience and a different room, which is not this room moving — it
   * is a different room, and the notebook's headers mean whatever that room
   * says they mean. Only an epoch strictly above the one these placements were
   * written against is the room they were written against having moved.
   *
   * @param before the audience these placements were written against
   * @param after  the audience the room has moved to
   */
  const dropDepartedPlacements = useCallback(
    (before: string[], after: string[]) => {
      const { edits, note } = unassignDeparted(
        chainsRef.current,
        departedPeers(before, after)
      );
      for (const edit of edits) {
        setCellPeer(edit.cell, edit.peer, edit.publishSlots);
      }
      // The run-status line, which is the only surface on screen whatever else
      // is open. The draft's version of this sentence lives on the session
      // sheet because that is where the reader just pressed something; here the
      // reader on the machine that matters most pressed nothing, and a live
      // region inside a closed sheet announces to nobody. `upgradeCellRecipe`
      // narrates its own header rewrite in the same place for the same reason.
      //
      // `narrate`, not `setRunStatus`: for two commits this comment cited a
      // live region the shell did not have, and a rotation ordered on another
      // machine is precisely the event a reader who cannot see the roster has
      // no other way to learn. The region exists now — see `announcement`.
      //
      // Silent when nothing moved, so `removeFromRoom`'s own line survives the
      // ordinary case and a rotation that disturbed no placement is not
      // reported as one that did.
      if (note) {
        narrate(`The room moved and somebody is no longer in it. ${note}`);
      }
    },
    [narrate, setCellPeer]
  );

  /**
   * Watch the room, and hand `dropDepartedPlacements` the two audiences when it moves.
   *
   * Every snapshot the exchange emits arrives here — several a second while a
   * mesh is coming up — so the guards below are what make a rotation
   * distinguishable from a roster tick and from a different room opening.
   */
  useEffect(() => {
    const audience = quorumState.audience || [];
    const epoch = Number(quorumState.epoch || 0);
    if (!audience.length) {
      placedAgainst.current = null;
      return;
    }
    const was = placedAgainst.current;
    placedAgainst.current = { epoch, audience };
    // Nothing to move from. An exchange this hook joined mid-flight — the only
    // way to reach a non-zero epoch with no memory — is a room whose earlier
    // numbering this browser never saw, and inventing one to rewrite against
    // would be worse than the silence.
    if (!was || epoch <= was.epoch) return;
    dropDepartedPlacements(was.audience, audience);
  }, [quorumState, dropDepartedPlacements]);

  /**
   * Offers and results a peer has sent, still waiting on a person.
   *
   * Read straight from the exchange rather than mirrored into state: the list
   * lives for as long as the session does, and a copy here would be a second
   * place for it to be wrong.
   */
  const pendingHandoffs = useCallback(() => getPendingHandoffs(), []);

  /**
   * The current run — the one identity that used to be four refs.
   *
   * `lib/toolkit/run.js` argues the object; what belongs here is why it is a
   * ref and what moved in. A ref, not state: its record is written inside the
   * run loop and read by the offer pass that follows it, and a render in
   * between would be a render that could arrive after the read. Replaced
   * whole per run — never mutated back to empty — so a cell that stopped
   * being somebody else's does not linger in anybody's declined list.
   *
   * What collapsed into it, and the argument each piece brought along:
   *
   * - **`record.declined`** (was `skippedRef`) — the gate's own report,
   *   written during the run and gone with it.
   * - **`plan`** (was `runPlanRef`) — "declined" is not "owed an offer";
   *   `run-offers.js` argues which declined cells this machine is on an end
   *   of, and every fact that answers it (`consumes[].from`, `produces`,
   *   `mine`) is in the plan and nowhere else. `skippedCells` is deliberately
   *   not widened to carry them: a report that carried the dependency graph
   *   would be `placement.js` deciding placement a second time. As a field of
   *   the same object as the declines, the two cannot come from different
   *   runs — the invariant the old comments asked two refs to keep by being
   *   "written and cleared on the lines beside" each other.
   * - **`record.sent`** (was `offersSentRef.sent`) — `NotebookSession
   *   ._invited`'s pattern: a set of what has been served, consulted before
   *   serving and written *before* the send is awaited, so a second pass
   *   arriving while the first is in flight finds the cell claimed. Pressing
   *   Run again mints a fresh run with a fresh set, which is what lets a peer
   *   who was not meshed the first time be tried again.
   * - **the sequence number** (was `runSeqRef` + `offersSentRef.run`) — the
   *   question "is this pass about the current run" is answered by object
   *   identity now (`handOffPlaced` compares against this ref), so the
   *   counter survives only as `run.id`, minted in `createRun` for the
   *   receipt's benefit.
   *
   * The kernel writes `record.cells` — what each performed cell read, wrote
   * and received — as the run walks; nothing here touches it.
   */
  const runRef = useRef<Run | null>(null);
  const skippedCells = useCallback(
    () => (runRef.current?.record.declined ?? []).slice(),
    []
  );

  /**
   * The run whose declined cells have not been handed over yet, or null.
   *
   * State rather than a ref precisely because it must cause a render: it is the
   * hop that gets `handOffPlaced` out of `runFrom`'s closure and into one built
   * from the notebook as it now stands. `startSession` used to hold a second
   * one of these — it appended cells and then had to run the notebook those
   * cells were in — and it is gone with them; this is the last of the device.
   */
  const [finishedRun, setFinishedRun] = useState<Run | null>(null);

  /**
   * What the last run decided about each cell it declined, for the queue to
   * draw beside the cell it was about.
   *
   * The narration goes to `runStatus`, which is the line always on screen; this
   * is the same facts per cell, so the row offering to hand cell 3 over can say
   * whether cell 3 has already gone and stop reading as though nothing had.
   *
   * `aside` is a verdict, not an outcome, and it is here for the same reason the
   * other two are: without it the row for a cell the run deliberately left alone
   * is indistinguishable from the row for a cell a Stop cut short, and those ask
   * the reader for opposite things.
   *
   * A rendered copy of `run.record.offers`, not a second ledger: the verdicts
   * live on the run (`noteOfferVerdicts` folds them there, latest per cell
   * winning) and this state exists only because a ref cannot cause a render.
   */
  const [autoOffered, setAutoOffered] = useState<
    { cell: number; peer: string; state: "sent" | "refused" | "aside"; why?: string }[]
  >([]);

  /**
   * Fold a pass's verdicts into the run's record and re-render the copy.
   *
   * The merge itself is `noteOfferVerdicts` — a merge rather than a replace
   * because `handOffPlaced` writes twice (the cells it is leaving alone before
   * the sends, the outcomes after) and because the effect that calls it can
   * re-fire on a re-render, where the second pass finds every send already
   * claimed and knows only about the `aside` half. A replace there would
   * erase this run's record of what went out.
   */
  const noteOffers = useCallback(
    (
      run: Run,
      rows: { cell: number; peer: string; state: "sent" | "refused" | "aside"; why?: string }[]
    ) => {
      if (!rows.length) return;
      setAutoOffered(noteOfferVerdicts(run, rows));
    },
    []
  );

  /**
   * The notebook as it stands right now, for the arrival path to read.
   *
   * A ref rather than a dependency of the listener below, because the listener
   * must see the notebook *at the moment a proposal lands* and re-subscribing on
   * every keystroke would put an add/remove pair between each character and the
   * one before it. Written in an effect with no dependency list, which runs after
   * every render, so it is never behind what the editor shows.
   */
  const notebookRef = useRef({ title, source });
  useEffect(() => {
    notebookRef.current = { title, source };
  });

  /**
   * The last text this browser adopted, and who from.
   *
   * This is how "has the local user edited since the last adopt" is answered,
   * and it is answered by **comparing the text to itself**, not by watching for
   * edits. A boolean flag would have to be set at each of the two dozen places
   * that mutate `chains`, and the failure mode of missing one is silent and
   * destructive: a peer's proposal overwrites work the flag said was not there.
   * Text against text cannot miss a mutator, cannot be defeated by a new one,
   * and gives the honest answer when somebody types a character and deletes it
   * again. It is also not an inference from a proxy signal — focus, a dirty bit,
   * a keypress count — it is the question itself.
   */
  const adoptedRef = useRef<{ from: string; title: string; source: string } | null>(null);

  /**
   * A notebook a peer proposed that this browser will not adopt on its own.
   *
   * Non-null only in the case that needs a person: there is work here, it is not
   * the proposed text, and it is not text this browser adopted and left alone.
   * Everything else is decided without a press — see `considerProposal`.
   */
  const [proposedNotebook, setProposedNotebook] = useState<{
    from: string;
    title: string;
    source: string;
    ts: number;
  } | null>(null);

  /**
   * Replace this notebook with the one a peer proposed.
   *
   * The text is stored back as it will actually settle: `loadRecipeText`
   * compiles and the editor's `source` is the *re-serialisation* of what it
   * compiled, so recording the proposal's own bytes would leave this ref
   * disagreeing with the notebook for any sender whose text was not already in
   * that form — and the next proposal from them would then read as "the local
   * user has edited" and stop. It is a fixed point for anything this build
   * sends, and this line is what makes it not matter when it is not.
   */
  const adoptProposal = useCallback(
    (p: { from: string; title: string; source: string }) => {
      const { ast } = compileRecipe(p.source);
      if (!ast) {
        refuse(
          `The notebook ${formatFingerprint(p.from)} sent does not parse in this ` +
            "build, so there is nothing to adopt. Nothing here was changed — ask " +
            "them which version they are running."
        );
        return false;
      }
      loadRecipeText(p.title, p.source);
      const settled = serializeRecipe(
        ast.chains?.length ? ast.chains : [{ steps: ast.steps || [] }]
      );
      adoptedRef.current = { from: p.from, title: p.title, source: settled };
      setProposedNotebook(null);
      clearProposedNotebook();
      return true;
    },
    [loadRecipeText, refuse]
  );

  /**
   * What to do about the notebook a peer just proposed.
   *
   * The rule is `decideProposal`, in `notebook-share.js`, and it is there rather
   * than here because it is the rule that decides whether somebody's work is
   * replaced — a thing a test should be able to drive without a browser. This is
   * the half that cannot be pure: it does the replacing.
   */
  const considerProposal = useCallback(() => {
    const proposal = getProposedNotebook();
    if (!proposal) {
      setProposedNotebook(null);
      return;
    }
    const { action } = decideProposal({
      proposal,
      here: notebookRef.current,
      adopted: adoptedRef.current,
    });
    if (action === "same") {
      // Recorded as adopted even though nothing was replaced: this browser and
      // that peer are holding the same text, which is the state the untouched
      // rule is asking about, and reaching it by typing along is no different
      // from reaching it by pressing Adopt.
      adoptedRef.current = {
        from: proposal.from,
        title: proposal.title,
        source: notebookRef.current.source,
      };
      setProposedNotebook(null);
      clearProposedNotebook();
      return;
    }
    if (action === "adopt") {
      adoptProposal(proposal);
      return;
    }
    setProposedNotebook(proposal);
  }, [adoptProposal]);

  useEffect(() => {
    const onProposal = () => considerProposal();
    window.addEventListener("basilisk:quorum-notebook", onProposal);
    // A proposal can land between the exchange opening and this listener
    // existing — the session meshes inside `quorum.offer`, which is a cell of a
    // run this hook started. Asking once on mount is what makes that arrival a
    // late one rather than a lost one.
    considerProposal();
    return () => window.removeEventListener("basilisk:quorum-notebook", onProposal);
  }, [considerProposal]);

  /** Adopt the pending proposal. The press the fourth case above waits for. */
  const adoptProposedNotebook = useCallback(() => {
    if (!proposedNotebook) return { ok: false, why: "Nothing has been proposed." };
    if (!adoptProposal(proposedNotebook)) {
      return { ok: false, why: "That notebook does not parse in this build." };
    }
    return { ok: true, from: proposedNotebook.from };
  }, [adoptProposal, proposedNotebook]);

  /** Dismiss it, keeping what is here. Their text is gone; theirs still runs. */
  const dismissProposedNotebook = useCallback(() => {
    setProposedNotebook(null);
    clearProposedNotebook();
  }, []);

  /**
   * Put this notebook in front of the room, signed.
   *
   * **The transport the digest gate was always written against.** Every check in
   * `handoff.js` compares an arriving offer to the recipient's *own* text, which
   * is what makes a shared run a reproducible build rather than a screen share —
   * and until this call existed nothing ever gave the other end that text, so a
   * joiner refused every offer against a manifest derived from an empty
   * notebook. Nothing about the gate is relaxed here. Both ends still hold the
   * same text and still prove it by digest; one of them may now receive it.
   *
   * Signed with the key the session was opened under, at the moment a person
   * presses Share — the same consent boundary `sendCellResult` crosses, and for
   * a stronger reason: the receiving end has nothing of its own to check this
   * against, because this is what it will check everything else against.
   *
   * `buildNotebookProposal` refuses a notebook that looks like it holds private
   * key material, before anything is signed and before anything is sent.
   */
  const shareNotebook = useCallback(async () => {
    const session = getLiveSession();
    if (!session) return { ok: false, why: "No live session to share this notebook on." };
    let signed: string;
    try {
      const proposal = buildNotebookProposal({ title, source });
      signed = await signSessionDocument(proposalToJson(proposal));
    } catch (err) {
      return { ok: false, why: err instanceof Error ? err.message : String(err) };
    }
    let sent = 0;
    try {
      sent = await session.shareNotebook(signed);
    } catch (err) {
      return { ok: false, why: err instanceof Error ? err.message : String(err) };
    }
    if (!sent) {
      // A count, not a promise — `_publishDocument` writes to confirmed peers
      // only, so zero is a room that has not meshed rather than a failure to
      // send, and saying "shared" here would be a claim nobody can act on.
      return {
        ok: false,
        why:
          "Nobody in this room has a confirmed channel yet, so the notebook went " +
          "nowhere. It is still here — share it again once a peer is verified.",
      };
    }
    // `adoptedRef` is deliberately not touched. It records what this browser
    // took from a peer, and sharing is the other direction — writing this
    // browser's own text into it would make the *next* proposal from whoever it
    // last adopted from land silently on the strength of an act they had no part
    // in. An echo of what was just sent is caught by the same-notebook branch of
    // `considerProposal`, which needs no record at all.
    return { ok: true, sent };
  }, [source, title]);

  /**
   * The attestation this browser signed over its own run manifest, or null.
   *
   * Kept because **the session's roster is the audience minus self** — it can
   * never say anything about this browser — while the manifest's `peers` names
   * everybody including this browser. Without this record, coverage would list
   * the reader as the one person who had not attested a second after they
   * pressed Attest, which is the sort of report that teaches people to stop
   * reading reports.
   *
   * Set whether or not the send reached anybody: it records that a person on
   * this machine looked at a digest and signed it, which is true even in an
   * empty room.
   *
   * **Not persisted, and not cleared when the notebook changes.** It names one
   * digest, and `manifestAttestedBy` compares that digest against the manifest
   * now derived — so editing a cell after attesting reports *you signed over a
   * different notebook* rather than quietly forgetting that you signed at all.
   * Clearing it would be this hook deciding, on the reader's behalf, that a
   * signature they made no longer counts.
   */
  const [ownAttestation, setOwnAttestation] = useState<ManifestAttestation | null>(null);

  /**
   * Who in this room has signed over the manifest this notebook derives.
   *
   * `manifestAttestedBy`'s own answer, not a count assembled here, and null when
   * there is nothing to answer about — no room, or a notebook that does not
   * compile and therefore has no manifest to be attested to.
   */
  const [attestation, setAttestation] = useState<AttestationCoverage | null>(null);

  /**
   * Sign *I saw this manifest* and put it in front of the room.
   *
   * **A press, and it has to be.** `attest.js` refuses to hold a signing
   * function for the reason `receipt.js` does — "the recipe is the thing the
   * user reads before pressing Run, and a signer buried in a module signs
   * without anyone having read a recipe" — and an attestation minted whenever a
   * run produced a manifest would be exactly that module, one layer out: this
   * browser swearing it saw a notebook nobody looked at. `a4f9399` allows an
   * automatic send where the run itself is the bound, and it is the right rule
   * for an *offer*, which restates a placement decision the reader already made
   * by pressing Run. Nothing about pressing Run says the reader read the
   * manifest.
   *
   * It is also not a duplicate of `run.attest`. That op puts an attestation in a
   * slot, which is where a recipe can pipe it, store it or hand it to
   * `gpg.sign`; this puts one on the wire. Both mint a signature only from a
   * human act, which is the property `approval-gate.js` protects.
   *
   * The manifest is `handoffContext`'s — the same derivation every offer and
   * every accept is checked against — so the digest signed here is the digest a
   * peer's own machine computes, and a mismatch is the notebooks differing
   * rather than the two ends disagreeing about how to digest one.
   */
  const attestManifest = useCallback(async () => {
    const session = getLiveSession();
    if (!session) return { ok: false, why: "No live session to put an attestation on." };
    let signed: string;
    let mine: ManifestAttestation;
    try {
      const { roster, me } = handoffWho();
      const ctx = await handoffContext({ source, me, roster, title });
      mine = await buildAttestation({ manifest: ctx.manifest });
      signed = await signSessionDocument(attestationToJson(mine));
    } catch (err) {
      return { ok: false, why: err instanceof Error ? err.message : String(err) };
    }
    let sent = 0;
    try {
      sent = await session.publishAttestation(signed);
    } catch (err) {
      return { ok: false, why: err instanceof Error ? err.message : String(err) };
    }
    // Recorded before the count is judged. The signature exists on this machine
    // whether or not a peer was meshed to hear about it, and a record that
    // waited for delivery would make this browser's own coverage a fact about
    // the network.
    setOwnAttestation(mine);
    if (!sent) {
      return {
        ok: false,
        why:
          "You have attested to this manifest, and nobody in this room has a " +
          "confirmed channel yet, so nobody was told. Attest again once a peer " +
          "is confirmed.",
      };
    }
    return { ok: true, sent, digest: mine.manifest };
  }, [handoffWho, source, title]);

  /**
   * Recount coverage whenever the roster or the notebook moves.
   *
   * Both halves matter and they move independently: an attestation arrives with
   * the notebook perfectly still, and editing a cell changes the digest every
   * held attestation is measured against — so a badge that only followed the
   * roster would go on saying "attested" about a manifest the reader has just
   * edited out of existence.
   *
   * The entries are the documents the peers signed, attributed by
   * `labelForFingerprint` — the one crossing from the session's fingerprints to
   * the peers a plan speaks in. An attestation the roster cannot name is passed
   * on with no `by`, which `manifestAttestedBy` counts toward nothing and says
   * so in its caveats; dropping it would be reporting less than is known.
   */
  useEffect(() => {
    // A room needs at least two fingerprints to exist, and with none there is no
    // manifest anybody could be expected to have seen. Reporting vacuous
    // coverage for a notebook nobody is sharing is a badge that means nothing.
    if ((quorumState.audience || []).length < 2) {
      setAttestation((prev) => (prev === null ? prev : null));
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const { roster, me } = handoffWho();
        const ctx = await handoffContext({ source, me, roster, title });
        const entries: { by?: string; attestation: ManifestAttestation }[] = [];
        for (const row of quorumState.peers || []) {
          const by = labelForFingerprint(roster, String(row.fingerprint || ""));
          for (const a of row.attested || []) {
            entries.push(by ? { by, attestation: a } : { attestation: a });
          }
        }
        if (ownAttestation && me) entries.push({ by: me, attestation: ownAttestation });
        const coverage = await manifestAttestedBy(ctx.manifest, entries);
        if (cancelled) return;
        // Replaced only when it says something different. A roster is emitted on
        // every ICE tick, and a fresh object each time would re-render the panel
        // — and re-announce the live region under it — for a count that has not
        // moved.
        setAttestation((prev) =>
          prev && JSON.stringify(prev) === JSON.stringify(coverage) ? prev : coverage
        );
      } catch {
        // A notebook that does not compile has no manifest, so there is nothing
        // for anybody to have attested to. That is not a failed signature and
        // must not be drawn as one.
        if (!cancelled) setAttestation((prev) => (prev === null ? prev : null));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [handoffWho, ownAttestation, quorumState.audience, quorumState.peers, source, title]);

  /**
   * Hand a skipped cell to the peer it belongs to.
   *
   * The offer carries the values that cell reads and nothing else —
   * `buildOfferFor` refuses rather than trimming, because a partial offer says
   * "run this" while withholding something the cell needs. `sendOffer` throws
   * rather than returning zero, so a failure here is a failure the author sees
   * instead of an offer they believe landed.
   */
  const offerCell = useCallback(
    async (cell: number) => {
      const skipped = runRef.current?.record.declined.find((sk) => sk.cell === cell);
      if (!skipped) return { ok: false, why: "That cell was not left to anybody." };
      const { roster, me } = handoffWho();
      const ctx = await handoffContext({ source, me, roster, title });
      const slots = kernelRef.current.slots;
      const built = await offerForSkipped(ctx, skipped, (l: string) =>
        slots.has(l) ? slots.resolve(l) : null
      );
      if (!built.ok) return { ok: false, why: summarizeHandoff(built) };
      const to = roster[built.peer];
      if (!to) return { ok: false, why: `Nobody in this room answers to @${built.peer}.` };
      const session = getLiveSession();
      if (!session) return { ok: false, why: "No live session to hand it over on." };
      // The roster is the audience, so a label can name a member who was
      // invited and has not meshed — `sendOffer` throws for exactly that, and
      // its sentence names the state (which fingerprint, and that no verified
      // peer holds it). Returned rather than thrown because the caller is a
      // click handler that reads `why` and does not catch.
      try {
        await session.sendOffer(to, built.json);
      } catch (err) {
        return { ok: false, why: err instanceof Error ? err.message : String(err) };
      }
      return { ok: true, cell, peer: built.peer };
    },
    [handoffWho, source, title]
  );

  /**
   * Hand over what this run left on somebody else *and this machine is an end
   * of*, without being asked twice.
   *
   * This is the last mile of the placed run, and until it existed the product
   * described it and did not do it: the queue's empty state promised that
   * declined cells "are offered to whoever owns them", while `offerCell`'s only
   * caller in the whole application was a per-row button. A placed run was Run,
   * and then one press per cell.
   *
   * **Which of them, though, is `offersOwed`'s question and not this one's.**
   * The first version of this sent every cell the gate declined, and the gate
   * declines a cell for a narrower reason than an offer claims — a joiner's run
   * declines the creator's own session cells and was offering them back to the
   * creator who had already run them. The rule and its argument are in
   * `run-offers.js`; what belongs here is that the cells it sets aside are still
   * in the queue with the press still on them, and the row says which state it
   * is in rather than reading like a send that has not happened yet.
   *
   * **Nothing runs anywhere because of this.** An offer is a document; the peer
   * that receives it holds it pending until they press accept, and accepting is
   * what turns it into bindings. `acceptHandoff` keeps that boundary and keeps
   * it in a function only a press reaches. What is removed here is a press that
   * restated a decision already made — the reader said "run this notebook", and
   * the notebook says which cells are not theirs.
   *
   * **The bound is what has gone out, never a clock.** `offerCell` deliberately
   * does not consume the skipped cell — that non-destructiveness is what makes
   * recovery after a reload possible, and `HandoffQueue` promises it in writing
   * — so nothing downstream would stop a second pass from sending the same cell
   * twice. `run.record.sent` is `NotebookSession._invited` one layer up:
   * marked before the await, so a re-entry finds the cell claimed rather than
   * in flight, and a field of the run so that pressing Run again — a fresh
   * object, a fresh set — is a real retry for a peer who was not reachable
   * the first time.
   *
   * **Failures are said out loud, in the handoff layer's words.** A run that
   * silently handed nothing over is the experience this whole arc exists to
   * end, and `offerCell` refuses for states that are distinguishable and worth
   * distinguishing: nobody answers to that label, the peer is in the audience
   * but has not meshed, the cell was left to nobody. They go to `runStatus`
   * rather than the session sheet for `dropDepartedPlacements`'s reason — the sheet is
   * very likely closed, and a live region inside a closed sheet announces to
   * nobody — appended to the run's own verdict rather than replacing it, so
   * "Failed" and why a cell did not go out are on screen together.
   */
  const handOffPlaced = useCallback(
    async (run: Run) => {
      // A newer run has already replaced this one as the current run. Sending
      // now would be offering the previous run's answers under the current
      // run's numbering — identity, not a counter, is what says so.
      if (runRef.current !== run) return;
      const { owed: waiting, aside } = offersOwed(
        run.record.declined,
        run.record.sent,
        run.plan ?? undefined
      );
      // Recorded before the sends and whether or not there is a session, because
      // it is a reading of the notebook rather than a thing that happened: the
      // holder's `quorum.recv` is not this dealer's to hand over in an empty
      // room either, and the row must not say "nothing has gone out" as though
      // the room were the reason.
      noteOffers(run, aside.map((o) => ({ cell: o.cell, peer: o.peer, state: "aside" as const })));
      if (!waiting.length) return;
      if (!getLiveSession()) {
        // Appended to the run's own verdict on screen, announced on its own:
        // "Done" has already been announced by the time this lands, and
        // re-reading it in front of the news would make a reader wait through
        // a word they have had to hear again for the sentence that is new.
        const said = narrateNoSession(waiting);
        setRunStatus((prev) => `${prev} ${said}`.trim());
        announce(said);
        return;
      }
      const outcomes: { cell: number; peer: string; ok: boolean; why?: string }[] = [];
      for (const o of waiting) {
        // Claimed before the send, not after it. `_onKnock` adds to `_invited`
        // on the line above its own await for the same reason: the failure this
        // prevents is two passes overlapping, and a mark written after the
        // answer comes back is not written during the window that matters.
        run.record.sent.add(o.key);
        const r = await offerCell(o.cell);
        outcomes.push({ cell: o.cell, peer: o.peer, ok: !!r.ok, why: r.ok ? undefined : r.why });
      }
      noteOffers(
        run,
        outcomes.map((o) => ({
          cell: o.cell,
          peer: o.peer,
          state: o.ok ? ("sent" as const) : ("refused" as const),
          why: o.ok ? undefined : o.why,
        }))
      );
      // Announced on its own, for the reason the no-session branch above
      // gives: the verdict this is appended to has already been said.
      const said = narrateOffers(outcomes);
      setRunStatus((prev) => `${prev} ${said}`.trim());
      announce(said);
    },
    [announce, noteOffers, offerCell]
  );

  useEffect(() => {
    if (finishedRun == null) return;
    setFinishedRun(null);
    void handOffPlaced(finishedRun);
  }, [finishedRun, handOffPlaced]);

  /**
   * Send back what a cell wrote, signed.
   *
   * `sendResult` takes a cleartext-signed document and refuses anything else:
   * the origin has to know *this* peer made the claim, and an unsigned result
   * is a value from whoever reached the channel. The key is the one the
   * session already opened, so signing asks nobody for anything new.
   */
  const sendCellResult = useCallback(
    async (cell: number, toPeer: string) => {
      const { roster, me } = handoffWho();
      const ctx = await handoffContext({ source, me, roster, title });
      const slots = kernelRef.current.slots;
      const built = await resultForCell(ctx, cell, (l: string) =>
        slots.has(l) ? slots.resolve(l) : null
      );
      if (!built.ok) return { ok: false, why: summarizeHandoff(built) };
      const session = getLiveSession();
      const to = roster[toPeer];
      if (!session || !to) return { ok: false, why: "No live session, or no such peer." };
      // `ok` does not narrow `result` — the shell's return is not a
      // discriminated union — and a result really can be absent. Refused with a
      // sentence rather than asserted away, because sending nothing back and
      // reporting success is the failure this whole exchange is built to avoid.
      if (!built.result) {
        return { ok: false, why: "That cell produced no result to send back." };
      }
      const signed = await signSessionDocument(resultToJson(built.result));
      // `sendResult` throws when the peer that asked is no longer reachable —
      // the same reason `offerCell` catches, and the same click handler.
      try {
        await session.sendResult(to, signed);
      } catch (err) {
        return { ok: false, why: err instanceof Error ? err.message : String(err) };
      }
      return { ok: true, cell, peer: toPeer };
    },
    [handoffWho, source, title]
  );

  /**
   * Accept one, which is the click the whole arc is gated on.
   *
   * `handoff.js` returns *bindings a caller would register* and registers
   * nothing itself, so this is where a handoff stops being a document and
   * starts being values in the registry — and it happens here, in a function
   * only a person's press reaches, rather than anywhere a running recipe could
   * arrive at.
   *
   * This paragraph sat three declarations up, stacked above `handoffWho` with
   * nothing of its own beneath it, so the function it describes had no comment
   * and the one it was attached to had two.
   */
  const acceptHandoff = useCallback(
    async (id: string) => {
      const doc = takeHandoff(id);
      if (!doc) return { ok: false, why: "That handoff is no longer pending." };

      const { roster, me } = handoffWho();
      const ctx = await handoffContext({ source, me, roster, title });
      const slots = kernelRef.current.slots;
      /**
       * Which peer the returning document answers to, resolved through the
       * roster rather than read off the document.
       *
       * **This line is why the returning half of the arc had never worked.**
       * `acceptCellResult` checks `by` against `plan.cells[n].runsOn`, which
       * holds whatever the notebook's headers say; those were positional labels
       * and could never hold a key, so passing `doc.from` — a bare fingerprint —
       * straight through meant every result that ever came back was refused
       * `not-theirs`, on a machine that had just handed that peer the cell.
       *
       * The two are now the same forty characters, which does not make the
       * resolution redundant: `handoff.js` and `attest.js` are explicit that the
       * session never learns what a notebook calls anybody and that the caller
       * resolves it — this is the caller. Going through `roomRoster` is what
       * makes a peer *outside the audience* resolve to "" and be refused, rather
       * than being admitted because its fingerprint happened to match its own
       * header. It is the same binding the offer went out under, so the two
       * directions cannot disagree about who a
       * peer is. An unknown fingerprint resolves to `""` and `acceptCellResult`
       * refuses it as unattributed, which is the state that is actually true.
       *
       * Nothing caught it because the arc's own e2e proof resolves the label
       * itself before calling in — `placed-run-arc.e2e.js` does
       * `labelForFingerprint(roster, from)` inside its own driver, so it
       * exercises the layer under this one doing the right thing with an
       * argument this layer never supplied. `placed-journey.e2e.js` presses the
       * button instead, and the button is where it was wrong.
       */
      const by = doc.kind === "result" ? labelForFingerprint(roster, doc.from) : "";
      const verdict =
        doc.kind === "offer"
          ? await reviewOffer(ctx, doc.offer, (l: string) => slots.has(l))
          : await reviewResult(ctx, doc.result, {
              by,
              // **This is not a bound, and saying so is the point.** Every field
              // of it is read off the document being judged, so
              // `acceptCellResult`'s `not-offered` refusal — "an answer to a
              // question nobody asked" — cannot fire here however wrong the
              // result is. A real record would be what *this* machine handed out
              // and to whom; `offerCell` knows both and writes neither down past
              // the current run, and `HandoffQueue` already states in writing
              // that the shell's memory of a handoff does not survive a reload.
              // So the check is left standing rather than quietly deleted, and
              // named as the hole it is: closing it needs a durable record of
              // outgoing offers, which is its own decision and not a corner of
              // this one.
              offered: [{ manifest: doc.manifest, cell: doc.cell, to: by }],
              hasSlot: (l: string) => slots.has(l),
            });

      if (!verdict.ok) return { ok: false, why: summarizeHandoff(verdict) };
      for (const b of verdict.bindings || []) {
        slots.register(b.label, b.value, { allowReplace: true });
      }
      // `kernelEpoch`, because what just changed is the kernel's slot registry.
      // This bumped `sessionTick` — which is the vault's counter, read by
      // `refreshVault` and by nothing that draws a slot — while `slotMetas`,
      // `cellOutputs` and every other read of `kernelRef` are memoised on
      // `kernelEpoch`. So the Slots tray went on saying "No slots yet" about a
      // value the shell had just told the reader it registered, until the next
      // run bumped the epoch for its own reasons. Registering a binding changes
      // nothing about which keys this browser holds, so the tick it used to
      // send was answering a question nobody had asked.
      setKernelEpoch((n) => n + 1);
      return { ok: true, cell: doc.cell, registered: (verdict.bindings || []).length };
    },
    [handoffWho, source, title]
  );

  const copyShareLink = useCallback(async () => {
    const result = hashForNotebook(source);
    if (result.ok === false) {
      narrate(result.reason || "Cannot share this recipe in a link");
      return;
    }
    await navigator.clipboard.writeText(toolkitShareUrl(result.hash));
    narrate("Share link copied");
  }, [narrate, source]);

  const copyRecipe = useCallback(async () => {
    await navigator.clipboard.writeText(source);
    narrate("Recipe copied");
  }, [narrate, source]);

  const unlockKey = useCallback(
    async (fpr: string) => {
      await unlockVaultForUse(fpr, {
        openPgpPassphrase: "",
        skipSession: getToolkitPrefs().sessionOff,
      });
      setSessionTick((n) => n + 1);
    },
    []
  );

  const lockKey = useCallback((fpr: string) => {
    sessionEvict(fpr);
    setSessionTick((n) => n + 1);
  }, []);

  const insertUnlockCell = useCallback(
    (fpr: string, kind: "agent.unlock" | "agent.pub" = "agent.unlock") => {
      const short = `@${(fpr.slice(-8) || "me").toLowerCase()}`;
      const slot = kind === "agent.unlock" ? "$me" : short;
      const recipe = `${kind} ${fpr} | out ${slot}`;
      const { ast } = compileRecipe(recipe);
      if (!ast) return;
      setChains((prev) => {
        const next = [...prev, ...(ast.chains?.length ? ast.chains : [{ steps: ast.steps || [] }])];
        setFocusedCell(next.length - 1);
        return next;
      });
      setSheet(null);
    },
    []
  );

  /** Insert/replace `in $label` at the start of `cell`. */
  const insertSlotRef = useCallback(
    (cell: number, label: string) => {
      const clean = String(label || "").replace(/^\$/, "");
      if (!clean) return;
      if (stepsAt(cell)[0]?.name === "in") {
        updateStepParams(cell, 0, "ref", `@${clean}`);
      } else {
        insertOpAt(cell, 0, "in", { params: { ref: `@${clean}` } });
      }
    },
    [stepsAt, updateStepParams, insertOpAt]
  );

  const clearSlot = useCallback((label: string) => {
    kernelRef.current.slots.deleteSlot(label);
    setKernelEpoch((n) => n + 1);
  }, []);

  /**
   * What the share in a slot says about itself, and only that.
   *
   * The recovery generator needs the threshold, count and set id off this
   * machine's own share, and those four facts are the whole of what leaves
   * the kernel here — the mnemonic itself is resolved and dropped inside this
   * callback, never returned, so no share ever rides React state or a prop
   * into a component tree. `readShareHeader` answers null for anything that
   * is not a share, which is the honest answer for a slot holding something
   * else: the caller's refusal names that state rather than typing it.
   */
  const shareFacts = useCallback(
    (label: string) => {
      void kernelEpoch;
      const slots = kernelRef.current.slots;
      if (!slots.has(label)) return null;
      const value = slots.resolve(label);
      return value?.type === "text" ? readShareHeader(String(value.data)) : null;
    },
    [kernelEpoch]
  );

  const clearAllSlots = useCallback(() => {
    kernelRef.current.slots.clear();
    setKernelEpoch((n) => n + 1);
  }, []);

  const filteredOps = useMemo(() => {
    const q = opsFilter.trim().toLowerCase();
    const all = listSteps();
    if (!q) return all;
    return all.filter(
      (s: { name: string; doc?: string; toolbox?: string }) =>
        s.name.includes(q) ||
        (s.doc || "").toLowerCase().includes(q) ||
        (s.toolbox || "").toLowerCase().includes(q)
    );
  }, [opsFilter]);

  /*
   * `unlockedCount` was here, and it is gone rather than rewired.
   *
   * It counted `sessionList().length` and had exactly one reader: a header
   * inside the Keys tray, which needed the tray open *and* that tab selected
   * before the number existed on screen. The shell now derives the same count
   * from `keyViews` — the one list that also draws the rows, feeds the tab's
   * badge and feeds the run bar's chip — so keeping this would be a second
   * derivation of one number, which is the drift the key-power vocabulary was
   * introduced to remove. See `loadedCount` in `lib/toolkit/key-power.js`.
   */

  const usesPgp = useMemo(
    () =>
      chains.some((c) =>
        (c.steps || []).some((s) =>
          ["gpg.encrypt", "gpg.symencrypt", "gpg.decrypt", "gpg.sign"].includes(s.name)
        )
      ),
    [chains]
  );

  const setBoundRecipients = useCallback(
    (recs: ResolvedRecipient[]) => {
      boundRecipientsRef.current = recs;
      setSessionTick((n) => n + 1);
    },
    []
  );

  return {
    title,
    setTitle,
    chains,
    focusedCell,
    setFocusedCell,
    inputText,
    setInputText,
    ciphertext,
    setCiphertext,
    shareRows,
    setShareRows,
    sharePassphrase,
    setSharePassphrase,
    gpgPassphrase,
    setGpgPassphrase,
    envelopeArmored,
    setEnvelopeArmored,
    keypairMaterial,
    setKeypairMaterial,
    pgpMode,
    setPgpMode,
    sessionEncryptProfile: profileForMode(pgpMode),
    boundRecipients: boundRecipientsRef.current,
    vaultKeys,
    opsFilter,
    setOpsFilter,
    filteredOps,
    runStatus,
    runError,
    // What the polite live region holds. `text` is a subset of what the status
    // line says — never the per-cell ticker — and `n` is what makes a repeat
    // of the same sentence a fresh announcement rather than a silent no-op.
    announcement,
    announce,
    busy,
    runProgress,
    stopRun,
    runningCell,
    quorumState,
    peerLinks,
    cancelQuorum,
    sheet,
    setSheet,
    ceremonyStage,
    setCeremonyStage,
    ceremonyParams,
    updateCeremonyParams,
    ceremonyRun,
    ceremonyError,
    openCeremony,
    runCeremonyStage,
    ceremonyView,
    slotMetas,
    cellStatuses,
    cellTimings,
    cellProvenance,
    cellOutputs,
    cellErrors,
    cellWarnings,
    cellRunErrors,
    publishArtifact,
    readinessBlocker,
    unmetForCell,
    usesPgp,
    presets: PRESETS,
    compiled,
    source,
    formatFingerprint,
    appendOp,
    insertOpAt,
    nestOp,
    addBranchWithStep,
    replaceStep,
    reorderStem,
    reorderNest,
    updateStepParams,
    updateNestStepParams,
    removeStep,
    removeNestStep,
    removeBranch,
    insertMessaging,
    loadPreset,
    restoreNotebook,
    appendPreset,
    appendPresetPair,
    applyCellRecipeText,
    setCellPeer,
    loadRecipeText,
    cellRecipeSource,
    upgradeCellRecipe,
    addCell,
    appendRecipeCell,
    deleteCell,
    runFrom,
    runCellOnly,
    clearSensitive,
    resetNotebook,
    copyShareLink,
    startSession,
    removeFromRoom,
    handoffTick,
    handoffWho,
    pendingHandoffs,
    skippedCells,
    autoOffered,
    offerCell,
    sendCellResult,
    acceptHandoff,
    shareNotebook,
    attestManifest,
    attestation,
    proposedNotebook,
    adoptProposedNotebook,
    dismissProposedNotebook,
    copyRecipe,
    unlockKey,
    lockKey,
    insertUnlockCell,
    insertSlotRef,
    clearSlot,
    clearAllSlots,
    shareFacts,
    toolkitPrefs,
    updateToolkitPrefs,
    refreshVault,
    setBoundRecipients,
    cellInputNeeds,
    cellRecipientSlots,
    sessionList,
  };
}
