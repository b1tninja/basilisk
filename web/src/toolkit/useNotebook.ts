import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createKernel } from "../lib/toolkit/kernel.js";
import { beginApprovalRun, clearApprovalGrants } from "../lib/toolkit/approval-gate.js";
import { clearActivity } from "../lib/toolkit/activity-log.js";
import {
  PRESETS,
  compileRecipe,
  migrateRecipe,
  serializeRecipe,
  validateRecipe,
  unresolvedRecipients,
} from "../lib/toolkit/recipe.js";
import {
  stitchPresetPair,
  resolvePresetPair,
  bridgeModeMeta,
} from "../lib/toolkit/conjugate-stitch.js";
import { listSteps, getStep } from "../lib/toolkit/registry.js";
import { wiredForCell } from "../lib/toolkit/slot-graph.js";
import {
  ceremonyCells,
  ceremonyTitle,
  tileForSlot,
  type CeremonyStageId,
} from "../lib/toolkit/ceremony.js";
import {
  MESSAGING_STARTERS,
  parseToolkitHash,
  hashForNotebook,
  toolkitShareUrl,
} from "../lib/toolkit/fragment.js";
import { profileForMode } from "../lib/pgp/profile-from-step.js";
import { listKeys } from "../lib/vault.js";
import { unlockVaultForUse } from "../lib/vault-unlock.js";
import { sessionEvict, sessionList } from "../lib/vault-session.js";
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
  ResolvedRecipient,
  SlotMeta,
  VaultKeyRow,
} from "./notebook-types";

/** One roster row — mirror of lib/notebook/roster's ConnectionPeerRow. */
export type QuorumPeerRow = {
  id: string;
  fingerprint: string;
  state: "new" | "connecting" | "connected" | "disconnected" | "failed" | "closed";
  authenticated: boolean;
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
  connected: number;
  expected: number;
  status: string;
  peers: QuorumPeerRow[];
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
 */
export function chainsWithCellSteps(
  chains: RecipeChain[],
  cellIndex: number,
  nextSteps: RecipeStep[]
): RecipeChain[] {
  const copy = chains.map((c) => ({ steps: [...(c.steps || [])] }));
  while (copy.length <= cellIndex) copy.push({ steps: [] });
  copy[cellIndex] = { steps: nextSteps };
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
    connected: 0,
    expected: 0,
    status: "",
    peers: [],
  });
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
    "workspace" | "prefs" | "ceremony" | "sharecheck" | "integrity" | null
  >(null);
  const [kernelEpoch, setKernelEpoch] = useState(0);
  const [toolkitPrefs, setToolkitPrefsState] = useState<ToolkitPrefs>(() => getToolkitPrefs());
  const boundRecipientsRef = useRef<ResolvedRecipient[]>([]);

  const refreshVault = useCallback(async () => {
    try {
      const keys = await listKeys();
      const rows: VaultKeyRow[] = (keys || []).map((k: VaultKeyRow) => ({
        fingerprint: k.fingerprint,
        uid: k.uid,
        email: k.email,
        protection: k.protection,
        // Carried so GpgKeyBinder (§39b) can warn before you sign with a key
        // that is about to expire — the vault has always known this, the
        // projection just dropped it.
        expires: k.expires ?? null,
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

  /** Compile `text` and replace the notebook's title/chains with it. Returns whether it parsed. */
  const loadRecipeText = useCallback((title: string, text: string) => {
    const { ast } = compileRecipe(text);
    if (!ast) return false;
    setTitle(title);
    setChains(ast.chains?.length ? ast.chains : [{ steps: ast.steps || [] }]);
    setFocusedCell(0);
    return true;
  }, []);

  const loadFromHash = useCallback(() => {
    const action = parseToolkitHash(window.location.hash || "");
    if (!action || action.kind === "empty") return;
    if (action.kind === "starter") {
      const starter = MESSAGING_STARTERS[action.starter];
      if (!starter) return;
      loadRecipeText(starter.title, starter.recipe);
      if (action.inputs?.ciphertext) setCiphertext(String(action.inputs.ciphertext));
      if (action.inputs?.text) setInputText(String(action.inputs.text));
      return;
    }
    if (action.kind === "preset") {
      const p = PRESETS.find((x: { id: string }) => x.id === action.id);
      if (!p) return;
      loadRecipeText(p.title, p.recipe);
      return;
    }
    if (action.kind === "recipe") {
      loadRecipeText("Shared notebook", action.recipe);
    }
  }, [loadRecipeText]);

  useEffect(() => {
    loadFromHash();
    const onHash = () => loadFromHash();
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, [loadFromHash]);

  const source = useMemo(() => serializeRecipe({ chains }), [chains]);

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
    (opName: string, opts?: { decode?: boolean; params?: Record<string, unknown> }) => {
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
      opts?: { decode?: boolean; params?: Record<string, unknown> }
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
      opts?: { decode?: boolean; params?: Record<string, unknown> }
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
      opts?: { decode?: boolean; params?: Record<string, unknown>; at?: number }
    ) => {
      // Nested tee/foreach is rejected by the parser (RECIPE.md, v1). The
      // shelf already hides them for nested carets; this catches drag-drops.
      if (opName === "tee" || opName === "foreach") return;
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
      opts?: { decode?: boolean; params?: Record<string, unknown> }
    ) => {
      const step = makeStep(opName, opts);
      if (!step) return;
      const next = stepsAt(cell).map((s, i) => {
        if (i !== stem) return s;
        const branches = [...(s.branches || [])];
        branches.push({
          selector,
          member: selector.replace(/^:/, ""),
          body: [step],
        });
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
    ).map((c: RecipeChain) => ({ steps: [...(c.steps || [])] }));
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
      setRunError(st.errors.join(" · "));
      return null;
    }
    const { ast } = compileRecipe(st.recipe);
    if (!ast) return null;
    const loaded: RecipeChain[] = (ast.chains?.length
      ? ast.chains
      : [{ steps: ast.steps || [] }]
    ).map((c: RecipeChain) => ({ steps: [...(c.steps || [])] }));
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
    setRunStatus(meta.toast);
    setRunError("");
    return st;
  }, []);

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
      setRunError(
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
      // `peer` and `publish` come with the chain and have to be carried over.
      // Rebuilding from `steps` alone dropped them, which made a `@peer`
      // header impossible to write anywhere in the product: the grammar reads
      // it (`recipe-parse.js` sets `chain.peer`), `serializeChain` writes it
      // back out, `planRun` places cells by it and `placementGate` enforces it
      // — and this one assignment threw it away between the parse and the
      // state, so typing `@mara publish` parsed cleanly and then vanished.
      next[cellIndex] = {
        steps: [...(chain.steps || [])],
        ...(chain.peer == null ? {} : { peer: chain.peer }),
        ...(chain.publish ? { publish: true } : {}),
      };
      return next;
    });
    setRunError("");
    return true;
  }, []);

  /**
   * Assign a cell to a peer, or take the assignment off.
   *
   * The header was reachable only by typing it, which made placement a feature
   * you had to already know the grammar to use. This is the same edit the text
   * makes — it sets the fields `serializeChain` writes as `@peer` /
   * `@peer publish` — so the two views cannot drift: there is one
   * representation and both surfaces move it.
   *
   * `peer: null` clears the header rather than writing an empty one. An
   * unassigned cell has no `peer` field at all, which is what `planRun` reads
   * as "everyone", and a `@` with nothing after it is not a recipe.
   *
   * `publish` is only meaningful alongside a peer — it says this cell's output
   * may leave the machine that made it — so clearing the peer clears it too
   * rather than leaving a modifier attached to nobody.
   */
  const setCellPeer = useCallback(
    (cellIndex: number, peer: string | null, publish = false) => {
      setChains((prev) => {
        const next = [...prev];
        const chain = next[cellIndex];
        if (!chain) return prev;
        const { peer: _p, publish: _pub, ...rest } = chain as Record<string, unknown>;
        next[cellIndex] = peer
          ? { ...rest, peer, ...(publish ? { publish: true } : {}) }
          : { ...rest };
        return next as typeof prev;
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
        text ?? serializeRecipe({ chains: [chains[cellIndex] || { steps: [] }] });
      const upgrade = recipeUpgrade(before);
      if (!upgrade) return null;
      if (!applyCellRecipeText(cellIndex, upgrade.recipe)) return null;
      // Named, not silent. A migration that renamed four steps and said
      // nothing is indistinguishable from a button that did not work, and the
      // rewrite is exactly the kind of change a reader wants to audit before
      // pressing Run — `migrateRecipe` returns the counts for this.
      setRunStatus(
        `Upgraded: ${upgrade.changes
          .map((c) => `${c.from} → ${c.to}${c.count > 1 ? ` ×${c.count}` : ""}`)
          .join(", ")}`
      );
      return upgrade;
    },
    [chains, applyCellRecipeText]
  );

  const cellRecipeSource = useCallback(
    (cellIndex: number) =>
      serializeRecipe({ chains: [chains[cellIndex] || { steps: [] }] }),
    [chains]
  );

  const addCell = useCallback(() => {
    setChains((prev) => {
      const next = [...prev, { steps: [] }];
      setFocusedCell(next.length - 1);
      return next;
    });
  }, []);

  const deleteCell = useCallback((index: number) => {
    setChains((prev) => {
      if (prev.length <= 1) return [{ steps: [] }];
      const next = prev.filter((_, i) => i !== index);
      setFocusedCell((f) => Math.min(f, next.length - 1));
      return next;
    });
    kernelRef.current.clearCellOutputs?.(index);
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
    if (needs.includes("gpg") || ciphertext.trim()) {
      inputs.gpg = {
        armoredMessages: ciphertext.trim() ? [ciphertext.trim()] : [],
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
    envelopeArmored,
    keypairMaterial,
    source,
    title,
  ]);

  const runFrom = useCallback(
    async (from: number) => {
      if (!compiled.validation?.ok) {
        setRunError(
          (compiled.validation?.errors || []).map((e: { message: string }) => e.message).join(" · ") ||
            "Recipe invalid"
        );
        return;
      }
      const runnable = chains
        .map((c, i) => i)
        .filter((i) => i >= from && (chains[i]?.steps?.length ?? 0) > 0);
      setBusy(true);
      setRunError("");
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
      try {
        const bindings = buildBindings();
        for (let n = 0; n < runnable.length; n++) {
          if (stopRunRef.current) {
            setRunStatus("Stopped");
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
            if (n === 0) {
              setRunError(msg);
              setRunStatus("Blocked");
              return;
            }
            setKernelEpoch((x) => x + 1);
            setRunStatus(
              `Paused before cell [${i}] — ${msg}. Cells above it ran; Run from here once its inputs are in.`
            );
            return;
          }
          setRunProgress({ cell: n + 1, total: runnable.length });
          setRunningCell(i);
          setRunStatus(`Running cell ${i}…`);
          at = i;
          await kernelRef.current.runCell(i, chains[i], bindings);
        }
        setKernelEpoch((n) => n + 1);
        setRunStatus("Done");
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
        setRunError(at >= 0 ? `Cell [${at}] — ${msg}` : msg);
        setRunStatus("Failed");
      } finally {
        setBusy(false);
        setRunProgress(null);
        setRunningCell(null);
      }
    },
    [buildBindings, chains, compiled.validation, unmetForCell]
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

  const runCeremonyStage = useCallback(
    async (stage: CeremonyStageId) => {
      const cells = ceremonyCells(ceremonyParams);
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
        setChains(compiled.map((c) => ({ steps: [...(c.steps || [])] })));
        setFocusedCell(at);
        const bindings = {
          ...buildBindings(),
          receipt: {
            recipeSource: cells.map((c) => c.recipe).join("\n\n"),
            label: ceremonyParams.label || ceremonyTitle(ceremonyParams),
          },
        };
        await kernelRef.current.runCell(at, compiled[at], bindings);
        setKernelEpoch((n) => n + 1);
        setCeremonyRun("done");
      } catch (err) {
        setKernelEpoch((n) => n + 1);
        setCeremonyError(err instanceof Error ? err.message : String(err));
        setCeremonyRun("error");
      }
    },
    [buildBindings, ceremonyParams]
  );

  /** Which notebook cell each ceremony stage's outputs live in. */
  const ceremonyCellIndex = useMemo(() => {
    const cells = ceremonyCells(ceremonyParams);
    return {
      split: cells.findIndex((c) => c.stage === "split"),
      verify: cells.findIndex((c) => c.stage === "verify"),
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
    setEnvelopeArmored("");
    boundRecipientsRef.current = [];
    setSessionTick((n) => n + 1);
    setKernelEpoch((n) => n + 1);
    setRunStatus("Cleared sensitive data");
    setRunError("");
  }, []);

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

  const copyShareLink = useCallback(async () => {
    const result = hashForNotebook(source);
    if (result.ok === false) {
      setRunStatus(result.reason || "Cannot share this recipe in a link");
      return;
    }
    await navigator.clipboard.writeText(toolkitShareUrl(result.hash));
    setRunStatus("Share link copied");
  }, [source]);

  const copyRecipe = useCallback(async () => {
    await navigator.clipboard.writeText(source);
    setRunStatus("Recipe copied");
  }, [source]);

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

  const unlockedCount = useMemo(() => {
    void sessionTick;
    return sessionList().length;
  }, [sessionTick]);

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
    cellOutputs,
    cellErrors,
    cellWarnings,
    cellRunErrors,
    publishArtifact,
    readinessBlocker,
    unmetForCell,
    unlockedCount,
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
    deleteCell,
    runFrom,
    clearSensitive,
    resetNotebook,
    copyShareLink,
    copyRecipe,
    unlockKey,
    lockKey,
    insertUnlockCell,
    insertSlotRef,
    clearSlot,
    clearAllSlots,
    toolkitPrefs,
    updateToolkitPrefs,
    refreshVault,
    setBoundRecipients,
    cellInputNeeds,
    cellRecipientSlots,
    sessionList,
  };
}
