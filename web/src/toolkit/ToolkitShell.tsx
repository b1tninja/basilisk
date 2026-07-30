import { useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
import {
  Link2,
  Eraser,
  Plus,
  MoreHorizontal,
  KeyRound,
  LayoutGrid,
  ArrowDownToLine,
  ArrowUpFromLine,
  SlidersHorizontal,
  Cable,
} from "lucide-react";
import { Button } from "@/components/ui/button";
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
import { setClipboardReadGate } from "../lib/toolkit/clipboard-ops.js";
import { cn } from "@/lib/cn";
import { useNotebook } from "./useNotebook";
import { RecipientBinderHost } from "./RecipientBinderHost";
import {
  OpsShelf,
  DocsFooter,
  CellTypeErrors,
  GpgKeyBinder,
  ConnectionsPanel,
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
  SessionStrip,
  TopBar,
  type SuiteTone,
  type SuiteDetail,
} from "./widgets/index";
import { getStep } from "../lib/toolkit/registry.js";
import { compileRecipe, projectTypeForMember } from "../lib/toolkit/recipe.js";
import { stepOverridesProfile } from "../lib/pgp/profile-from-step.js";
import {
  cellPipelineTip,
  nestedTipFor,
  selectorGhostsFor,
  tipFitFor,
} from "../lib/toolkit/suggest.js";
import { getTrust, setTrust, type TrustLevel } from "../lib/trust.js";
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
import type { ArmedBranch, ChipPath, ChipStemView } from "./widgets/RecipeChipFlow";
import type { RecipeChain, RecipeStep } from "./notebook-types";

type CellView = "pipeline" | "source";

type SuiteState = "verified" | "unverified" | "error";

/** Extends the OpenPGP/WebCrypto/SSS CAST suite map with a client-side WebAuthn capability check. */
type ToolkitSuiteStatus = {
  openpgp: SuiteState;
  webcrypto: SuiteState;
  sss: SuiteState;
  webauthn: SuiteState;
};

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

const STATUS_DOT_VAR: Record<CellStatus, string> = {
  ok: "var(--success)",
  error: "var(--error)",
  stale: "var(--warn)",
  running: "var(--brand)",
  idle: "var(--muted-foreground)",
};

/** One-line status: dot color + plain-language text, replacing the old badge pile. */
function describeCellStatus(
  status: CellStatus,
  timing: { ranAt: number; durationMs: number } | null,
  now: number
): string {
  if (status === "running") return "running…";
  if (status === "error") return timing ? `failed ${relativeTimeShort(timing.ranAt, now)}` : "failed";
  if (status === "stale") return "edited since last run";
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

export function ToolkitShell() {
  const nb = useNotebook();
  const [chipEdit, setChipEdit] = useState<ChipPath | null>(null);
  /** One-shot field to autofocus once chipEdit lands (design v2 §22b). */
  const [focusParamHint, setFocusParamHint] = useState<string | null>(null);
  useEffect(() => {
    if (!focusParamHint) return;
    const t = window.setTimeout(() => setFocusParamHint(null), 50);
    return () => window.clearTimeout(t);
  }, [focusParamHint]);
  /** Cell the live quorum exchange was opened in — SessionStrip pins there (§21a). */
  const [quorumCell, setQuorumCell] = useState<number | null>(null);
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
    if (name === "tee" || name === "foreach") {
      setPendingInsert({ cell, stem, branch: null, body: 0 });
    }
  };
  /**
   * §32d — clipboard.read's permission moment. Asked every run and never
   * remembered (clipboard contents change silently between runs). The Allow
   * handler reads the clipboard itself so the read happens inside the click's
   * transient activation.
   */
  const [clipboardAsk, setClipboardAsk] = useState<{
    resolve: (text: string | null) => void;
  } | null>(null);
  /** §32d — clipboard.write toast ("ok" weight, 2s auto-dismiss). */
  const [clipboardWrote, setClipboardWrote] = useState<number | null>(null);
  useEffect(() => {
    setClipboardReadGate(
      () =>
        new Promise<string | null>((resolve) => {
          setClipboardAsk({ resolve });
        })
    );
    const onWrote = (ev: Event) => {
      setClipboardWrote((ev as CustomEvent<{ chars: number }>).detail?.chars ?? 0);
    };
    window.addEventListener("basilisk:clipboard-wrote", onWrote);
    return () => {
      setClipboardReadGate(null);
      window.removeEventListener("basilisk:clipboard-wrote", onWrote);
    };
  }, []);
  useEffect(() => {
    if (clipboardWrote == null) return;
    const t = window.setTimeout(() => setClipboardWrote(null), 2000);
    return () => window.clearTimeout(t);
  }, [clipboardWrote]);
  const [cellViews, setCellViews] = useState<Record<number, CellView>>({});
  const [rawDrafts, setRawDrafts] = useState<Record<number, string>>({});
  const [presetMenuOpen, setPresetMenuOpen] = useState(false);
  const [trayOpen, setTrayOpen] = useState(true);
  const [trayTab, setTrayTab] = useState<
    "keys" | "slots" | "connections" | "outputs" | "inputs" | "params"
  >("keys");
  /** One-shot Load-template undo — set right before a destructive replace, cleared once used or superseded. */
  const [undoSnapshot, setUndoSnapshot] = useState<{
    title: string;
    chains: RecipeChain[];
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
  const [trustTick, setTrustTick] = useState(0);
  const applyTrust = (fpr: string, level: TrustLevel) => {
    setTrust(fpr, level);
    setTrustTick((n) => n + 1);
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
      width = Math.round(
        Math.max(OPS_PANE_LIMITS.min, Math.min(OPS_PANE_LIMITS.max, ev.clientX - rect.left))
      );
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

  const onOpsSplitterDoubleClick = () => {
    setOpsWidth(OPS_PANE_LIMITS.def);
    saveToolkitLayout({ opsW: null });
  };

  const [now, setNow] = useState(() => Date.now());
  const [workspaces, setWorkspaces] = useState<ToolkitWorkspace[]>(() => listWorkspaces());
  const [workspaceError, setWorkspaceError] = useState("");
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
    });
    if (!saved.ok) {
      setWorkspaceError(saved.reason);
      return;
    }
    setWorkspaceError("");
    setWorkspaces(listWorkspaces());
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
            (s: { name: string }) => s.name !== "tee" && s.name !== "foreach"
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
          setFocusParamHint("turn");
          return true;
        }
      }
    }
    return false;
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
          subtitle={`${nb.chains.length} cell${nb.chains.length === 1 ? "" : "s"}`}
          suiteStatus={suitePillStatus}
          suiteDetail={suiteDetail}
        >
            <PresetMenu
              presets={nb.presets}
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
              triggerClassName="h-auto rounded-[6px] px-[11px] py-[5px] text-[length:11.5px] font-medium"
            />
            <MenuPopover
              label={<MoreHorizontal className="opacity-80" />}
              align="end"
              triggerClassName="h-auto w-auto rounded-[6px] p-[6px]"
              items={[
                {
                  id: "workspace",
                  label: "Workspace library",
                  onSelect: () => nb.setSheet("workspace"),
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
                { id: "keys", label: "My Keys", href: "/my-keys" },
              ]}
            />
        </TopBar>

        {/* Run bar — run controls + the one global readiness summary, matching design v2 §18b/19g/21a */}
        <RunBar
          state={
            nb.busy &&
            (nb.quorumState.phase === "offering" || nb.quorumState.phase === "waiting")
              ? "waiting-peer"
              : nb.busy
                ? "running"
                : nb.readinessBlocker
                  ? "blocked"
                  : "idle"
          }
          blocker={nb.readinessBlocker}
          runDisabled={!nb.compiled.validation?.ok}
          focusedCell={nb.focusedCell}
          progress={nb.runProgress}
          waitingCell={nb.runningCell ?? undefined}
          sessionInvite={nb.quorumState.invite}
          onCopyInvite={() => void navigator.clipboard.writeText(nb.quorumState.invite)}
          onCancelSession={() => nb.cancelQuorum()}
          onRunAll={() => void nb.runFrom(0)}
          onRunFrom={(from) => void nb.runFrom(from)}
          onStop={() => nb.stopRun()}
          onBind={() => {
            setTrayOpen(true);
            setTrayTab("inputs");
          }}
        >
          <Button variant="ghost" onClick={() => void nb.copyShareLink()}>
            <Link2 />
            Copy link
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

        {undoSnapshot ? (
          <div className="flex items-center gap-2 border-b border-[var(--border)] bg-[var(--surface-raised)] px-3.5 py-1.5">
            <span className="text-[length:11.5px] text-[var(--muted-foreground)]">
              Replaced the notebook with a template.
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

        <div className="flex min-h-0 flex-1" ref={opsWorkspaceRef}>
          {opsCollapsed ? (
            <button
              type="button"
              className="flex w-[28px] shrink-0 items-center justify-center border-r border-[var(--border)] bg-[color-mix(in_srgb,var(--surface-raised)_88%,var(--surface))] text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
              title="Expand Toolkit panel"
              onClick={toggleOpsCollapsed}
            >
              <span className="[writing-mode:vertical-rl] text-[11px] font-semibold tracking-wide">
                Toolkit
              </span>
            </button>
          ) : (
            <div className="relative flex min-h-0" style={{ width: opsWidth }}>
              <OpsShelf
                className="w-full"
                ops={shelfOps}
                filter={nb.opsFilter}
                onFilter={nb.setOpsFilter}
                tipFit={tipModel.tipFit}
                tip={{
                  base: tipModel.tip.base,
                  kind: tipModel.tip.kind,
                  encoding: tipModel.tip.encoding,
                }}
                caretBanner={
                  <div className="border-b border-l-2 border-[var(--border)] border-l-[var(--caret)] bg-[color-mix(in_srgb,var(--caret)_6%,transparent)] px-2.5 py-2">
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
                    nb.addBranchWithStep(ab.stem, ab.selector, name, opts);
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
                      nb.nestOp(path.stem, path.branch ?? null, name, {
                        ...opts,
                        at: path.body,
                      });
                      // Keep the caret in the same scope, after the new step.
                      setPendingInsert({ ...path, body: path.body + 1 });
                      return;
                    }
                    nb.insertOpAt(path.stem, name, opts);
                    focusNestAfterInsert(path.cell, name, path.stem);
                    return;
                  }
                  const endStem = nb.chains[nb.focusedCell]?.steps?.length ?? 0;
                  nb.appendOp(name, opts);
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
            <div
              role="separator"
              aria-orientation="vertical"
              aria-label="Resize Toolkit panel"
              title="Drag to resize · double-click to reset"
              className={cn(
                "w-[5px] shrink-0 cursor-col-resize bg-transparent hover:bg-[var(--brand)]",
                opsDragging && "bg-[var(--brand)]"
              )}
              onPointerDown={onOpsSplitterPointerDown}
              onDoubleClick={onOpsSplitterDoubleClick}
            />
          ) : null}

          {/* Notebook */}
          <section
            className="flex min-w-0 flex-1 flex-col"
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
                          <span
                            className="h-[6px] w-[6px] shrink-0 rounded-full"
                            style={{ background: STATUS_DOT_VAR[status] }}
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
                        <div className="ml-auto flex gap-1">
                          <Button
                            size="sm"
                            disabled={!!needs.length || !chain.steps?.length || nb.busy}
                            onClick={(e) => {
                              e.stopPropagation();
                              nb.setFocusedCell(i);
                              void nb.runFrom(i);
                            }}
                          >
                            Run
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="text-[var(--error)]"
                            disabled={nb.chains.length <= 1}
                            title="Delete cell"
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

                        {focused && needs.length ? (
                          <ReadinessBar
                            blockers={needs
                              .map((n) => ({
                                need: n,
                                spec: NEED_BLOCKER[n] || {
                                  priority: 2,
                                  label: n.replace(/^needs\s+/, "") + " is missing",
                                  action: "Open tray",
                                  tray: "inputs" as const,
                                },
                              }))
                              .sort((a, b) => a.spec.priority - b.spec.priority)
                              .map(({ need, spec }) => ({
                                id: need,
                                label: spec.label,
                                action: spec.action,
                                onAction: () => {
                                  setTrayOpen(true);
                                  setTrayTab(spec.tray);
                                },
                              }))}
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
                            onCopyInvite={() =>
                              void navigator.clipboard.writeText(nb.quorumState.invite)
                            }
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
                            errors={nb.cellErrors[i] || []}
                            steps={chain.steps || []}
                            onFocusStep={(si) => {
                              nb.setFocusedCell(i);
                              setChipEdit({ cell: i, stem: si, branch: null, body: null });
                            }}
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
                                placeholder="random 32 | base64 | out @secret"
                              />
                              <p className="text-xs text-[var(--muted-foreground)]">
                                Edit the cell recipe as text — applies on blur.
                              </p>
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
                                s.name === "tee" || s.name === "foreach";
                              return {
                                step: {
                                  name: s.name,
                                  label: spec?.label || s.name,
                                  op: spec || undefined,
                                },
                                hasNest: isNest,
                                nestKind: isNest
                                  ? (s.name as "tee" | "foreach")
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
                                  const sel = !rawSel
                                    ? ":?"
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
                                    nb.addBranchWithStep(stem, selector, name, opts);
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
                                    nb.replaceStep(stem, "peek");
                                  }}
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
                                        from.stem,
                                        from.branch ?? null,
                                        from.body,
                                        to.body
                                      );
                                      return;
                                    }
                                    nb.reorderStem(from.stem, to.stem);
                                  }}
                                  onDropStep={(path, name, opts) => {
                                    nb.setFocusedCell(i);
                                    setPendingInsert(null);
                                    setArmedBranch(null);
                                    if (path.body != null) {
                                      nb.nestOp(
                                        path.stem,
                                        path.branch ?? null,
                                        name,
                                        { ...opts, at: path.body }
                                      );
                                      return;
                                    }
                                    nb.insertOpAt(path.stem, name, opts);
                                    focusNestAfterInsert(i, name, path.stem);
                                    setChipEdit(null);
                                  }}
                                  onRemove={(path) => {
                                    nb.setFocusedCell(i);
                                    if (path.body != null) {
                                      nb.removeNestStep(
                                        path.stem,
                                        path.branch ?? null,
                                        path.body
                                      );
                                    } else {
                                      nb.removeStep(path.stem);
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
                                              nb.removeNestStep(
                                                selected.stem,
                                                selected.branch ?? null,
                                                selected.body
                                              );
                                            } else {
                                              nb.removeStep(selected.stem);
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
                                            selected.stem,
                                            selected.branch ?? null,
                                            selected.body,
                                            name,
                                            value
                                          );
                                        } else {
                                          nb.updateStepParams(
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
                                              selectedStep.name === "rtc.ice"
                                                ? focusParamHint
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

                        {(nb.cellOutputs[i] || []).length > 0 ? (
                          <OutputList
                            className="mt-3"
                            outputs={(nb.cellOutputs[i] || []).map((a, oi) => {
                              const label =
                                a.label || a.filename || `output ${oi + 1}`;
                              const publishable = a.role === "public-key";
                              const fpr = a.traits?.fingerprint || "";
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
                                kind:
                                  a.role === "share"
                                    ? "share"
                                    : a.role === "diagnostic"
                                      ? "diag"
                                      : publishable
                                        ? "key"
                                        : "text",
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
                                onConfigureTurn: openRtcIceTurnParam,
                                onCopy: () =>
                                  void navigator.clipboard.writeText(a.content),
                                publishable,
                                publishConfirmLabel: fpr
                                  ? `${fpr.slice(0, 4)}…${fpr.slice(-3)}`
                                  : undefined,
                                publishedAs: a.publishedAs,
                                directoryUrl: a.directoryUrl,
                                onPublish: publishable
                                  ? () => nb.publishArtifact(i, oi)
                                  : undefined,
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
          </section>

        {/* Session tray — persistent, not modal. Replaces the old Keyring/Variables/Crypto sheets. */}
        {trayOpen ? (
          <div className="flex w-[328px] shrink-0 flex-col border-l border-[var(--border)] bg-[var(--surface)]">
            <div
              role="tablist"
              aria-label="Session tray"
              className="flex items-center gap-1 border-b border-[var(--border)] px-2 pt-2"
            >
              {(
                [
                  // §35 — icon + label. Outputs/Inputs deliberately mirror
                  // each other (down-into-tray vs. up-out-of-notebook).
                  { id: "keys" as const, label: "Keys", Icon: KeyRound },
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
              <>
                <div className="flex items-center justify-between gap-2 border-b border-[var(--border)] p-3">
                  <div>
                    <h3 className="text-sm font-bold">Keyring</h3>
                    <p className="mt-0.5 text-[length:10.5px] text-[var(--muted-foreground)]">
                      Unlock into the agent session, or insert{" "}
                      <code>agent.unlock</code>/<code>agent.pub</code> cells. Full vault management
                      is on{" "}
                      <a className="text-[var(--brand)] underline" href="/my-keys">
                        My Keys
                      </a>
                      .
                    </p>
                  </div>
                  {nb.unlockedCount > 0 ? (
                    <Button
                      variant="outline"
                      className="h-auto shrink-0 rounded-[7px] border-[var(--error)] px-[9px] py-[4px] text-[length:11px] font-semibold text-[var(--error)]"
                      onClick={lockAllSessions}
                    >
                      Lock all
                    </Button>
                  ) : null}
                </div>
                <ScrollArea className="flex-1 px-3">
                  {!nb.vaultKeys.length ? (
                    <p className="py-4 text-sm text-[var(--muted-foreground)]">
                      No keys in My Keys yet. Generate one on My Keys or use{" "}
                      <code>agent.save</code>.
                    </p>
                  ) : (
                    <ul className="space-y-3 py-3">
                      {nb.vaultKeys.map((k) => {
                        void trustTick;
                        const session = nb
                          .sessionList()
                          .find((e) => e.fingerprint === k.fingerprint);
                        const unlocked = !!session;
                        const trust = getTrust(k.fingerprint);
                        return (
                          <li
                            key={k.fingerprint}
                            className="rounded-[9px] border border-[var(--border)] bg-[var(--surface-raised)] p-3"
                          >
                            <div className="font-semibold">{k.uid || k.email || "Key"}</div>
                            <a
                              className="font-mono text-xs text-[var(--brand)]"
                              href={`/key?fpr=${k.fingerprint}`}
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              {nb.formatFingerprint(k.fingerprint)}
                            </a>
                            <div className="mt-1 text-xs text-[var(--muted-foreground)]">
                              {k.protection || "device"}
                              {session ? (
                                <>
                                  {" · unlocked · "}
                                  <span className="font-mono text-[length:10.5px] text-[var(--warn)]">
                                    {formatCountdown(session.expiresAt - now)} left
                                  </span>
                                </>
                              ) : null}
                            </div>
                            <div className="mt-2 flex flex-wrap gap-1">
                              {unlocked ? (
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  onClick={() => nb.lockKey(k.fingerprint)}
                                >
                                  Lock
                                </Button>
                              ) : (
                                <Button
                                  size="sm"
                                  variant="secondary"
                                  onClick={() => void nb.unlockKey(k.fingerprint)}
                                >
                                  Unlock
                                </Button>
                              )}
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => nb.insertUnlockCell(k.fingerprint, "agent.unlock")}
                              >
                                Unlock → cell
                              </Button>
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => nb.insertUnlockCell(k.fingerprint, "agent.pub")}
                              >
                                Pub → cell
                              </Button>
                            </div>
                            <div className="mt-2 flex items-center gap-1">
                              <span className="text-[length:10.5px] text-[var(--muted-foreground)]">
                                Trust:
                              </span>
                              {(["trusted", "marginal", "never"] as TrustLevel[]).map((level) => (
                                <Button
                                  key={level}
                                  variant={trust?.level === level ? "secondary" : "ghost"}
                                  className={cn(
                                    "h-auto rounded-md px-[8px] py-[2px] text-[length:10px] font-semibold capitalize",
                                    trust?.level === level &&
                                      level === "trusted" &&
                                      "text-[var(--success)]",
                                    trust?.level === level &&
                                      level === "never" &&
                                      "text-[var(--error)]"
                                  )}
                                  onClick={() => applyTrust(k.fingerprint, level)}
                                >
                                  {level}
                                </Button>
                              ))}
                            </div>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </ScrollArea>
              </>
            ) : null}

            {trayTab === "slots" ? (
              <>
                <div className="border-b border-[var(--border)] p-3">
                  <h3 className="text-sm font-bold">Slots</h3>
                  <p className="mt-0.5 text-[length:10.5px] text-[var(--muted-foreground)]">
                    Live <code>@slots</code> from the notebook kernel — metas only, no private
                    armor. Cleared by <strong>Clear session</strong>.
                  </p>
                </div>
                <ScrollArea className="flex-1 px-3">
                  {!nb.slotMetas.length ? (
                    <p className="py-4 text-sm text-[var(--muted-foreground)]">
                      No slots yet — run a cell that ends with <code>out @label</code>.
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
                              onClick={() => nb.insertSlotRef(m.label)}
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
                <div className="border-b border-[var(--border)] p-3">
                  <h3 className="text-sm font-bold">Connections</h3>
                  <p className="mt-0.5 text-[length:10.5px] text-[var(--muted-foreground)]">
                    Whatever is live right now, and the actions that close or repair it.
                    Separate from Outputs, which holds what a run already produced.
                  </p>
                </div>
                <ScrollArea className="flex-1">
                  <ConnectionsPanel
                    session={{
                      phase: nb.quorumState.phase,
                      room: nb.quorumState.room,
                      role: nb.quorumState.role,
                      invite: nb.quorumState.invite,
                      connected: nb.quorumState.connected,
                      expected: nb.quorumState.expected,
                      peers: nb.quorumState.peers,
                    }}
                    onCopyInvite={() =>
                      void navigator.clipboard.writeText(nb.quorumState.invite)
                    }
                    onClose={() => nb.cancelQuorum()}
                    onRestartIce={() => void restartLiveIce()}
                  />
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
                              sizeBytes: new TextEncoder().encode(a.content).length,
                              sensitive: a.sensitive,
                              revealable: a.revealable,
                              content: a.content,
                              netType: a.netType,
                              inspectSnapshot: a.inspectSnapshot,
                              jose: a.jose,
                              netKind: a.netKind,
                              netData: a.netData,
                              preview: a.sensitive ? undefined : oneLinePreview(a.content),
                              onCopy: () => copyText(a.content),
                            }))}
                          />
                        </div>
                      ))
                    ) : (
                      <p className="text-[length:11px] italic text-[var(--muted-foreground)]">
                        No outputs yet — run a cell that ends in{" "}
                        <code className="font-mono">out @label</code>.
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
                                disabled={nb.shareRows.length <= 1}
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
          </div>
        ) : (
          <button
            type="button"
            className="flex w-[28px] shrink-0 items-center justify-center border-l border-[var(--border)] bg-[color-mix(in_srgb,var(--surface-raised)_88%,var(--surface))] text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
            title="Expand session tray"
            onClick={() => setTrayOpen(true)}
          >
            <span className="[writing-mode:vertical-rl] text-[11px] font-semibold tracking-wide">
              Tray
            </span>
          </button>
        )}
        </div>

        {/* Workspace library sheet */}
        <Sheet
          open={nb.sheet === "workspace"}
          onOpenChange={(o) => nb.setSheet(o ? "workspace" : null)}
        >
          <SheetContent side="right" className="w-full sm:max-w-md">
            <SheetHeader>
              <div className="flex items-center justify-between gap-2">
                <SheetTitle>Workspace library</SheetTitle>
                <Button
                  className="h-auto rounded-[7px] px-[11px] py-[5px] text-[length:11.5px] font-bold"
                  onClick={saveCurrentWorkspace}
                >
                  + Save current
                </Button>
              </div>
              <SheetDescription>
                Named recipes saved in this browser — title and steps only, never Inputs, kernel
                slots, or private keys.
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
                  {workspaces.map((ws) => (
                    <li
                      key={ws.id}
                      className="flex items-center justify-between gap-3 rounded-[9px] border border-[var(--border)] bg-[var(--surface)] px-[11px] py-[9px]"
                    >
                      <div className="min-w-0">
                        <div className="truncate text-[12.5px] font-bold">{ws.title}</div>
                        <div className="text-[length:10.5px] text-[var(--muted-foreground)]">
                          {relativeTime(ws.updatedAt)} · {workspaceStepCount(ws.recipe)} steps
                        </div>
                      </div>
                      <Button
                        variant="secondary"
                        className="h-auto shrink-0 rounded-md px-[9px] py-[4px] text-[10.5px] font-semibold"
                        onClick={() => {
                          nb.loadRecipeText(ws.title, ws.recipe);
                          nb.setSheet(null);
                        }}
                      >
                        Load
                      </Button>
                    </li>
                  ))}
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
                  accept=".json,.txt,.recipe"
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
