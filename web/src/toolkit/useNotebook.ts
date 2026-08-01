import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createKernel } from "../lib/toolkit/kernel.js";
import { beginApprovalRun, clearApprovalGrants } from "../lib/toolkit/approval-gate.js";
import { clearActivity } from "../lib/toolkit/activity-log.js";
import {
  PRESETS,
  compileRecipe,
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

/** One roster row — mirror of lib/quorum/roster's ConnectionPeerRow. */
export type QuorumPeerRow = {
  id: string;
  fingerprint: string;
  state: "new" | "connecting" | "connected" | "disconnected" | "failed" | "closed";
  authenticated: boolean;
  via?: string;
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

  const steps = chains[focusedCell]?.steps || [];

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
        label: String(m.label || "").replace(/^@/, ""),
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
   */
  const cellErrors: { message: string; stepIndex: number }[][] = useMemo(() => {
    void kernelEpoch;
    return chains.map((chain) => {
      if (!chain?.steps?.length) return [];
      try {
        const v = validateRecipe({ chains: [chain], steps: chain.steps, source: "" });
        return (v.errors || []).map((e: { message: string; stepIndex?: number }) => ({
          message: String(e.message),
          stepIndex: typeof e.stepIndex === "number" ? e.stepIndex : -1,
        }));
      } catch {
        return [];
      }
    });
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
    if (tile.role !== "public-key") {
      throw new Error("publishArtifact: only public-key exports are publishable");
    }
    const { publishArmoredKey } = await import("../lib/toolkit/hkp-ops.js");
    const { fingerprint, directoryUrl } = await publishArmoredKey(tile.content);
    tile.publishedAs = fingerprint ? `@${fingerprint.slice(-8)}` : "@pub";
    tile.directoryUrl = directoryUrl;
    setKernelEpoch((n) => n + 1);
    // Returned, not just stored: the Activity log records where an outward
    // action *went* (§36), and a log that says "Published" without naming the
    // directory answers the wrong half of the question at 2am.
    return { fingerprint, directoryUrl };
  }, []);

  const setCellSteps = useCallback((cellIndex: number, nextSteps: RecipeStep[]) => {
    setChains((prev) => {
      const copy = prev.map((c) => ({ steps: [...(c.steps || [])] }));
      while (copy.length <= cellIndex) copy.push({ steps: [] });
      copy[cellIndex] = { steps: nextSteps };
      return copy;
    });
  }, []);

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
    (opName: string, opts?: { decode?: boolean; params?: Record<string, unknown> }) => {
      const step = makeStep(opName, opts);
      if (!step) return;
      setCellSteps(focusedCell, [...steps, step]);
    },
    [focusedCell, makeStep, setCellSteps, steps]
  );

  const insertOpAt = useCallback(
    (
      index: number,
      opName: string,
      opts?: { decode?: boolean; params?: Record<string, unknown> }
    ) => {
      const step = makeStep(opName, opts);
      if (!step) return;
      const at = Math.max(0, Math.min(steps.length, index));
      const next = [...steps.slice(0, at), step, ...steps.slice(at)];
      setCellSteps(focusedCell, next);
    },
    [focusedCell, makeStep, setCellSteps, steps]
  );

  /** Append (or insert at body index) inside a tee/foreach nest. */
  const nestOp = useCallback(
    (
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
      const next = steps.map((s, i) => {
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
      setCellSteps(focusedCell, next);
    },
    [focusedCell, makeStep, setCellSteps, steps]
  );

  /**
   * Create a selector branch on a tee *together with* its first step. A branch
   * is not valid recipe text until it has a step (`- :public |` alone doesn't
   * parse), so the two land as one mutation — the UI "arms" the branch
   * client-side until then, same as activeGap.
   */
  const addBranchWithStep = useCallback(
    (
      stem: number,
      selector: string,
      opName: string,
      opts?: { decode?: boolean; params?: Record<string, unknown> }
    ) => {
      const step = makeStep(opName, opts);
      if (!step) return;
      const next = steps.map((s, i) => {
        if (i !== stem) return s;
        const branches = [...(s.branches || [])];
        branches.push({
          selector,
          member: selector.replace(/^:/, ""),
          body: [step],
        });
        return { ...s, branches };
      });
      setCellSteps(focusedCell, next);
    },
    [focusedCell, makeStep, setCellSteps, steps]
  );

  /** Swap one stem step for another op ("peek instead of an empty tee"). */
  const replaceStep = useCallback(
    (stem: number, opName: string) => {
      const step = makeStep(opName);
      if (!step || !steps[stem]) return;
      setCellSteps(
        focusedCell,
        steps.map((s, i) => (i === stem ? step : s))
      );
    },
    [focusedCell, makeStep, setCellSteps, steps]
  );

  const updateNestStepParams = useCallback(
    (
      stem: number,
      branch: number | null,
      bodyIndex: number,
      name: string,
      value: string | number | boolean
    ) => {
      const next = steps.map((s, i) => {
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
      setCellSteps(focusedCell, next);
    },
    [focusedCell, setCellSteps, steps]
  );

  const removeNestStep = useCallback(
    (stem: number, branch: number | null, bodyIndex: number) => {
      const next = steps.map((s, i) => {
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
          if (!br?.body) return s;
          br.body = br.body.filter((_, j) => j !== bodyIndex);
        } else if (clone.body) {
          clone.body = clone.body.filter((_, j) => j !== bodyIndex);
        }
        return clone;
      });
      setCellSteps(focusedCell, next);
    },
    [focusedCell, setCellSteps, steps]
  );

  /**
   * Remove a whole selector branch from a tee. Returns true when the tee stem
   * was dropped along with its last branch (see `stepsWithBranchRemoved`), so
   * the caller can say that out loud and offer the undo.
   */
  const removeBranch = useCallback(
    (stem: number, branch: number) => {
      const next = stepsWithBranchRemoved(steps, stem, branch);
      if (next.steps === steps) return false;
      setCellSteps(focusedCell, next.steps);
      return next.droppedStem;
    },
    [focusedCell, setCellSteps, steps]
  );

  const reorderStem = useCallback(
    (from: number, to: number) => {
      if (from === to || from < 0 || from >= steps.length) return;
      const next = [...steps];
      const [moved] = next.splice(from, 1);
      let insertAt = to;
      if (from < to) insertAt = to - 1;
      insertAt = Math.max(0, Math.min(next.length, insertAt));
      next.splice(insertAt, 0, moved);
      setCellSteps(focusedCell, next);
    },
    [focusedCell, setCellSteps, steps]
  );

  /** Reorder within a tee/foreach body or selector branch. `toBody` is gap splice index. */
  const reorderNest = useCallback(
    (stem: number, branch: number | null, fromBody: number, toBody: number) => {
      if (fromBody === toBody) return;
      const next = steps.map((s, i) => {
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
      setCellSteps(focusedCell, next);
    },
    [focusedCell, setCellSteps, steps]
  );

  const updateStepParams = useCallback(
    (stepIndex: number, name: string, value: string | number | boolean) => {
      const next = steps.map((s, i) =>
        i === stepIndex
          ? { ...s, params: { ...(s.params || {}), [name]: value } }
          : s
      );
      setCellSteps(focusedCell, next);
    },
    [focusedCell, setCellSteps, steps]
  );

  const removeStep = useCallback(
    (stepIndex: number) => {
      setCellSteps(
        focusedCell,
        steps.filter((_, i) => i !== stepIndex)
      );
    },
    [focusedCell, setCellSteps, steps]
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
      next[cellIndex] = { steps: [...(chain.steps || [])] };
      return next;
    });
    setRunError("");
    return true;
  }, []);

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
    bindings.receipt = { recipeSource: source, label: title };
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
          await kernelRef.current.runCell(i, chains[i], bindings);
        }
        setKernelEpoch((n) => n + 1);
        setRunStatus("Done");
      } catch (err) {
        setKernelEpoch((n) => n + 1);
        setRunError(err instanceof Error ? err.message : String(err));
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
      const slot = kind === "agent.unlock" ? "@me" : short;
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

  /** Insert/replace `in @label` at the start of the focused cell. */
  const insertSlotRef = useCallback(
    (label: string) => {
      const clean = String(label || "").replace(/^@/, "");
      if (!clean) return;
      if (steps[0]?.name === "in") {
        updateStepParams(0, "ref", `@${clean}`);
      } else {
        insertOpAt(0, "in", { params: { ref: `@${clean}` } });
      }
    },
    [steps, updateStepParams, insertOpAt]
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
    steps,
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
    loadRecipeText,
    cellRecipeSource,
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
