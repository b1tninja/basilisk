import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createKernel } from "../lib/toolkit/kernel.js";
import {
  PRESETS,
  compileRecipe,
  serializeRecipe,
  validateRecipe,
  unresolvedRecipients,
} from "../lib/toolkit/recipe.js";
import { listSteps, getStep } from "../lib/toolkit/registry.js";
import {
  MESSAGING_STARTERS,
  parseToolkitHash,
  hashForNotebook,
  toolkitShareUrl,
} from "../lib/toolkit/fragment.js";
import { PROFILE_AUTO, PROFILE_COMPATIBLE, PROFILE_MODERN } from "../lib/pgp/encrypt.js";
import { listKeys } from "../lib/vault.js";
import { unlockVaultForUse } from "../lib/vault-unlock.js";
import { sessionEvict, sessionList } from "../lib/vault-session.js";
import { getToolkitPrefs } from "../lib/toolkit/prefs.js";
import { formatFingerprint } from "../lib/utils.js";
import type {
  ArtifactTile,
  CellStatus,
  PgpMode,
  RecipeChain,
  RecipeStep,
  SlotMeta,
  VaultKeyRow,
} from "./notebook-types";

function emptyChains(): RecipeChain[] {
  return [{ steps: [] }];
}

function profileForMode(mode: PgpMode) {
  if (mode === "modern") return { ...PROFILE_MODERN };
  if (mode === "compatible") return { ...PROFILE_COMPATIBLE };
  return { ...PROFILE_AUTO };
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

export function useNotebook() {
  const kernelRef = useRef(createKernel());
  const [title, setTitle] = useState("Untitled notebook");
  const [chains, setChains] = useState<RecipeChain[]>(emptyChains);
  const [focusedCell, setFocusedCell] = useState(0);
  const [inputText, setInputText] = useState("");
  const [ciphertext, setCiphertext] = useState("");
  const [pgpMode, setPgpMode] = useState<PgpMode>("auto");
  const [vaultKeys, setVaultKeys] = useState<VaultKeyRow[]>([]);
  const [sessionTick, setSessionTick] = useState(0);
  const [opsFilter, setOpsFilter] = useState("");
  const [runStatus, setRunStatus] = useState("");
  const [runError, setRunError] = useState("");
  const [busy, setBusy] = useState(false);
  const [sheet, setSheet] = useState<"keyring" | "variables" | "crypto" | null>(null);
  const [kernelEpoch, setKernelEpoch] = useState(0);
  const boundRecipientsRef = useRef<{ fingerprint: string; armoredKey: string }[]>([]);

  const refreshVault = useCallback(async () => {
    try {
      const keys = await listKeys();
      setVaultKeys(
        (keys || []).map((k: VaultKeyRow) => ({
          fingerprint: k.fingerprint,
          uid: k.uid,
          email: k.email,
          protection: k.protection,
        }))
      );
    } catch {
      setVaultKeys([]);
    }
  }, []);

  useEffect(() => {
    void refreshVault();
  }, [refreshVault]);

  const loadFromHash = useCallback(() => {
    const action = parseToolkitHash(window.location.hash || "");
    if (!action || action.kind === "empty") return;
    if (action.kind === "starter") {
      const starter = MESSAGING_STARTERS[action.starter];
      if (!starter) return;
      const { ast } = compileRecipe(starter.recipe);
      if (ast) {
        setTitle(starter.title);
        setChains(ast.chains?.length ? ast.chains : [{ steps: ast.steps || [] }]);
        setFocusedCell(0);
      }
      if (action.inputs?.ciphertext) setCiphertext(String(action.inputs.ciphertext));
      if (action.inputs?.text) setInputText(String(action.inputs.text));
      return;
    }
    if (action.kind === "preset") {
      const p = PRESETS.find((x: { id: string }) => x.id === action.id);
      if (!p) return;
      const { ast } = compileRecipe(p.recipe);
      if (ast) {
        setTitle(p.title);
        setChains(ast.chains?.length ? ast.chains : [{ steps: ast.steps || [] }]);
        setFocusedCell(0);
      }
      return;
    }
    if (action.kind === "recipe") {
      const { ast } = compileRecipe(action.recipe);
      if (ast) {
        setTitle("Shared notebook");
        setChains(ast.chains?.length ? ast.chains : [{ steps: ast.steps || [] }]);
        setFocusedCell(0);
      }
    }
  }, []);

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
      if (needs.includes("text") && !inputText.trim()) badges.push("needs input");
      if (needs.includes("gpg") && !ciphertext.trim()) badges.push("needs ciphertext");
      const slots = cellRecipientSlots(chain);
      const filled = boundRecipientsRef.current.filter((r) => r?.fingerprint).length;
      if (slots > 0 && filled < slots) badges.push("needs recipients");
      return badges;
    },
    [chains, inputText, ciphertext, sessionTick, kernelEpoch]
  );

  const readinessBlocker = useMemo(() => {
    for (let i = 0; i < chains.length; i++) {
      if (!chains[i]?.steps?.length) continue;
      const u = unmetForCell(i);
      if (u.includes("needs input")) return "Add input text before running";
      if (u.includes("needs ciphertext")) return "Paste OpenPGP ciphertext before running";
      if (u.includes("needs recipients")) return "Add recipients before running";
      if (u[0]) return u[0];
    }
    return "";
  }, [chains, unmetForCell]);

  const slotMetas: SlotMeta[] = useMemo(() => {
    void kernelEpoch;
    return (kernelRef.current.listSlots?.() || []).map(
      (m: { label: string; type?: string; fingerprint?: string }) => ({
        label: String(m.label || "").replace(/^@/, ""),
        type: String(m.type || "unknown"),
        fingerprint: m.fingerprint,
      })
    );
  }, [kernelEpoch]);

  const cellStatuses: CellStatus[] = useMemo(() => {
    void kernelEpoch;
    return chains.map((_, i) => kernelRef.current.getCellStatus(i) as CellStatus);
  }, [chains, kernelEpoch]);

  const cellOutputs: ArtifactTile[][] = useMemo(() => {
    void kernelEpoch;
    return chains.map((_, i) =>
      (kernelRef.current.getCellOutputs(i) || []).map(
        (a: ArtifactTile & { role?: string }) => ({
          label: a.label,
          filename: a.filename,
          content: String(a.content ?? ""),
          sensitive: !!a.sensitive,
          role: a.role,
        })
      )
    );
  }, [chains, kernelEpoch]);

  const setCellSteps = useCallback((cellIndex: number, nextSteps: RecipeStep[]) => {
    setChains((prev) => {
      const copy = prev.map((c) => ({ steps: [...(c.steps || [])] }));
      while (copy.length <= cellIndex) copy.push({ steps: [] });
      copy[cellIndex] = { steps: nextSteps };
      return copy;
    });
  }, []);

  const appendOp = useCallback(
    (opName: string) => {
      const spec = getStep(opName);
      if (!spec) return;
      const step: RecipeStep = { name: opName, params: {} };
      for (const p of spec.params || []) {
        if (p.default !== undefined) step.params![p.name] = p.default;
      }
      const next = [...steps, step];
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
    bindings.inputs = inputs;
    const recs = boundRecipientsRef.current.filter((r) => r?.fingerprint);
    if (recs.length) {
      bindings.recipientKeysArmored = recs.map((r) => r.armoredKey);
      bindings.recipientFingerprints = recs.map((r) => r.fingerprint);
    }
    return bindings;
  }, [chains, focusedCell, pgpMode, inputText, ciphertext]);

  const runFrom = useCallback(
    async (from: number) => {
      if (readinessBlocker) {
        setRunError(readinessBlocker);
        return;
      }
      if (!compiled.validation?.ok) {
        setRunError(
          (compiled.validation?.errors || []).map((e: { message: string }) => e.message).join(" · ") ||
            "Recipe invalid"
        );
        return;
      }
      setBusy(true);
      setRunError("");
      setRunStatus("Running…");
      try {
        const bindings = buildBindings();
        for (let i = from; i < chains.length; i++) {
          if (!chains[i]?.steps?.length) continue;
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
      }
    },
    [buildBindings, chains, compiled.validation, readinessBlocker]
  );

  const clearSensitive = useCallback(() => {
    kernelRef.current.clearSensitive?.();
    for (const e of sessionList()) sessionEvict(e.fingerprint);
    setInputText("");
    setCiphertext("");
    boundRecipientsRef.current = [];
    setSessionTick((n) => n + 1);
    setKernelEpoch((n) => n + 1);
    setRunStatus("Cleared sensitive data");
    setRunError("");
  }, []);

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
    (recs: { fingerprint: string; armoredKey: string }[]) => {
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
    pgpMode,
    setPgpMode,
    vaultKeys,
    opsFilter,
    setOpsFilter,
    filteredOps,
    runStatus,
    runError,
    busy,
    sheet,
    setSheet,
    slotMetas,
    cellStatuses,
    cellOutputs,
    readinessBlocker,
    unmetForCell,
    unlockedCount,
    usesPgp,
    presets: PRESETS,
    compiled,
    source,
    formatFingerprint,
    appendOp,
    removeStep,
    insertMessaging,
    loadPreset,
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
    refreshVault,
    setBoundRecipients,
    cellInputNeeds,
    cellRecipientSlots,
    sessionList,
  };
}
