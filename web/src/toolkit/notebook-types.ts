export type RecipeStep = {
  name: string;
  params?: Record<string, unknown>;
  body?: RecipeStep[];
  branches?: { selector?: string; member?: string; body?: RecipeStep[] }[];
};

export type RecipeChain = { steps: RecipeStep[] };

export type CellStatus = "idle" | "ok" | "error" | "stale" | "running";

export type VaultKeyRow = {
  fingerprint: string;
  uid?: string;
  email?: string;
  protection?: string;
  /** Epoch ms, or null when the key does not expire. */
  expires?: number | null;
};

export type SlotMeta = {
  label: string;
  type: string;
  fingerprint?: string;
  sensitive?: boolean;
  recipients?: number;
  length?: number;
};

export type PgpMode = "auto" | "modern" | "compatible";

export type StepCryptoProfile = "auto" | "modern" | "compatible" | "custom";

export type ResolvedRecipient = {
  fingerprint: string;
  armoredKey: string;
  label?: string;
  email?: string;
  /** Advertises SEIPD v2 (RFC 9580 features bit) — see lib/pgp/capabilities.js. */
  modernCapable?: boolean;
};

export type ArtifactTile = {
  label?: string;
  filename?: string;
  content: string;
  sensitive?: boolean;
  role?: string;
  traits?: { fingerprint?: string };
  /** Directory slot once published (design v2 §21b) — persists on the kernel-held tile. */
  publishedAs?: string;
  directoryUrl?: string;
  /**
   * Network/WebRTC pipeline type and its structured payload. Present only on
   * artifacts produced by the WebRTC toolbox; the type selects which manager
   * widget renders the row instead of a raw JSON preview.
   */
  netType?: string;
  netKind?: string;
  netData?: unknown;
  /** Explicit `out`/`text`/`inspect` tile — a sensitive value here may be revealed. */
  revealable?: boolean;
  /** Structured `inspect` body — absent for sensitive tips by design. */
  inspectSnapshot?: unknown;
  /**
   * JOSE body from the `jose.*` ops — header, claims, and the op's own
   * verification verdict. The verdict cannot be re-derived in the UI (only
   * the op that ran knows whether a key checked out), so it travels with the
   * artifact rather than being inferred from the token text.
   */
  jose?: unknown;
  /**
   * The refined pipeline type at emit time, and the tags/metadata the artifact
   * kind registry (§32) matches on. `pipeType` has ridden on every artifact
   * since the type system landed; this projection dropped it until §32, which
   * is why the fields above grew as parallel discriminators for a
   * discriminator that already existed.
   */
  pipeType?: { base?: string; kind?: string; which?: string; alg?: string };
  tags?: string[];
  shareIndex?: number;
  mime?: string;
  encoding?: string;
  bytes?: Uint8Array;
  stepName?: string;
  disposition?: string;
};
