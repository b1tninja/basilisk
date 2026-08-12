/**
 * The recipe shapes, taken from the parser that produces them.
 *
 * These were declared here by hand and drifted from `recipe.js`, which is the
 * only thing that makes a chain: this copy had `params` optional and no
 * `start`/`end`, and — the expensive one — no `peer` or `publish`. A chain
 * carrying a `@peer` header was therefore *invalid* under the type the hook
 * uses, so the assignment that silently dropped the header typechecked, and
 * the one that restored it did not.
 *
 * Re-exported rather than redeclared, for the same reason `CellAssign` writes
 * the same two fields the source view writes: one representation, two
 * surfaces onto it, so they cannot disagree about what a chain is.
 */
export type { RecipeStep, RecipeChain, RecipeParams } from "../lib/toolkit/recipe.js";

export type CellStatus = "idle" | "ok" | "error" | "stale" | "running";

export type VaultKeyRow = {
  fingerprint: string;
  uid?: string;
  email?: string;
  protection?: string;
  /**
   * What this record actually holds: OpenPGP armor, an openssh-key-v1 block,
   * or a bare private JWK (§28a/§28d).
   *
   * Absent means a legacy record, which is definitionally pgp — the same
   * reading `agent-ops.js` gives it. It was absent from this type entirely
   * while the Keyring read `k.kind` through a cast six times over, so the badge
   * that distinguishes the three was dead code and ssh and raw keys rendered as
   * PGP with a `/key?fpr=` link that leads nowhere for them. Worse, they were
   * offered as candidates to sign a session invite, which only PGP armor can
   * do; `sessionKeyChoices` is the reader that needs this to be here.
   */
  kind?: "pgp" | "ssh" | "raw";
  /**
   * When this key stops being good, or null when it never does.
   *
   * Two shapes, because two sources fill it: the vault stores an ISO
   * timestamp, and a session-only key carries epoch ms. `expiryInstant` in
   * `artifact-readouts.js` — which every reader goes through — takes a string,
   * a number or a Date, so both have always worked at runtime. This said
   * "Epoch ms" and typed only the number, describing one of its two callers.
   */
  expires?: string | number | null;
  /**
   * The OpenSSH public line, on `ssh` records only.
   *
   * Public material, which is why it rides on the row rather than behind an
   * export: `authorized_keys` and pasting into GitHub are what an ssh key is
   * mostly *for*. The vault has stored it since kinds landed and this
   * projection dropped it, so the Keys tray had no way to offer what
   * `/my-keys` already did.
   */
  publicLine?: string;
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
  /**
   * Facts a step computed that the body cannot say — a fingerprint, the
   * genkey-style algorithm tag, the public JWK of a keypair whose body is
   * deliberately withheld. Open-ended because `traits` is the one bag every
   * projection copies wholesale, which is why named fields added beside it
   * have twice reached nothing.
   */
  traits?: Record<string, unknown> & { fingerprint?: string };
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
