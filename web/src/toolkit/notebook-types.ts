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
};

export type SlotMeta = {
  label: string;
  type: string;
  fingerprint?: string;
};

export type PgpMode = "auto" | "modern" | "compatible";

export type ArtifactTile = {
  label?: string;
  filename?: string;
  content: string;
  sensitive?: boolean;
};
