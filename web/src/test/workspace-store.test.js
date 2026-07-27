import { describe, expect, it } from "vitest";
import {
  WORKSPACE_MAX_ENTRIES,
  WORKSPACE_STORE_KEY,
  deleteWorkspace,
  exportWorkspaceBlob,
  getWorkspace,
  listWorkspaces,
  parseWorkspaceFile,
  saveWorkspace,
  workspaceFingerprint,
} from "../lib/toolkit/workspace-store.js";

/** @returns {{ getItem: (k: string) => string|null, setItem: (k: string, v: string) => void, _data: Record<string, string> }} */
function memoryStorage() {
  /** @type {Record<string, string>} */
  const data = {};
  return {
    _data: data,
    getItem(k) {
      return Object.prototype.hasOwnProperty.call(data, k) ? data[k] : null;
    },
    setItem(k, v) {
      data[k] = String(v);
    },
  };
}

describe("workspace-store", () => {
  it("round-trips save / list / get / delete", () => {
    const storage = memoryStorage();
    const saved = saveWorkspace(
      { title: "Demo", recipe: "input | gpg.encrypt" },
      storage
    );
    expect(saved.ok).toBe(true);
    if (!saved.ok) return;
    expect(saved.workspace.id).toBeTruthy();
    expect(listWorkspaces(storage)).toHaveLength(1);
    expect(getWorkspace(saved.workspace.id, storage)?.title).toBe("Demo");

    const again = saveWorkspace(
      {
        id: saved.workspace.id,
        title: "Demo 2",
        recipe: "gpg.decrypt",
      },
      storage
    );
    expect(again.ok).toBe(true);
    expect(listWorkspaces(storage)).toHaveLength(1);
    expect(getWorkspace(saved.workspace.id, storage)?.title).toBe("Demo 2");

    expect(deleteWorkspace(saved.workspace.id, storage).ok).toBe(true);
    expect(listWorkspaces(storage)).toHaveLength(0);
    expect(storage._data[WORKSPACE_STORE_KEY]).toBe("[]");
  });

  it("refuses private armor in recipe", () => {
    const storage = memoryStorage();
    const result = saveWorkspace(
      {
        title: "Bad",
        recipe:
          "-----BEGIN PGP PRIVATE KEY BLOCK-----\nSECRET\n-----END PGP PRIVATE KEY BLOCK-----",
      },
      storage
    );
    expect(result.ok).toBe(false);
    expect(listWorkspaces(storage)).toHaveLength(0);
  });

  it("exports and parses JSON workspaces", () => {
    const blob = exportWorkspaceBlob({
      v: 1,
      id: "abc",
      title: "Pipe",
      recipe: "random 8 | to hex | out @x",
      updatedAt: "2026-01-01T00:00:00.000Z",
    });
    expect(blob).toContain('"title": "Pipe"');
    const parsed = parseWorkspaceFile(blob);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.workspace.id).toBe("abc");
    expect(parsed.workspace.recipe).toContain("random 8");
  });

  it("parses plain recipe text with filename title", () => {
    const parsed = parseWorkspaceFile("input | gpg.encrypt", {
      filename: "alice-encrypt.recipe",
    });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.workspace.title).toBe("alice-encrypt");
    expect(parsed.workspace.recipe).toBe("input | gpg.encrypt");
  });

  it("enforces library entry cap", () => {
    const storage = memoryStorage();
    for (let i = 0; i < WORKSPACE_MAX_ENTRIES; i++) {
      const r = saveWorkspace(
        { title: `N${i}`, recipe: `random 8 | out @x${i}` },
        storage
      );
      expect(r.ok).toBe(true);
    }
    const overflow = saveWorkspace(
      { title: "overflow", recipe: "random 8 | out @overflow" },
      storage
    );
    expect(overflow.ok).toBe(false);
    expect(listWorkspaces(storage)).toHaveLength(WORKSPACE_MAX_ENTRIES);
  });

  it("fingerprints title and recipe", () => {
    expect(workspaceFingerprint("A", "r")).toBe("A\0r");
    expect(workspaceFingerprint(" A ", " r ")).toBe("A\0r");
  });
});
