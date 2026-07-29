import { createElement, type ReactElement } from "react";
import { createRoot, type Root } from "react-dom/client";

/** Stable React roots keyed by host element (legacy island remounts). */
const roots = new WeakMap<Element, Root>();

export function ensureRoot(host: Element): Root {
  let root = roots.get(host);
  if (!root) {
    root = createRoot(host);
    roots.set(host, root);
  }
  return root;
}

export function renderIsland(host: Element | null, node: ReactElement | null): void {
  if (!host) return;
  const root = ensureRoot(host);
  if (node == null) {
    root.render(createElement("div"));
    return;
  }
  root.render(node);
}

export function unmountIsland(host: Element | null): void {
  if (!host) return;
  const root = roots.get(host);
  if (!root) return;
  root.unmount();
  roots.delete(host);
}
