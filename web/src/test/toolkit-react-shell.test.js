/**
 * Smoke: shared cn() helper used by shadcn UI components.
 */
import { describe, expect, it } from "vitest";
import { cn } from "../lib/cn.ts";

describe("toolkit React shell modules", () => {
  it("cn merges conflicting Tailwind classes", () => {
    expect(cn("px-2", "px-4")).toBe("px-4");
  });
});
