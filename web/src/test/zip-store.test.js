import { describe, expect, it } from "vitest";
import {
  buildZipStore,
  crc32,
  sanitizeFilename,
  uniquifyFilenames,
} from "../lib/zip-store.js";

describe("uniquifyFilenames", () => {
  it("leaves unique names alone", () => {
    expect(uniquifyFilenames(["a.txt", "b.txt"])).toEqual(["a.txt", "b.txt"]);
  });

  it("suffixes duplicates before the extension", () => {
    expect(uniquifyFilenames(["share.txt", "share.txt", "share.txt"])).toEqual([
      "share.txt",
      "share (2).txt",
      "share (3).txt",
    ]);
  });
});

describe("sanitizeFilename", () => {
  it("preserves normal suggested filenames", () => {
    expect(sanitizeFilename("recovery key.pem")).toBe("recovery key.pem");
  });

  it("removes paths, control characters, and invalid filename characters", () => {
    expect(sanitizeFilename("../keys\\secret\u0000:key?.pem")).toBe(
      "..-keys-secret-key-.pem"
    );
  });

  it("uses the fallback for blank and dot-only names", () => {
    expect(sanitizeFilename("   ", "output.bin")).toBe("output.bin");
    expect(sanitizeFilename("..", "output.bin")).toBe("output.bin");
  });
});

describe("buildZipStore", () => {
  it("embeds file contents and names", () => {
    const zip = buildZipStore([
      { name: "one.txt", content: "hello" },
      { name: "two.txt", content: "world" },
    ]);
    expect(zip[0]).toBe(0x50); // 'P'
    expect(zip[1]).toBe(0x4b); // 'K'
    const asText = new TextDecoder().decode(zip);
    expect(asText).toContain("one.txt");
    expect(asText).toContain("two.txt");
    expect(asText).toContain("hello");
    expect(asText).toContain("world");
    // End of central directory signature
    const sig = 0x06054b50;
    let found = false;
    for (let i = 0; i < zip.length - 3; i++) {
      if (
        zip[i] === (sig & 0xff) &&
        zip[i + 1] === ((sig >>> 8) & 0xff) &&
        zip[i + 2] === ((sig >>> 16) & 0xff) &&
        zip[i + 3] === ((sig >>> 24) & 0xff)
      ) {
        found = true;
        break;
      }
    }
    expect(found).toBe(true);
  });

  it("crc32 matches known vector", () => {
    // CRC-32 of "123456789" is 0xCBF43926
    expect(crc32(new TextEncoder().encode("123456789"))).toBe(0xcbf43926);
  });
});
