import { describe, expect, it } from "vitest";
import { splitArmoredMessages } from "../lib/pgp/armor.js";

describe("splitArmoredMessages", () => {
  const block = (n) =>
    `-----BEGIN PGP MESSAGE-----\nVersion: test\n\nPAYLOAD${n}\n-----END PGP MESSAGE-----`;

  it("returns a single block", () => {
    const blocks = splitArmoredMessages(block(1));
    expect(blocks).toHaveLength(1);
    expect(blocks[0]).toContain("PAYLOAD1");
  });

  it("splits multiple blocks with junk between", () => {
    const text = `${block(1)}\n\n# note\n\n${block(2)}\r\n${block(3)}`;
    const blocks = splitArmoredMessages(text);
    expect(blocks).toHaveLength(3);
    expect(blocks[0]).toContain("PAYLOAD1");
    expect(blocks[1]).toContain("PAYLOAD2");
    expect(blocks[2]).toContain("PAYLOAD3");
  });

  it("returns empty for no MESSAGE blocks", () => {
    expect(splitArmoredMessages("hello")).toEqual([]);
    expect(splitArmoredMessages("-----BEGIN PGP PUBLIC KEY BLOCK-----\n-----\n-----END PGP PUBLIC KEY BLOCK-----")).toEqual([]);
  });
});
