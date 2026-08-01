/**
 * `file.read` / `file.save`.
 *
 * The suite runs in `node` (see vitest.config.js — rendering is deliberately
 * out of scope), so this stubs the two browser surfaces these ops touch: the
 * File System Access API, which is the path Chromium takes, and a minimal
 * `document` for the `<input type=file>` / download-anchor fallback everyone
 * else takes. Both are small enough to stub honestly; what is being tested is
 * this module's logic, not the browser's.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  acceptToTypes,
  execFileRead,
  execFileSave,
  saveBytesFor,
  saveNameFor,
} from "../lib/toolkit/file-ops.js";
import { getStep } from "../lib/toolkit/registry.js";
import { compileRecipe, migrateRecipe } from "../lib/toolkit/recipe.js";
import { formatType, inferSourceType, POLYMORPHIC_STEPS } from "../lib/toolkit/types.js";

/**
 * Comments first — this file's own prose names `as=auto` and `fileLooksTextual`
 * repeatedly, so a raw source scan for either would pass on the comment that
 * explains why they are gone.
 * @param {string} t
 */
const stripComments = (t) =>
  t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

/**
 * A `document` with just enough surface for the fallback paths: elements
 * remember their listeners so a test can fire `change`, and track whether they
 * were attached and removed.
 */
function fakeDom() {
  /** @type {*[]} */
  const created = [];
  /** @type {*[]} */
  const attached = [];
  /** @type {{ name: string, bytes: number }[]} */
  const saves = [];

  const makeEl = (tag) => {
    /** @type {Record<string, Function[]>} */
    const listeners = {};
    const el = {
      tagName: tag.toUpperCase(),
      dataset: {},
      files: null,
      clicked: 0,
      removed: false,
      addEventListener(type, fn) {
        (listeners[type] = listeners[type] || []).push(fn);
      },
      click() {
        el.clicked++;
      },
      remove() {
        el.removed = true;
        const i = attached.indexOf(el);
        if (i >= 0) attached.splice(i, 1);
      },
      /** Test-side trigger; not part of the DOM surface the module uses. */
      fire(type) {
        for (const fn of listeners[type] || []) fn();
      },
    };
    created.push(el);
    return el;
  };

  vi.stubGlobal("document", {
    createElement: makeEl,
    body: {
      appendChild(el) {
        attached.push(el);
      },
    },
  });
  vi.stubGlobal("window", {
    dispatchEvent(ev) {
      if (ev?.type === "basilisk:file-saved") saves.push(ev.detail);
      return true;
    },
  });
  if (typeof URL.createObjectURL !== "function") {
    // Node ≥ 20 has these; define them where it does not so the spy below has
    // something to replace.
    /** @type {*} */ (URL).createObjectURL = () => "blob:stub";
    /** @type {*} */ (URL).revokeObjectURL = () => {};
  }
  vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:stub");
  vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});

  return { created, attached, saves, last: () => created[created.length - 1] };
}

/**
 * Install `window.showOpenFilePicker`. Must be set on the stubbed `window`,
 * which is where `hasFsAccess` looks.
 * @param {*} win
 * @param {string} name
 * @param {Uint8Array|string} body
 * @param {string} mime
 */
function stubOpenPicker(win, name, body, mime) {
  const bytes = typeof body === "string" ? new TextEncoder().encode(body) : body;
  const file = {
    name,
    type: mime,
    lastModified: 1700000000000,
    arrayBuffer: async () =>
      bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
  };
  win.showOpenFilePicker = vi.fn(async () => [{ getFile: async () => file }]);
  return win.showOpenFilePicker;
}

/** @param {*} win */
function stubSavePicker(win) {
  /** @type {Uint8Array[]} */
  const written = [];
  const state = { written, closed: false, opts: /** @type {*} */ (null) };
  win.showSaveFilePicker = vi.fn(async (o) => {
    state.opts = o;
    return {
      createWritable: async () => ({
        write: async (chunk) => written.push(new Uint8Array(chunk)),
        close: async () => {
          state.closed = true;
        },
      }),
    };
  });
  return state;
}

/** The stubbed window object, for tests that install pickers on it. */
function win() {
  return /** @type {*} */ (globalThis).window;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("file.read", () => {
  it("brings a file in as bytes by default, with filename and MIME in meta", async () => {
    fakeDom();
    stubOpenPicker(win(), "notes.txt", "hello disk", "text/plain");
    const v = await execFileRead({});
    expect(v.type).toBe("bytes");
    expect(v.data).toEqual(new TextEncoder().encode("hello disk"));
    expect(v.meta.filename).toBe("notes.txt");
    expect(v.meta.mime).toBe("text/plain");
    expect(v.meta.size).toBe(10);
  });

  it("brings a binary file in as bytes, never guessing an encoding", async () => {
    fakeDom();
    const raw = new Uint8Array([0, 1, 2, 250, 251, 255]);
    stubOpenPicker(win(), "blob.bin", raw, "application/octet-stream");
    const v = await execFileRead({});
    expect(v.type).toBe("bytes");
    expect(v.data).toEqual(raw);
  });

  it("marks the value sensitive — a chosen file may well be a private key", async () => {
    fakeDom();
    stubOpenPicker(win(), "id.pem", "-----BEGIN PRIVATE KEY-----", "");
    expect((await execFileRead({})).meta.sensitive).toBe(true);
  });

  it("honours as=bytes on a text file and as=text on a binary one", async () => {
    fakeDom();
    stubOpenPicker(win(), "notes.txt", "hello", "text/plain");
    expect((await execFileRead({ as: "bytes" })).type).toBe("bytes");
    stubOpenPicker(win(), "blob.bin", new Uint8Array([104, 105]), "application/octet-stream");
    const v = await execFileRead({ as: "text" });
    expect(v.type).toBe("text");
    expect(v.data).toBe("hi");
  });

  /**
   * D8, and the reason `as=auto` no longer exists: a declared type is a
   * promise the ops drawer, the chip underlining and `cellErrorsForChains`
   * all spend *before* the run. `auto` sniffed MIME and extension at run
   * time while `inferSourceType` and `effectiveIo`, holding no file, said
   * `bytes` — so a `.pem` arrived as `text` into a chain compiled for bytes.
   *
   * The gate is agreement over the whole enum × a spread of files chosen to
   * straddle the old sniff (`text/plain`, `.pem`, `.json`, a PNG, an empty
   * MIME). `formatType(inferSourceType(...))` and `effectiveIo` are both
   * checked, because they are two separate declarations of the same fact and
   * a fix to one is not a fix to the other.
   */
  it("emits the type it declares, for every as= × file combination", async () => {
    const files = [
      ["notes.txt", "hello disk", "text/plain"],
      ["id.pem", "-----BEGIN PRIVATE KEY-----", "application/x-pem-file"],
      ["r.json", '{"a":1}', "application/json"],
      ["shot.png", new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0, 1, 250]), "image/png"],
      ["nomime", "plain", ""],
    ];
    const spec = getStep("file.read");
    const allowed = spec.params.find((p) => p.name === "as").enum;
    expect(allowed).toEqual(["bytes", "text"]);
    for (const as of allowed) {
      const declared = formatType(inferSourceType("file.read", { as })).split("/")[0];
      expect(spec.effectiveIo({ as }).output, `effectiveIo for as=${as}`).toBe(declared);
      for (const [name, body, mime] of files) {
        fakeDom();
        stubOpenPicker(win(), name, body, mime);
        const v = await execFileRead({ as });
        expect(v.type, `as=${as} on ${name} (${mime || "no mime"})`).toBe(declared);
      }
    }
    // And the default, which is what an unwritten `as=` compiles to.
    const byDefault = formatType(inferSourceType("file.read", {})).split("/")[0];
    expect(byDefault).toBe(spec.params.find((p) => p.name === "as").default);
    fakeDom();
    stubOpenPicker(win(), "id.pem", "-----BEGIN PRIVATE KEY-----", "application/x-pem-file");
    expect((await execFileRead({})).type).toBe(byDefault);
  });

  it("compiles the recipe that used to compile clean and then throw", () => {
    // `base64` is strict — nothing coerces text to bytes — so this chain is
    // only safe because `file.read` now really does hand it bytes.
    const ok = compileRecipe("file.read accept=.pem | base64 | out @b");
    expect(ok.validation.errors).toEqual([]);
    expect(formatType(inferSourceType("file.read", { accept: ".pem" }))).toBe("bytes/opaque");
    // And the text form is refused up front rather than at run time.
    const bad = compileRecipe("file.read accept=.pem as=text | base64 | out @b");
    expect(bad.validation.errors.map((e) => e.message).join(" ")).toMatch(
      /"base64" expects bytes, got text/
    );
  });

  it("names as=auto as retired, and Upgrade rewrites it to as=bytes", () => {
    const errs = compileRecipe("file.read as=auto | out @b").validation.errors;
    expect(errs).toHaveLength(1);
    expect(errs[0].message).toMatch(/as="auto" was removed/);
    expect(errs[0].message).toMatch(/Upgrade recipe/);

    const migrated = migrateRecipe('file.read ".pem" as=auto | out @b');
    expect(migrated.recipe).toBe('file.read ".pem" as=bytes | out @b');
    expect(compileRecipe(migrated.recipe).validation.errors).toEqual([]);
    expect(migrated.changes).toContainEqual({
      from: "file.read as=auto",
      to: "file.read as=bytes",
      count: 1,
    });
  });

  it("leaves other ops' live auto= alone — the rewrite is scoped to the step", () => {
    const src = "random 16 | out @r encoding=auto\n\nfile.read as=auto | out @b";
    const migrated = migrateRecipe(src);
    expect(migrated.recipe).toContain("out @r encoding=auto");
    expect(migrated.recipe).toContain("file.read as=bytes");
  });

  it("reports a dismissed picker as a cancel, not a DOMException", async () => {
    fakeDom();
    win().showOpenFilePicker = vi.fn(async () => {
      const err = new Error("The user aborted a request.");
      err.name = "AbortError";
      throw err;
    });
    await expect(execFileRead({})).rejects.toThrow(/cancelled/);
  });

  it("translates an accept list into the picker's types dict", async () => {
    fakeDom();
    const picker = stubOpenPicker(win(), "k.pem", "x", "application/x-pem-file");
    await execFileRead({ accept: ".pem,.asc" });
    expect(picker.mock.calls[0][0].types[0].accept["application/octet-stream"]).toEqual([
      ".pem",
      ".asc",
    ]);
  });

  it("falls back to <input type=file>, and removes it once resolved", async () => {
    const dom = fakeDom();
    // No showOpenFilePicker — Firefox / Safari / any insecure context.
    const pending = execFileRead({ accept: ".txt" });
    const input = dom.last();
    expect(input.tagName).toBe("INPUT");
    expect(input.type).toBe("file");
    expect(input.accept).toBe(".txt");
    // Off-screen via a data attribute, not an inline style — CSP forbids the latter.
    expect("basiliskFilePicker" in input.dataset).toBe(true);
    expect(input.clicked).toBe(1);
    input.files = [
      {
        name: "a.txt",
        type: "text/plain",
        lastModified: 0,
        arrayBuffer: async () => new TextEncoder().encode("fallback").buffer,
      },
    ];
    input.fire("change");
    const v = await pending;
    expect(v.data).toEqual(new TextEncoder().encode("fallback"));
    expect(input.removed).toBe(true);
    expect(dom.attached).toEqual([]);
  });

  it("treats a dismissed fallback input as a cancel", async () => {
    const dom = fakeDom();
    const pending = execFileRead({});
    dom.last().fire("cancel");
    await expect(pending).rejects.toThrow(/cancelled/);
  });
});

describe("file.save", () => {
  it("writes bytes and passes the value through unchanged, like out", async () => {
    fakeDom();
    const save = stubSavePicker(win());
    const value = { type: "bytes", data: new Uint8Array([1, 2, 3]), meta: {} };
    expect(await execFileSave(value, { name: "x.bin" })).toBe(value);
    expect(save.closed).toBe(true);
    expect(save.written.flatMap((c) => [...c])).toEqual([1, 2, 3]);
  });

  it("encodes text as UTF-8", async () => {
    fakeDom();
    const save = stubSavePicker(win());
    await execFileSave({ type: "text", data: "héllo", meta: {} }, {});
    expect(
      new TextDecoder().decode(Uint8Array.from(save.written.flatMap((c) => [...c])))
    ).toBe("héllo");
  });

  it("chunks large writes rather than materializing one Blob", async () => {
    fakeDom();
    const save = stubSavePicker(win());
    // 2.5 MiB — three writes at the module's 1 MiB stride.
    await execFileSave({ type: "bytes", data: new Uint8Array(2_621_440), meta: {} }, {});
    expect(save.written.length).toBe(3);
    expect(save.written.reduce((n, c) => n + c.length, 0)).toBe(2_621_440);
  });

  it("takes the name from name=, then meta, then a generic fallback", () => {
    expect(
      saveNameFor({ meta: { filename: "from-meta.age" } }, { name: "explicit.bin" })
    ).toBe("explicit.bin");
    expect(saveNameFor({ meta: { filename: "from-meta.age" } }, {})).toBe("from-meta.age");
    expect(saveNameFor({ type: "text", meta: {} }, {})).toBe("output.txt");
    expect(saveNameFor({ type: "bytes", meta: {} }, {})).toBe("output.bin");
  });

  it("suggests that name to the picker", async () => {
    fakeDom();
    const save = stubSavePicker(win());
    await execFileSave(
      { type: "bytes", data: new Uint8Array([1]), meta: { filename: "doc.age" } },
      {}
    );
    expect(save.opts.suggestedName).toBe("doc.age");
  });

  it("reports a dismissed save dialog as a cancel", async () => {
    fakeDom();
    win().showSaveFilePicker = vi.fn(async () => {
      const err = new Error("aborted");
      err.name = "AbortError";
      throw err;
    });
    await expect(
      execFileSave({ type: "bytes", data: new Uint8Array([1]), meta: {} }, {})
    ).rejects.toThrow(/cancelled/);
  });

  it("announces the write toast-weight, like clipboard.write", async () => {
    const dom = fakeDom();
    stubSavePicker(win());
    await execFileSave(
      { type: "bytes", data: new Uint8Array([1, 2]), meta: {} },
      { name: "a.bin" }
    );
    expect(dom.saves).toEqual([{ name: "a.bin", bytes: 2 }]);
  });

  it("falls back to a download anchor where the API is absent, and cleans up", async () => {
    const dom = fakeDom();
    await execFileSave({ type: "text", data: "x", meta: {} }, { name: "a.txt" });
    const a = dom.last();
    expect(a.tagName).toBe("A");
    expect(a.download).toBe("a.txt");
    expect(a.href).toBe("blob:stub");
    expect(a.clicked).toBe(1);
    expect(a.removed).toBe(true);
    expect(dom.attached).toEqual([]);
    expect(dom.saves).toEqual([{ name: "a.txt", bytes: 1 }]);
  });
});

describe("helpers", () => {
  it("keeps no MIME/extension sniff — the module must not be able to guess", () => {
    // `fileLooksTextual` was the mechanism behind `as=auto`. It is gone, not
    // merely unused: an exported sniff is an invitation to reintroduce the
    // same divergence somewhere the type checker cannot see it.
    const src = stripComments(
      readFileSync(
        fileURLToPath(new URL("../lib/toolkit/file-ops.js", import.meta.url)),
        "utf8"
      )
    );
    expect(src).not.toMatch(/fileLooksTextual/);
    expect(src).not.toMatch(/\bauto\b/);
  });

  it("serializes structured values as JSON rather than [object Object]", () => {
    expect(new TextDecoder().decode(saveBytesFor({ data: { a: 1 } }))).toContain('"a": 1');
    expect(() => saveBytesFor({ data: null })).toThrow(/nothing on the pipeline/);
  });

  it("keeps a Uint8Array uncopied", () => {
    const raw = new Uint8Array([9]);
    expect(saveBytesFor({ data: raw })).toBe(raw);
  });

  it("groups bare extensions under a MIME key for the picker", () => {
    expect(acceptToTypes(".pem .asc")).toEqual({
      "application/octet-stream": [".pem", ".asc"],
    });
    expect(acceptToTypes("text/plain,.txt")).toEqual({ "text/plain": [".txt"] });
    expect(acceptToTypes("")).toEqual({ "application/octet-stream": [".bin"] });
  });
});

describe("registry wiring", () => {
  it("makes file.save a passthrough sink, like out and clipboard.write", () => {
    expect(POLYMORPHIC_STEPS.has("file.save")).toBe(true);
    // Which is what lets it follow a value that is not bytes at all.
    expect(
      compileRecipe("genkey ec/p256 | file.save name=key.jwk | export pkcs8 | out @k")
        .validation.ok
    ).toBe(true);
  });

  it("declares file.read a source that needs no pipeline input", () => {
    const spec = getStep("file.read");
    expect(spec.kind).toBe("source");
    expect(spec.input).toBe("none");
    expect(compileRecipe("file.read | out @f").validation.ok).toBe(true);
  });

  it("pairs the two as conjugates in the drawer", () => {
    expect(getStep("file.read").conjugate).toBe("file.save");
    expect(getStep("file.save").conjugateOf).toBe("file.read");
  });
});
