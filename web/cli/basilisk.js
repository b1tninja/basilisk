#!/usr/bin/env node
/**
 * `basilisk` executable wrapper.
 *
 * Three jobs, in order, and nothing else — the commands themselves live in
 * `cli/main.js` so they can be tested without spawning a process:
 *
 *  1. Register the `?raw` loader hooks *before* anything imports the engine,
 *     so Vite's text-asset imports resolve under plain Node (see raw-loader.js).
 *  2. Collect stdin when `--stdin` was asked for.
 *  3. Turn the returned exit code into a process exit code.
 *
 * @module cli/basilisk
 */

import { register } from "node:module";

register("./raw-loader.js", import.meta.url);

/** Read piped stdin, or "" when nothing is piped. */
async function readStdin() {
  if (process.stdin.isTTY) return "";
  /** @type {Buffer[]} */
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

const { main } = await import("./main.js");

const argv = process.argv.slice(2);
const stdin = argv.includes("--stdin") ? await readStdin() : "";
const code = await main(argv, {
  out: (s) => process.stdout.write(`${s}\n`),
  err: (s) => process.stderr.write(`${s}\n`),
  env: process.env,
  stdin,
});
process.exit(code);
