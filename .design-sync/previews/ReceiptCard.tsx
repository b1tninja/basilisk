import { ReceiptCard } from "basilisk-portal";

/*
 * Two real `run.receipt` bodies.
 *
 * `HEADLESS` came straight out of `basilisk run` on a three-step recipe — the
 * CLI runs a notebook as one cell, which is why it has a single row group.
 * `NOTEBOOK` is the three-cell shape the browser produces, assembled by calling
 * the app's own `buildRunReceipt` over the same artifacts; every digest in it
 * is `digestArtifact`'s hash of the real body it names.
 *
 * A receipt never contains a value — that is the invariant the whole format
 * rests on. What is below is digests, byte lengths, roles and timestamps.
 */

const HEADLESS =
  '{"cells":[{"index":0,"inputs":[{"channel":"text","digest":"02f92eb0429085e1a06219eff65320cb3322069d80123d57bc8ee8956a6c773a"}],"outputs":[{"digest":"a69196f78278a5935c0817c2afeb24160b54348bd2c00483d9e6d539b1128710","filename":"pub.txt","label":"pub","length":97,"role":"ssh-public","sensitive":false,"stepName":"out"},{"digest":"c9073d1d04486035b585085b7f20b165152cde63c5cf0938fc30c21f0400e91f","filename":"digest.txt","label":"digest","length":64,"role":"text","sensitive":false,"stepName":"out"}],"recipe":"genkey ed25519 | ssh.encode comment=ada@lovelace.dev | out @pub | input | digest sha-256 | encode hex | out @digest | run.receipt \\"release signing v4.2\\" | out @receipt","startedAt":"2026-08-01T15:58:18.099Z"}],"createdAt":"2026-08-01T15:58:18.129Z","kind":"basilisk.run-receipt","label":"release signing v4.2","recipeDigest":"f236ba20e8dedd0b4d6d7729fad9be1d20ebef2e681c03f6ed056956386a086a","recipeSource":"genkey ed25519 | ssh.encode comment=ada@lovelace.dev | out @pub | input | digest sha-256 | encode hex | out @digest | run.receipt \\"release signing v4.2\\" | out @receipt","registry":"ops-118-aeb381b8","v":2}';

const NOTEBOOK =
  '{"cells":[{"index":0,"inputs":[],"outputs":[{"digest":"a03c557d8fa98378e291fcfd78a73dc5875ceafa9d9aca561bc321a7ce2f5bcd","filename":"kp.txt","label":"kp","length":175,"role":"keypair","sensitive":true,"stepName":"out"},{"digest":"a69196f78278a5935c0817c2afeb24160b54348bd2c00483d9e6d539b1128710","filename":"pub.txt","label":"pub","length":97,"role":"ssh-public","sensitive":false,"stepName":"out"}],"recipe":"genkey ed25519 | tee | ssh.encode comment=\\"ada@lovelace.dev\\" | out @pub","startedAt":"2026-08-01T15:58:18.099Z"},{"index":1,"inputs":[{"channel":"text","digest":"02f92eb0429085e1a06219eff65320cb3322069d80123d57bc8ee8956a6c773a"}],"outputs":[{"digest":"c9073d1d04486035b585085b7f20b165152cde63c5cf0938fc30c21f0400e91f","filename":"digest.txt","label":"digest","length":64,"role":"text","sensitive":false,"stepName":"out"}],"recipe":"input | digest sha-256 | encode hex | out @digest","startedAt":"2026-08-01T15:58:18.112Z"},{"index":2,"inputs":[],"outputs":[{"digest":"0ea424b4f39d0014d2059822da95f8d3f77499c3af4a84371f3b7cd98d8d4c65","filename":"sig.txt","label":"sig","length":96,"role":"signature","sensitive":false,"stepName":"out"}],"recipe":"in @digest | sign key=@kp | encode base64 | out @sig","startedAt":"2026-08-01T15:58:18.121Z"}],"createdAt":"2026-08-01T15:58:18.129Z","kind":"basilisk.run-receipt","label":"release signing v4.2","recipeDigest":"a5714ea13db0422c480b74355997cc5573336582f0864a0f393470771e7a2f25","recipeSource":"genkey ed25519 | tee | ssh.encode comment=\\"ada@lovelace.dev\\" | out @pub\\ninput | digest sha-256 | encode hex | out @digest\\nin @digest | sign key=@kp | encode base64 | out @sig","registry":"ops-118-aeb381b8","v":2}';

/**
 * The digest table, in the order `run.verify` walks it.
 *
 * A receipt shipped as canonical JSON: correct as a wire format and unreadable
 * as a document. These are the same rows, laid out so that a mismatch reported
 * later — "cell 1 · output 2" — names something a reader can actually find.
 *
 * Digests are truncated to twelve hex characters with the full value and the
 * byte length in `title`. Twelve is enough to see that two rows differ; the
 * full sixty-four makes every row wrap, and a truncated digest that *looks*
 * complete is the one failure mode a digest table must not have.
 */
export const DigestTable = () => <ReceiptCard content={NOTEBOOK} />;

/**
 * The two shapes a receipt arrives in. A headless `basilisk run` executes the
 * whole notebook as one cell, so its receipt has one row group; the browser
 * runs cells separately and the cell numbers become navigable.
 *
 * No "verify this" button, and the absence is the design. Verifying means
 * re-running the recipe and comparing — that is `run.verify`, an op, with a
 * receipt as its input. A button here could only re-run *this* notebook, which
 * is not what verifying somebody else's receipt means.
 */
export const OneCellAndThree = () => (
  <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr)", gap: 18 }}>
    <ReceiptCard content={HEADLESS} />
    <ReceiptCard content={NOTEBOOK} />
  </div>
);
