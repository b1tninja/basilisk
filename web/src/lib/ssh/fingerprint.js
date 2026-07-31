/**
 * SSH public-key fingerprints (§29): SHA-256 over the RFC 4253 public blob,
 * rendered `SHA256:` + unpadded base64 — byte-identical to `ssh-keygen -lf`.
 *
 * MD5 fingerprints are omitted on purpose (§29f): nothing here consumes
 * them, and emitting the legacy form invites pasting it somewhere
 * load-bearing.
 */

import { bytesToBase64 } from "../toolkit/encode.js";

/**
 * @param {Uint8Array} publicBlob  RFC 4253 public-key blob
 * @returns {Promise<string>}  e.g. `SHA256:BV9AB0OE5ffriBtNWFcPq6qLkdtnnn2LXlERMTNNuGc`
 */
export async function sshFingerprint(publicBlob) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", publicBlob));
  return `SHA256:${bytesToBase64(digest).replace(/=+$/, "")}`;
}
