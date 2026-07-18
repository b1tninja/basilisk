/**
 * Quorum signaling mailbox client (opaque ciphertext relay).
 * @module lib/quorum/signaling
 */

import { fetchJson } from "../utils.js";
import { isValidRoomId } from "./room.js";

/**
 * @param {string} roomId
 * @param {string} armoredPayload
 * @returns {Promise<{ seq: number, room_id: string }>}
 */
export async function postSignaling(roomId, armoredPayload) {
  const rid = String(roomId || "")
    .trim()
    .toUpperCase();
  if (!isValidRoomId(rid)) throw new Error("Invalid room id");
  return fetchJson(`/api/v1/quorum/room/${encodeURIComponent(rid)}/messages`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ payload: armoredPayload }),
  });
}

/**
 * @param {string} roomId
 * @param {number} since
 * @returns {Promise<{ room_id: string, messages: Array<{ seq: number, payload: string }>, next_since: number }>}
 */
export async function pollSignaling(roomId, since = 0) {
  const rid = String(roomId || "")
    .trim()
    .toUpperCase();
  if (!isValidRoomId(rid)) throw new Error("Invalid room id");
  return fetchJson(
    `/api/v1/quorum/room/${encodeURIComponent(rid)}/messages?since=${encodeURIComponent(String(since))}`
  );
}

/**
 * Poll loop helper.
 * @param {object} opts
 * @param {string} opts.roomId
 * @param {() => number} opts.getSince
 * @param {(since: number) => void} opts.setSince
 * @param {(msg: { seq: number, payload: string }) => void | Promise<void>} opts.onMessage
 * @param {(err: Error) => void} [opts.onError]
 * @param {number} [opts.intervalMs]
 * @returns {{ stop: () => void }}
 */
export function startSignalingPoll({
  roomId,
  getSince,
  setSince,
  onMessage,
  onError,
  intervalMs = 1500,
}) {
  let stopped = false;
  let timer = null;
  const tick = async () => {
    if (stopped) return;
    try {
      const batch = await pollSignaling(roomId, getSince());
      for (const m of batch.messages || []) {
        await onMessage(m);
      }
      if (typeof batch.next_since === "number") setSince(batch.next_since);
    } catch (err) {
      onError?.(err instanceof Error ? err : new Error(String(err)));
    } finally {
      if (!stopped) {
        timer = setTimeout(tick, intervalMs);
      }
    }
  };
  timer = setTimeout(tick, 0);
  return {
    stop() {
      stopped = true;
      if (timer) clearTimeout(timer);
    },
  };
}
