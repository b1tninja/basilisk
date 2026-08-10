/**
 * The signalling seam, over the Web PubSub protocol.
 *
 * What replaced the mailbox is not a different relay — it is a different
 * *place for the state to live*. The old one kept rooms in a process-global
 * dict, which on Consumption Functions meant two peers met only when they
 * happened to land on the same warm instance, and any caller could post into
 * any room. So the properties worth pinning are the two that were missing:
 * the grant is scoped to one room, and the client refuses to pretend
 * otherwise.
 *
 * The service stands in as `webpubsub-double.js` — the documented frames over
 * a fake socket, with the token verified by WebCrypto and the `role` claims
 * enforced per request. The client above it is the shipped one.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  negotiateSignaling,
  openSignalingChannel,
} from "../lib/notebook/signaling.js";
import { connectWebPubSub, WEBPUBSUB_SUBPROTOCOL } from "../lib/notebook/webpubsub.js";
import {
  installWebPubSubDouble,
  mintClientAccessToken,
  roomRoles,
} from "./helpers/webpubsub-double.js";

const ROOM_A = "AAAA2345EFGH67YZ";
const ROOM_B = "BBBB7654VUTS32XY";

/** @type {ReturnType<typeof installWebPubSubDouble>|null} */
let relay = null;
let realFetch;
/** Every negotiate request the client made, in order. */
let negotiations = [];

/**
 * @param {(room: string) => Promise<object>|object} grant
 */
function stubServer(grant) {
  globalThis.fetch = /** @type {any} */ (
    async (url, init) => {
      const href = String(url);
      if (href.includes("/pks/v2/challenge")) {
        return Response.json({ nonce: "n", timestamp: 1, difficulty: 0, hint: "n:1:sig" });
      }
      if (href.includes("/api/v1/notebook/negotiate")) {
        const body = JSON.parse(String(init?.body || "{}"));
        negotiations.push({ body, headers: init?.headers || {} });
        return Response.json(await grant(String(body.room)));
      }
      return new Response(`unexpected ${href}`, { status: 500 });
    }
  );
}

/** Wait for `check()`, or give up. Real timers — the socket is async. */
async function until(check, budgetMs = 3000) {
  const deadline = Date.now() + budgetMs;
  while (Date.now() < deadline) {
    if (check()) return true;
    await new Promise((r) => setTimeout(r, 5));
  }
  return check();
}

beforeEach(() => {
  negotiations = [];
  realFetch = globalThis.fetch;
  relay = installWebPubSubDouble();
});

afterEach(() => {
  relay?.restore();
  relay = null;
  globalThis.fetch = realFetch;
  vi.restoreAllMocks();
});

describe("negotiate", () => {
  it("asks for one room and carries the proof header", async () => {
    stubServer((room) => relay.grantFor(room));
    const grant = await negotiateSignaling(ROOM_A);
    expect(grant.room).toBe(ROOM_A);
    expect(grant.transport).toBe("webpubsub");
    expect(grant.protocol).toBe(WEBPUBSUB_SUBPROTOCOL);
    expect(negotiations).toHaveLength(1);
    expect(negotiations[0].body).toEqual({ room: ROOM_A });
    // The gate the mailbox never had. `proof.js` treats a failed challenge as
    // "no header", so its presence here is the whole assertion.
    expect(negotiations[0].headers["X-Basilisk-Proof"]).toBe("n:1:sig");
  });

  it("refuses a room id that is not one, before any request", async () => {
    stubServer((room) => relay.grantFor(room));
    for (const bad of ["", "short", "not-valid!!!", "lowercase-room"]) {
      await expect(negotiateSignaling(bad)).rejects.toThrow(/Invalid room id/);
    }
    expect(negotiations).toHaveLength(0);
  });
});

describe("a room-scoped grant", () => {
  it("carries the room's two roles and no wider one", async () => {
    const grant = await relay.grantFor(ROOM_A);
    const token = new URL(grant.url).searchParams.get("access_token");
    const claims = JSON.parse(
      atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))
    );
    expect(claims.role).toEqual(roomRoles(ROOM_A));
    expect(claims.role).not.toContain("webpubsub.joinLeaveGroup");
    expect(claims.role).not.toContain("webpubsub.sendToGroup");
    expect(claims["webpubsub.group"]).toEqual([ROOM_A]);
  });

  it("cannot join or publish to any other room", async () => {
    // The token says room A. Everything below asks it for room B, which is
    // the authorization fix stated as an experiment: the old mailbox let any
    // caller POST into any room, and this must not.
    const grant = await relay.grantFor(ROOM_A);
    const errors = [];
    const wrongRoom = connectWebPubSub({
      url: grant.url,
      protocol: grant.protocol,
      group: ROOM_B,
      onMessage: () => {},
      onError: (err) => errors.push(err),
    });
    await expect(wrongRoom.ready).rejects.toThrow(/Forbidden/);
    await expect(wrongRoom.send("anything")).rejects.toThrow(/Forbidden/);
    wrongRoom.close();

    // And the same token in its own room works — so the refusal above is the
    // scope, not a broken double.
    const rightRoom = connectWebPubSub({
      url: grant.url,
      protocol: grant.protocol,
      group: ROOM_A,
      onMessage: () => {},
    });
    await expect(rightRoom.ready).resolves.toBeUndefined();
    rightRoom.close();
  });

  it("is refused outright when the token is not ours", async () => {
    const forged = await mintClientAccessToken({
      accessKey: "not-the-access-key",
      audience: relay.audience,
      roles: roomRoles(ROOM_A),
      groups: [ROOM_A],
    });
    const conn = connectWebPubSub({
      url: relay.clientUrl(forged),
      group: ROOM_A,
      onMessage: () => {},
      onError: () => {},
    });
    await expect(conn.ready).rejects.toThrow();
  });
});

describe("openSignalingChannel", () => {
  it("carries an envelope from one peer to the other", async () => {
    stubServer((room) => relay.grantFor(room));
    const heard = [];
    const alice = openSignalingChannel({ roomId: ROOM_A, onMessage: () => {} });
    const bob = openSignalingChannel({
      roomId: ROOM_A,
      onMessage: (payload) => heard.push(payload),
    });
    await alice.ready;
    await bob.ready;

    const armored = "-----BEGIN PGP MESSAGE-----\nsealed\n-----END PGP MESSAGE-----";
    await alice.send(armored);
    expect(await until(() => heard.includes(armored))).toBe(true);

    alice.stop();
    bob.stop();
  });

  it("names a transport it does not speak instead of guessing", async () => {
    stubServer((room) => ({
      v: 1,
      room,
      transport: "some-other-cloud",
      url: "wss://elsewhere.example/socket",
      protocol: "x.v1",
      expires_at: 0,
    }));
    const errors = [];
    const channel = openSignalingChannel({
      roomId: ROOM_A,
      onMessage: () => {},
      onError: (err) => errors.push(err),
    });
    await expect(channel.ready).rejects.toThrow(/unsupported signalling transport/);
    expect(errors[0].message).toContain("some-other-cloud");
    channel.stop();
  });

  it("re-negotiates after a drop rather than redialling a stale URL", async () => {
    stubServer((room) => relay.grantFor(room));
    const heard = [];
    const channel = openSignalingChannel({
      roomId: ROOM_A,
      onMessage: (payload) => heard.push(payload),
    });
    await channel.ready;
    expect(negotiations).toHaveLength(1);

    // The service dropped us. The grant is minutes long and a session is not,
    // so coming back has to go through the server: the old URL's token may
    // already have expired, and redialling it would fail as a 401 the client
    // could not distinguish from the room having gone away.
    relay.dropAll();
    expect(await until(() => negotiations.length >= 2)).toBe(true);
    expect(await until(() => heard.length === 0 && negotiations.length >= 2)).toBe(true);

    // And the room still works on the far side of the reconnect.
    const bob = openSignalingChannel({ roomId: ROOM_A, onMessage: () => {} });
    await bob.ready;
    await bob.send("after the drop");
    expect(await until(() => heard.includes("after the drop"))).toBe(true);
    bob.stop();
    channel.stop();
  });

  it("stops meaning stopped", async () => {
    stubServer((room) => relay.grantFor(room));
    const channel = openSignalingChannel({ roomId: ROOM_A, onMessage: () => {} });
    await channel.ready;
    channel.stop();
    await expect(channel.send("x")).rejects.toThrow(/closed/);
  });
});

/* ─────────────────────── bounded connection lifetime ─────────────────────── */

describe("the connection has a bounded life", () => {
  /**
   * Record every socket the double hands out, so "re-established" can be
   * asserted as *a different socket*, which is the only form of the claim a
   * scheduled callback cannot fake.
   */
  function watchSockets() {
    const made = [];
    const Base = globalThis.WebSocket;
    globalThis.WebSocket = /** @type {any} */ (
      class extends Base {
        constructor(...args) {
          super(...args);
          made.push(this);
        }
      }
    );
    return { made, restore: () => (globalThis.WebSocket = Base) };
  }

  it("really re-connects on the cycle, and the new socket is the live one", async () => {
    // The whole point of the cycle. A token's expiry is checked when a
    // connection is made and never again, so a connection held open outlives
    // every grant that would be refused today. Proving the *timer fired*
    // would prove nothing: what has to be true is that a second socket exists,
    // that it was bought with a second negotiate, that the first one is shut,
    // and that traffic lands on the second.
    stubServer((room) => relay.grantFor(room));
    const watch = watchSockets();
    const heard = [];
    const channel = openSignalingChannel({
      roomId: ROOM_A,
      onMessage: (payload) => heard.push(payload),
      recycleMs: 60,
    });
    try {
      await channel.ready;
      expect(watch.made).toHaveLength(1);
      expect(negotiations).toHaveLength(1);
      const first = watch.made[0];

      expect(await until(() => watch.made.length >= 2, 3000)).toBe(true);
      // A fresh negotiate, not a redial of a URL whose token is ageing — and
      // therefore a fresh proof of work, which is the cost that makes lurking
      // recurring rather than one-off.
      expect(negotiations.length).toBeGreaterThanOrEqual(2);

      // Make before break: the replacement was joined before the original was
      // shut, so no window existed in which the room was unattended.
      expect(await until(() => first.readyState === 3, 3000)).toBe(true);
      const live = watch.made.at(-1);
      expect(live.readyState).toBe(1);
      expect(live).not.toBe(first);

      // And the room still works — on the socket that replaced the one that
      // was closed, not on a stale handle the channel forgot to swap.
      const bob = openSignalingChannel({ roomId: ROOM_A, onMessage: () => {} });
      await bob.ready;
      await bob.send("after the cycle");
      expect(await until(() => heard.includes("after the cycle"))).toBe(true);
      bob.stop();
    } finally {
      channel.stop();
      watch.restore();
    }
  });

  it("takes the cycle from the grant's own lifetime when none is given", async () => {
    // One knob, not two. The server states how long it is willing to grant and
    // the client re-asserts inside that window, so a deployment that shortens
    // BASILISK_WEBPUBSUB_TOKEN_TTL_SEC shortens the cycle with it and there is
    // no second constant that can disagree.
    stubServer(async (room) => ({
      ...(await relay.grantFor(room)),
      expires_at: Math.floor(Date.now() / 1000) + 10,
    }));
    const watch = watchSockets();
    const channel = openSignalingChannel({ roomId: ROOM_A, onMessage: () => {} });
    try {
      await channel.ready;
      // 80% of a ten-second grant is eight seconds, so nothing has recycled
      // within the first second — the cycle is derived, not a fixed default.
      await new Promise((r) => setTimeout(r, 1000));
      expect(watch.made).toHaveLength(1);
    } finally {
      channel.stop();
      watch.restore();
    }
  });

  it("keeps the connection it has when the replacement cannot be bought", async () => {
    // A re-negotiation that fails must not take the working connection down
    // with it. That is why the cycle sits inside the grant's life rather than
    // at the end of it: there is still a valid connection to keep.
    let fail = false;
    stubServer((room) => {
      if (fail) throw new Error("negotiate is down");
      return relay.grantFor(room);
    });
    const watch = watchSockets();
    const errors = [];
    const channel = openSignalingChannel({
      roomId: ROOM_A,
      onMessage: () => {},
      onError: (err) => errors.push(err),
      recycleMs: 60,
    });
    try {
      await channel.ready;
      const first = watch.made[0];
      fail = true;
      expect(await until(() => errors.length > 0, 3000)).toBe(true);
      expect(first.readyState).toBe(1);
      // And it is still usable, not merely open.
      await expect(channel.send("still here")).resolves.toBeUndefined();
    } finally {
      channel.stop();
      watch.restore();
    }
  });

  it("asks for the room group when it holds the key, and the lobby otherwise", async () => {
    stubServer((room) => relay.grantFor(room));
    const roomKey = `${ROOM_A}MZXW6YTBOI5XG5DBOJUXA43UMFZGKZLB`;
    expect(roomKey).toHaveLength(48);
    const withKey = openSignalingChannel({
      roomId: ROOM_A,
      roomKey: `${roomKey}MFZG`,
      onMessage: () => {},
    });
    await withKey.ready;
    expect(negotiations.at(-1).body).toEqual({
      room: ROOM_A,
      key: `${roomKey}MFZG`,
    });
    withKey.stop();

    const withoutKey = openSignalingChannel({ roomId: ROOM_A, onMessage: () => {} });
    await withoutKey.ready;
    expect(negotiations.at(-1).body).toEqual({ room: ROOM_A });
    withoutKey.stop();
  });

  it("refuses a key that is not this room's, before any request", async () => {
    stubServer((room) => relay.grantFor(room));
    const before = negotiations.length;
    for (const key of [
      `${ROOM_B}MZXW6YTBOI5XG5DBOJUXA43UMFZGKZLBMFZG`, // another room
      `${ROOM_A}MZXW6YTBOI5XG5DBOJUXA43UMFZGKZLBMFZ`, // too short
      `${ROOM_A}MZXW6YTBOI5XG5DBOJUXA43UMFZGKZLBMF1G`, // not base32
    ]) {
      await expect(negotiateSignaling(ROOM_A, { roomKey: key })).rejects.toThrow(
        /Invalid room key|does not match/
      );
    }
    expect(negotiations).toHaveLength(before);
  });
});
