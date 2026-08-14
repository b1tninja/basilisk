import { PlanPanel } from "basilisk-portal";

/*
 * Where every cell runs, and why — the shared notebook's commitment, before
 * anything runs.
 *
 * **Every plan below is real output.** Each is planRun(compileRecipe(src),
 * {me, roster}) for one two-party ceremony, captured from this repo's own
 * planner. A hand-written plan drifts from the shape the planner emits, and
 * this panel renders the planner's sentences verbatim — an invented fixture
 * would be previewing prose no reader will ever see.
 *
 * The ceremony is the same four lines throughout:
 *
 *     @mara publish
 *     bytes deadbeef | encode hex | out $a
 *
 *     @okafor
 *     in $a | digest sha-256 | encode hex | out $d
 *
 * "publish" is a header modifier, not a step. It is what lets $a leave mara's
 * machine, and without it the second cell is a refusal rather than a plan —
 * one of the cells below is exactly that refusal.
 */

const frame = { maxWidth: 560 };

/**
 * The placed ceremony from mara's seat. Both cells are hers, and each carries
 * the planner's own sentence for why — the first a choice the header made,
 * the second a consequence of where the value already lives.
 */
export const Default = () => (
  <div style={frame}>
    <PlanPanel plan={{
        "ok": true,
        "bound": true,
        "play": "placed",
        "me": "mara",
        "peers": [
          "mara",
          "okafor"
        ],
        "unknownPeers": [],
        "cells": [
          {
            "index": 0,
            "peer": "mara",
            "kind": "placed",
            "declared": true,
            "forced": false,
            "basis": "header",
            "why": "runs on `@mara` because the header says so — nothing this cell reads is private to anyone, so this was a choice rather than a consequence",
            "runsOn": [
              "mara"
            ],
            "mine": true,
            "publish": true,
            "publishes": [
              "a"
            ],
            "produces": [
              "a"
            ],
            "consumes": [],
            "start": 0,
            "end": 13
          },
          {
            "index": 1,
            "peer": "okafor",
            "kind": "placed",
            "declared": true,
            "forced": false,
            "basis": "header",
            "why": "runs on `@okafor` because the header says so — nothing this cell reads is private to anyone, so this was a choice rather than a consequence",
            "runsOn": [
              "okafor"
            ],
            "mine": false,
            "publish": false,
            "publishes": [],
            "produces": [
              "d"
            ],
            "consumes": [
              {
                "label": "a",
                "via": "in",
                "from": 0,
                "owner": "mara",
                "private": false,
                "type": "text/opaque/hex",
                "slotOf": []
              }
            ],
            "start": 52,
            "end": 59
          }
        ],
        "refusals": [],
        "asks": [],
        "waits": [],
        "counts": {
          "solo": 0,
          "forced": 0,
          "chosen": 2,
          "witnessed": 0,
          "rendezvous": 0,
          "empty": 0
        }
      }} />
  </div>
);

/**
 * The same notebook from okafor's seat, which is the case that makes a shared
 * notebook legible: cell 1 is his, cell 0 is not, and the wait line names what
 * he is blocked on and who owes it. Nothing here is an error — waiting is the
 * normal state of a ceremony with two people in it.
 */
export const WaitingOnAPeer = () => (
  <div style={frame}>
    <PlanPanel plan={{
        "ok": true,
        "bound": true,
        "play": "placed",
        "me": "okafor",
        "peers": [
          "mara",
          "okafor"
        ],
        "unknownPeers": [],
        "cells": [
          {
            "index": 0,
            "peer": "mara",
            "kind": "placed",
            "declared": true,
            "forced": false,
            "basis": "header",
            "why": "runs on `@mara` because the header says so — nothing this cell reads is private to anyone, so this was a choice rather than a consequence",
            "runsOn": [
              "mara"
            ],
            "mine": false,
            "publish": true,
            "publishes": [
              "a"
            ],
            "produces": [
              "a"
            ],
            "consumes": [],
            "start": 0,
            "end": 13
          },
          {
            "index": 1,
            "peer": "okafor",
            "kind": "placed",
            "declared": true,
            "forced": false,
            "basis": "header",
            "why": "runs on `@okafor` because the header says so — nothing this cell reads is private to anyone, so this was a choice rather than a consequence",
            "runsOn": [
              "okafor"
            ],
            "mine": true,
            "publish": false,
            "publishes": [],
            "produces": [
              "d"
            ],
            "consumes": [
              {
                "label": "a",
                "via": "in",
                "from": 0,
                "owner": "mara",
                "private": false,
                "type": "text/opaque/hex",
                "slotOf": []
              }
            ],
            "start": 52,
            "end": 59
          }
        ],
        "refusals": [],
        "asks": [],
        "waits": [
          {
            "cell": 1,
            "on": 0,
            "peer": "mara",
            "slot": "a",
            "reason": "published-slot"
          }
        ],
        "counts": {
          "solo": 0,
          "forced": 0,
          "chosen": 2,
          "witnessed": 0,
          "rendezvous": 0,
          "empty": 0
        }
      }} />
  </div>
);

/**
 * The refusal the publish modifier exists to prevent. Without it, cell 1 on
 * @okafor would read a value private to @mara, so the plan refuses and names
 * both remedies in its own words. Refusals sit above the cell list because
 * ok: false means the run cannot start at all — a reader who has to scroll
 * past a cell list to learn that has already been misled.
 */
export const RefusedTwoOwners = () => (
  <div style={frame}>
    <PlanPanel plan={{
        "ok": false,
        "bound": true,
        "play": "placed",
        "me": "mara",
        "peers": [
          "mara",
          "okafor"
        ],
        "unknownPeers": [],
        "cells": [
          {
            "index": 0,
            "peer": "mara",
            "kind": "placed",
            "declared": true,
            "forced": false,
            "basis": "header",
            "why": "runs on `@mara` because the header says so — nothing this cell reads is private to anyone, so this was a choice rather than a consequence",
            "runsOn": [
              "mara"
            ],
            "mine": true,
            "publish": false,
            "publishes": [],
            "produces": [
              "a"
            ],
            "consumes": [],
            "start": 0,
            "end": 5
          },
          {
            "index": 1,
            "peer": "mara",
            "kind": "placed",
            "declared": true,
            "forced": true,
            "basis": "secret-locality",
            "why": "runs on `@mara` because it reads $a, written by cell 0 under `@mara` and not published — the value is on that machine and moving it is the thing this refuses to do",
            "runsOn": [
              "mara"
            ],
            "mine": true,
            "publish": false,
            "publishes": [],
            "produces": [
              "d"
            ],
            "consumes": [
              {
                "label": "a",
                "via": "in",
                "from": 0,
                "owner": "mara",
                "private": true,
                "type": "text/opaque/hex",
                "slotOf": []
              }
            ],
            "start": 44,
            "end": 51
          }
        ],
        "refusals": [
          {
            "path": "cell 1",
            "field": "peer",
            "expected": "mara",
            "actual": "okafor",
            "cell": 1,
            "reason": "two-owners",
            "message": "Cell 1 says `@okafor` but reads `$a`, which `@mara` holds privately (cell 0). Running it on `@okafor` means `@mara` hands over a private value. Move the cell to `@mara`, or publish what it needs from cell 0 with `@mara publish`.",
            "start": 44,
            "end": 51
          }
        ],
        "asks": [],
        "waits": [],
        "counts": {
          "solo": 0,
          "forced": 1,
          "chosen": 1,
          "witnessed": 0,
          "rendezvous": 0,
          "empty": 0
        }
      }} />
  </div>
);

/**
 * A notebook naming somebody who is not in the room. That is a fact about the
 * notebook rather than about one cell, so it gets its own line above the
 * refusals; burying it in a cell's why would make it look local and fixable
 * there.
 */
export const UnknownPeer = () => (
  <div style={frame}>
    <PlanPanel plan={{
        "ok": false,
        "bound": true,
        "play": "placed",
        "me": "mara",
        "peers": [
          "mara",
          "zara"
        ],
        "unknownPeers": [
          "zara"
        ],
        "cells": [
          {
            "index": 0,
            "peer": "mara",
            "kind": "placed",
            "declared": true,
            "forced": false,
            "basis": "header",
            "why": "runs on `@mara` because the header says so — nothing this cell reads is private to anyone, so this was a choice rather than a consequence",
            "runsOn": [
              "mara"
            ],
            "mine": true,
            "publish": true,
            "publishes": [
              "a"
            ],
            "produces": [
              "a"
            ],
            "consumes": [],
            "start": 0,
            "end": 13
          },
          {
            "index": 1,
            "peer": "zara",
            "kind": "placed",
            "declared": true,
            "forced": false,
            "basis": "header",
            "why": "runs on `@zara` because the header says so — nothing this cell reads is private to anyone, so this was a choice rather than a consequence",
            "runsOn": [
              "zara"
            ],
            "mine": false,
            "publish": false,
            "publishes": [],
            "produces": [
              "d"
            ],
            "consumes": [
              {
                "label": "a",
                "via": "in",
                "from": 0,
                "owner": "mara",
                "private": false,
                "type": "text/opaque/hex",
                "slotOf": []
              }
            ],
            "start": 52,
            "end": 57
          }
        ],
        "refusals": [
          {
            "path": "cell 1",
            "field": "roster",
            "expected": "mara, okafor",
            "actual": "zara",
            "cell": 1,
            "reason": "unknown-peer",
            "message": "Cell 1 runs on `@zara`, and no one in this room answers to that name — the roster binds `@mara` and `@okafor`. A peer label means a person only because the roster says which fingerprint it is; rename the cell's peer, or add `@zara` to the roster before running.",
            "start": 52,
            "end": 57
          }
        ],
        "asks": [],
        "waits": [],
        "counts": {
          "solo": 0,
          "forced": 0,
          "chosen": 2,
          "witnessed": 0,
          "rendezvous": 0,
          "empty": 0
        }
      }} />
  </div>
);

/**
 * The same placed notebook with no roster. The labels still parse and the
 * placement is still shown — they just do not mean anybody yet, and saying so
 * beats hiding the plan until a peer arrives.
 */
export const Unbound = () => (
  <div style={frame}>
    <PlanPanel plan={{
        "ok": true,
        "bound": false,
        "play": "placed",
        "me": "",
        "peers": [
          "mara",
          "okafor"
        ],
        "unknownPeers": [],
        "cells": [
          {
            "index": 0,
            "peer": "mara",
            "kind": "placed",
            "declared": true,
            "forced": false,
            "basis": "header",
            "why": "runs on `@mara` because the header says so — nothing this cell reads is private to anyone, so this was a choice rather than a consequence",
            "runsOn": [
              "mara"
            ],
            "mine": false,
            "publish": true,
            "publishes": [
              "a"
            ],
            "produces": [
              "a"
            ],
            "consumes": [],
            "start": 0,
            "end": 13
          },
          {
            "index": 1,
            "peer": "okafor",
            "kind": "placed",
            "declared": true,
            "forced": false,
            "basis": "header",
            "why": "runs on `@okafor` because the header says so — nothing this cell reads is private to anyone, so this was a choice rather than a consequence",
            "runsOn": [
              "okafor"
            ],
            "mine": false,
            "publish": false,
            "publishes": [],
            "produces": [
              "d"
            ],
            "consumes": [
              {
                "label": "a",
                "via": "in",
                "from": 0,
                "owner": "mara",
                "private": false,
                "type": "text/opaque/hex",
                "slotOf": []
              }
            ],
            "start": 52,
            "end": 59
          }
        ],
        "refusals": [],
        "asks": [],
        "waits": [],
        "counts": {
          "solo": 0,
          "forced": 0,
          "chosen": 2,
          "witnessed": 0,
          "rendezvous": 0,
          "empty": 0
        }
      }} />
  </div>
);

/**
 * One cell, no headers, nobody else involved — the state most notebooks are in.
 * The panel still answers rather than rendering nothing, because "runs here" is
 * a real answer to where this runs.
 */
export const Solo = () => (
  <div style={frame}>
    <PlanPanel plan={{
        "ok": true,
        "bound": false,
        "play": "solo",
        "me": "",
        "peers": [],
        "unknownPeers": [],
        "cells": [
          {
            "index": 0,
            "peer": "",
            "kind": "witnessed",
            "declared": false,
            "forced": false,
            "basis": "solo",
            "why": "this notebook names no peer, so the cell runs here — the same single runner every recipe without a `@peer` header has always had",
            "runsOn": [],
            "mine": true,
            "publish": false,
            "publishes": [],
            "produces": [
              "a"
            ],
            "consumes": [],
            "start": 0,
            "end": 15
          },
          {
            "index": 1,
            "peer": "",
            "kind": "witnessed",
            "declared": false,
            "forced": false,
            "basis": "solo",
            "why": "this notebook names no peer, so the cell runs here — the same single runner every recipe without a `@peer` header has always had",
            "runsOn": [],
            "mine": true,
            "publish": false,
            "publishes": [],
            "produces": [
              "d"
            ],
            "consumes": [
              {
                "label": "a",
                "via": "in",
                "from": 0,
                "owner": "",
                "private": false,
                "type": "text/opaque/hex",
                "slotOf": []
              }
            ],
            "start": 38,
            "end": 44
          }
        ],
        "refusals": [],
        "asks": [],
        "waits": [],
        "counts": {
          "solo": 2,
          "forced": 0,
          "chosen": 0,
          "witnessed": 0,
          "rendezvous": 0,
          "empty": 0
        }
      }} />
  </div>
);
