import { InviteCard } from "basilisk-portal";

/*
 * The invite, which is not a token.
 *
 * A room here is `SHA-256(hostname | sorted audience fingerprints)`, truncated.
 * Nobody allocates it and nobody hands it out: both ends compute the same name
 * from the same list, and anybody with a different list computes a different
 * room. So the link carries public fingerprints and nothing else, and forwarding
 * it admits nobody — which is the opposite of what a reader will assume about a
 * link they are pasting into a chat window unless the card says so.
 *
 * That is why the two lists are the component rather than a footnote. They come
 * from exported constants (`INVITE_CARRIES` / `INVITE_OMITS`), because they are
 * a security claim and a claim a component owns is a claim no test can pin.
 *
 * The fingerprints below are real 40-hex OpenPGP shapes. The card truncates them
 * itself (`AABBCCDD…EEFF`) using the same rule as the roster projection, so the
 * fixtures carry the full string and let it do the shortening.
 */

const ADA = "D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388";
const GRACE = "9F2A11B4C8D30E5761AA0C4E88B2F6D5091C7E43";
const LIN = "44C1D9E07B8A2F631E5D0A9C2B7E4F81D3A65029";

const URL = `https://basilisk.pages.dev/toolkit#j=${[ADA, GRACE].sort().join(",")}`;

/**
 * Two people, before a session exists. There is no room line: the room is a
 * digest of this list and the hostname, so it is entirely *predictable* and not
 * yet *open* — printing a code for a room nobody is in would invite somebody to
 * read it out as though it meant a meeting.
 */
export const Default = () => (
  <InviteCard url={URL} audience={[ADA, GRACE].sort()} self={ADA} onCopy={() => {}} />
);

/**
 * The same invite once the session is live. The room id appears now, truncated,
 * because there is something for it to name — and because it is the short thing
 * two people say aloud on a call to confirm they landed in the same place.
 */
export const InLiveSession = () => (
  <InviteCard
    url={URL}
    audience={[ADA, GRACE].sort()}
    self={ADA}
    room="KJ8X4M2Q7T9FQ2AB"
    onCopy={() => {}}
  />
);

/**
 * Three keys. The audience is drawn in full rather than counted, and this is the
 * state that shows why: "3 keys" is a number nobody can check, and inviting the
 * wrong fingerprint is the one mistake still available after every cryptographic
 * guarantee above it has held.
 */
export const ThreeInTheRoom = () => (
  <InviteCard
    url={`https://basilisk.pages.dev/toolkit#j=${[ADA, GRACE, LIN].sort().join(",")}`}
    audience={[ADA, GRACE, LIN].sort()}
    self={GRACE}
    room="7QP2N4XA9CD1M5RT"
    onCopy={() => {}}
  />
);

/**
 * **No link yet, and the reason.** One fingerprint derives no room —
 * `deriveRoomMaterial` refuses fewer than two — so `hashForJoin` refuses too and
 * the card has nothing to offer. Copy is removed rather than dimmed-and-silent,
 * and the sentence names what is missing, because "Copy invite (disabled)" tells
 * a reader nothing they can act on.
 */
export const NotYetARoom = () => (
  <InviteCard url={null} audience={[ADA]} self={ADA} />
);
