/**
 * Reading facts back out of SDP.
 *
 * Parsing `a=fingerprint:` is a fact about the session-description format, not
 * about a quorum transcript — it moved out of `lib/notebook/crypto.js` when the
 * driver moved out of `lib/notebook/session.js`, because the driver is what calls it
 * and `lib/webrtc/` must not import the layer sitting on top of it.
 *
 * What quorum keeps is the part that *is* protocol: `combineDtlsFingerprints`
 * decides how two fingerprints become one transcript field, and that ordering
 * is a wire format both peers must agree on. Extracting one is reading; joining
 * them is a commitment.
 *
 * @module lib/webrtc/sdp
 */

/**
 * Every DTLS certificate fingerprint an SDP blob announces, normalised and
 * joined with `|`.
 *
 * Normalisation is load-bearing rather than cosmetic: the two ends of a
 * connection each parse their own description and the peer's, and the result
 * goes into a key transcript that must match byte for byte on both sides.
 * Engines differ on the case of the hash name, so it is lowercased and the hex
 * uppercased, always, whichever end is reading.
 *
 * @param {string} sdp
 * @returns {string}
 */
export function extractDtlsFingerprint(sdp) {
  const lines = String(sdp || "").split(/\r?\n/);
  const fps = [];
  for (const line of lines) {
    const m = line.match(/^a=fingerprint:(\S+)\s+(\S+)/i);
    if (m) fps.push(`${m[1].toLowerCase()} ${m[2].toUpperCase()}`);
  }
  return fps.join("|");
}
