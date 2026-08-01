import { SshKeyCard } from "basilisk-portal";

/*
 * The checked-in interop fixtures from `web/src/test/fixtures/ssh/`, written
 * once by OpenSSH 10.3p1's own `ssh-keygen` and byte-asserted by the test
 * suite. The `.pub` line for `ada@lovelace.dev` is `basilisk run` output from
 * `genkey ed25519 | ssh.encode comment="ada@lovelace.dev"`.
 *
 * The card decodes the wire blob to get its `SHA256:` fingerprint, so these
 * have to be real base64 — `fingerprints.txt` beside the fixtures records what
 * `ssh-keygen -lf` prints for each, and the card must agree with it.
 */

const ED_PUB =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMeF/gbtowAiX4cvtJmsW1GeOqtB0MF90K22SvdOVCXL fixture@basilisk";

const ED_PUB_2 =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIJhiyUwSjQLNDGnNPz0etb+We8mz1D0Sz4Vw0Sz5dWf ada@lovelace.dev";

const ECDSA_PUB =
  "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBB9EMYVA7hShr9PXKWF2FgewIYOM+hbb5YCDcSbP8nHRhtJDOKZpcu3VuEcBiRqfAgf5gvszCJMLZK343QmMv9w= fixture@basilisk";

const RSA_PUB =
  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3ZQ+DY72mBJ4CGJhedP3It8tfWLMj9ijAqptsUYmkt9yQWmXA5a/6DNSeWC12rEXqZ3qoPGDuYJkh2K3EAuVIYQ0gp6YrD+elex17xL0mEyKZmWe3ayTRK5/CXN4wDw+G+s6yqm/hVIJ4XIXYEdmN4K/ByuzGI6qxnhGUtfgCXCE4qYMaiGQad8hBtOJAelmt1u9LI7FtNkaHf63YPJuZsmY3BYMa/sYN/4soxBrtsiadVttWJJONeA9sSFNW0pBUFhUqAMldU15Eu62ijeTvueN4aTg6Vs7RNrQm1Lvgj49eYYIbyuTCCPBoTk7If3/yTHOzOSsYAGhwTP4aZhsWI+Gk8LlsxjWhkj+JRF9qL8I5XXCULnOOSvFNfLEQGGTOOb+v0CgNi5nQxRP7aMbgx6n5GR1v9pUSLTiILSxzfnVDrF8EXJRCn1M4rpA3+ukXFWFfL+6F59Hueg3OjEoL28HpykjFz+ip/uvB//nNMfyxWQD2ZzTBY3fe+7WF0OU= fixture@basilisk";

const ED_PRIVATE = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDHhf4G7aMAIl+HL7SZrFtRnjqrQdDBfdCttkr3TlQlywAAAJg3I4yMNyOM
jAAAAAtzc2gtZWQyNTUxOQAAACDHhf4G7aMAIl+HL7SZrFtRnjqrQdDBfdCttkr3TlQlyw
AAAECqPOqyW0rv0mnUy1x9YjL++ntSmG1gt6eSgnzTojDGBceF/gbtowAiX4cvtJmsW1Ge
OqtB0MF90K22SvdOVCXLAAAAEGZpeHR1cmVAYmFzaWxpc2sBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----`;

/**
 * A `.pub` line — the form that goes in `authorized_keys` and into GitHub.
 *
 * The fingerprint under the identity is the point of the card. It is what
 * `ssh-keygen -lf` prints and what a server's log line carries, so it is the
 * string you compare when you need to know *which* key this is — a question
 * the base64 above it cannot answer by being read.
 */
export const PublicLine = () => <SshKeyCard content={ED_PUB} />;

/**
 * The private block, and the same three facts. One card rather than two,
 * because an openssh-key-v1 container and a `.pub` line answer identical
 * questions — the caption changes and the toggle's verb changes, nothing else.
 */
export const PrivateBlock = () => <SshKeyCard content={ED_PRIVATE} />;

/**
 * `withRaw={false}` is how this card is safe on a masked tile, and it is the
 * kind's `publicView`. Every field still drawn comes off the container's
 * cleartext public blob; the private block itself is not rendered at all
 * rather than rendered behind a toggle a stray click would open.
 */
export const MaskedPrivate = () => <SshKeyCard content={ED_PRIVATE} withRaw={false} />;

/**
 * The key types, on one identity each. The leading name is fixed by the key's
 * algorithm and curve, never chosen: a P-256 key is always
 * `ecdsa-sha2-nistp256`, where the `sha2` is part of that RFC 5656 name rather
 * than a digest anyone picked.
 */
export const KeyTypes = () => (
  <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr)", gap: 14 }}>
    <SshKeyCard content={ED_PUB_2} withRaw={false} />
    <SshKeyCard content={ECDSA_PUB} withRaw={false} />
    <SshKeyCard content={RSA_PUB} withRaw={false} />
  </div>
);
