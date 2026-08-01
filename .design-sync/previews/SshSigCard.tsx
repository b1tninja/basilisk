import { SshSigCard } from "basilisk-portal";

/*
 * Both blocks are checked-in fixtures — `payload.id_ed25519.file.sshsig` and
 * `payload.id_ed25519.git.sshsig` in `web/src/test/fixtures/ssh/`, written by
 * OpenSSH's own `ssh-keygen -Y sign` over the same payload with the same key.
 *
 * They differ in one field, which is the whole reason this card exists.
 */

const FILE_SIG = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgx4X+Bu2jACJfhy+0maxbUZ46q0
HQwX3QrbZK905UJcsAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
OQAAAEDkS19bENEbZNmE15dJx+Vs1vM/hrH+g4xhea4lc3Ddchbr/cSGHbnL9seCWc5bQu
okxHBFA1b7SGD13Vz5Ec8C
-----END SSH SIGNATURE-----`;

const GIT_SIG = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgx4X+Bu2jACJfhy+0maxbUZ46q0
HQwX3QrbZK905UJcsAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQD3U9vDwN4tOzxxzbvjq+T3Xh8Ad0JMu7016298zq9gehORuRPj/fCD0Jn/9TsSU4A
90SAOUWBTp7+WmjLJ9EQE=
-----END SSH SIGNATURE-----`;

/**
 * A file signature. Namespace leads because it is the field that silently
 * decides whether a signature verifies at all, and the armor gives no hint
 * which one you are holding.
 *
 * There is deliberately no verify button. Verification needs a key and the
 * payload; a tile has neither — the block outlived the run that made it, and
 * the payload was never on it. That is `ssh.verify`.
 */
export const FileSignature = () => <SshSigCard content={FILE_SIG} />;

/**
 * The pair that makes the card's argument. Same key, same payload, same hash —
 * and the two are not interchangeable: a `git` signature can never verify as a
 * `file` signature. Read as armor these two blocks are near-identical walls of
 * base64; read as cards, they differ in the first word.
 */
export const NamespaceDecides = () => (
  <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr)", gap: 14 }}>
    <SshSigCard content={FILE_SIG} />
    <SshSigCard content={GIT_SIG} />
  </div>
);
