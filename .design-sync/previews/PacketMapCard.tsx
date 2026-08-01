import { PacketMapCard } from "basilisk-portal";

/*
 * Real armor, produced by the app's own encrypt service (`lib/pgp/encrypt.js`,
 * the code behind `gpg.encrypt`) against three freshly generated Curve25519
 * keys — the same path a recipe takes. The card walks the packet headers with
 * `mapPacketSpans`, so the byte counts below are read out of these bytes; a
 * hand-typed block would map to nothing and the tile would fall back to armor.
 */

/** Encrypted to three recipients, and signed. */
const TO_THREE = `-----BEGIN PGP MESSAGE-----

wV4DJ26OYptsjXwSAQdAZgNpzoRxDPKzjZrPWvf793BJedNc9HtiowtbNhz7
+ngwyI2oN3IsoS3CqkZHWnt5yFD9L0KpIndCeN+QxuE1/tpoHjg4YYLjFkF8
g0mwZiKXwV4DwnlbPkFzMVESAQdASIDE+YnKL9Rg5yHV8qu+sipOactgcWat
1jy6qw10JnYwW6maEwUgV0kD0uT8yDfg5KFMosd7MDT5VNweHlPTEBGwr4md
aB/brBMTtiVwWWZzwV4Da7Jm6vAR+vgSAQdAyL2OteWq75kAnKRrRMPJ1PdX
V3TKK6xKD7/lAu0+E2gwHp/7B1GOvMgLKogqqvuX259fyEFQw1pMcMSaeua5
YNU7PLjdRya+1VxmvbY8yn0O0sByAY/DYv1VpRDiqNol7Y3Kiul5C79BuZ/L
4RjU89Z5Q/QKP1natWJdUv/O/juocJeDYF2zKlNWXpu/uJbQ2FNCq4G1RE/b
G59v9VYLD4Hww88dushWDJ5bw0/DlEvJLApB/GMoipDOEU/sbujuUPqNTPRQ
KWrPpxV2sljQKvrC8Y/LTtj5yChe1jqU+L+AN9IbN8EuV3Pg/rC+j7O9rqOQ
5QaPOZ05MW5TVQl1I69vq9CfBL0HrnHrWsRzKidukU5DvAU+sG2Q5cF5xXHt
cWyrTFKGVhbS+eEYAtzP6fvx26jYiNX2vkDOpxcvU0St0z95Odixd9gkRShP
Bd0S/nCDkk0qQkaUrem9vCf/bh0g0AQ/84BXW8oMXcwbDpiVTGK+jETAPR+a
Vo2PX7VzZapI9tRT
=1PWI
-----END PGP MESSAGE-----`;

/** A passphrase instead of a key — `gpg.symencrypt mode=passphrase`. */
const PASSPHRASE = `-----BEGIN PGP MESSAGE-----

wy4ECQMICuvIhKX9psTgvcLht8vRYW0JTCdNhBqZ4kfFddYxOSlrS7j3cfJK
oymP0j8BYZzOTs620y7gLRx41rHYFd70DaVKUtwIIX2YIlnJ86067KqhUzqz
+HJjjVCDBnWG+g/unbMVcxPIDTEDRXk=
=BsXQ
-----END PGP MESSAGE-----`;

/**
 * A ciphertext, read as its framing.
 *
 * An armored message is a wall of base64 that tells you nothing about itself —
 * but its *framing* is in the clear, and the framing is what a reader wants.
 * Three PKESKs means three recipients could open this. The SEIPD is the sealed
 * body, and its size is the only honest thing anyone can say about the content.
 *
 * Nothing here needs a key and nothing here is a verdict. "Decrypt with…" was
 * rejected as an action because it computes a new value; "inspect packets" was
 * rejected because it is not a button at all — it is what the tile should
 * already show.
 */
export const ThreeRecipients = () => <PacketMapCard content={TO_THREE} />;

/**
 * The distinction the map exists to make legible. **PKESK** means a key was
 * involved — one per recipient, so the count is the recipient count. **SKESK**
 * means a passphrase was, and there is exactly one no matter who holds it.
 * Both wrap the same kind of SEIPD; only the header says which.
 */
export const KeyVersusPassphrase = () => (
  <div style={{ display: "grid", gap: 14 }}>
    <PacketMapCard content={TO_THREE} />
    <PacketMapCard content={PASSPHRASE} />
  </div>
);
