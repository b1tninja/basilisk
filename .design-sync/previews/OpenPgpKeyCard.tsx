import { OpenPgpKeyCard } from "basilisk-portal";

/*
 * Real armor for `Ada Lovelace <ada.lovelace@example.org>`. Both blocks are the
 * same Curve25519 key — the private one is the tip `gpg.genkey` emits, and the
 * public one is what it writes beside it.
 *
 * The card parses these with `openpgp`'s `readKey`, so the user id, the grouped
 * fingerprint and the dates on screen are all read back out of the bytes below.
 * Substitute a plausible-looking fake and the card falls back to "OpenPGP key",
 * which is exactly the unreadable state it was written to replace.
 *
 * **The creation date is load-bearing: keep it behind 2024-05-15.** The capture
 * harness pins the browser clock to `2024-05-15T12:00:00Z` so screenshots are
 * deterministic, and `getPrimaryUser` validates the self-certification against
 * the clock it is given. A key generated *today* is signed in that clock's
 * future, so the self-sig is not yet valid and `getPrimaryUser` rejects —
 * silently, because `openpgpKeySummary` catches it and leaves `uid` empty. The
 * fingerprint and creation date do no date validation and `getExpirationTime`
 * answers `Infinity` on its own failure path, so the card renders every field
 * *except* the user id and reads as a live bug in the component. It is not one:
 * a real reader has a real clock. Regenerate these and the whole cell silently
 * reverts to that fallback, which is why the date is stated here rather than
 * left to whoever next runs `generateKey`.
 */

const PUBLIC = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEZHhhDBYJKwYBBAHaRw8BAQdAUcwlXpt+Lq6Zl+9P1shhbcCxCWEsMsK4
at1iz6n7LmnNJ0FkYSBMb3ZlbGFjZSA8YWRhLmxvdmVsYWNlQGV4YW1wbGUu
b3JnPsLAEwQTFgoAhQWCZHhhDAMLCQcJECxeu7Rq0BOIRRQAAAAAABwAIHNh
bHRAbm90YXRpb25zLm9wZW5wZ3Bqcy5vcmcqSYt6iRrZVjsgRTy7W8V2P8cx
KhRi/UjLz8O14Tw/jgUVCggODAQWAAIBAhkBApsDAh4BFiEE13IHjFx8Kg7c
oJ7TLF67tGrQE4gAAKldAPwPwdeP8O7Nxzf43pB13h3PsCyCFhFKQYtDUVlA
uRl37QEAjyv6ATu/WbOpXifMKDp3Z1HsH3Yln6wBp1Sr2sBCuQ7OOARkeGEM
EgorBgEEAZdVAQUBAQdAE2rk/hJIhITUWpJpkn/kwIZGdFhoNwLIv2uP6RRb
6EYDAQgHwr4EGBYKAHAFgmR4YQwJECxeu7Rq0BOIRRQAAAAAABwAIHNhbHRA
bm90YXRpb25zLm9wZW5wZ3Bqcy5vcmdBIxJkS+vr8kQZn3LpVvsHYgtww95g
o/pYug048DtvnQKbDBYhBNdyB4xcfCoO3KCe0yxeu7Rq0BOIAAB+DwEAqUSH
DAiwidKj344y4JORClJxShghOrlKyO2KQrDZ51ABAMHvHPJTlVxG3gAzQsZz
yjltP/kOPj+fEp/ZBKRn22kL
=YyoN
-----END PGP PUBLIC KEY BLOCK-----`;

const PRIVATE = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEZHhhDBYJKwYBBAHaRw8BAQdAUcwlXpt+Lq6Zl+9P1shhbcCxCWEsMsK4
at1iz6n7LmkAAP9Dcx4kx4mT/sLmVt9vRZbFeAkTkzyYRVlN75jCUNmXQxD2
zSdBZGEgTG92ZWxhY2UgPGFkYS5sb3ZlbGFjZUBleGFtcGxlLm9yZz7CwBME
ExYKAIUFgmR4YQwDCwkHCRAsXru0atATiEUUAAAAAAAcACBzYWx0QG5vdGF0
aW9ucy5vcGVucGdwanMub3JnKkmLeoka2VY7IEU8u1vFdj/HMSoUYv1Iy8/D
teE8P44FFQoIDgwEFgACAQIZAQKbAwIeARYhBNdyB4xcfCoO3KCe0yxeu7Rq
0BOIAACpXQD8D8HXj/Duzcc3+N6Qdd4dz7AsghYRSkGLQ1FZQLkZd+0BAI8r
+gE7v1mzqV4nzCg6d2dR7B92JZ+sAadUq9rAQrkOx10EZHhhDBIKKwYBBAGX
VQEFAQEHQBNq5P4SSISE1FqSaZJ/5MCGRnRYaDcCyL9rj+kUW+hGAwEIBwAA
/2TQ7slt+5H6EQAKKLW0bdhkdNs/bRJjqZhq+0mRqI5wEcjCvgQYFgoAcAWC
ZHhhDAkQLF67tGrQE4hFFAAAAAAAHAAgc2FsdEBub3RhdGlvbnMub3BlbnBn
cGpzLm9yZ0EjEmRL6+vyRBmfculW+wdiC3DD3mCj+li6DTjwO2+dApsMFiEE
13IHjFx8Kg7coJ7TLF67tGrQE4gAAH4PAQCpRIcMCLCJ0qPfjjLgk5EKUnFK
GCE6uUrI7YpCsNnnUAEAwe8c8lOVXEbeADNCxnPKOW0/+Q4+P58Sn9kEpGfb
aQs=
=I2Xp
-----END PGP PRIVATE KEY BLOCK-----`;

/**
 * The public key `gpg.genkey` writes beside its tip — the only artifact in the
 * notebook that gets Publish. The armor answers "whose is this" only after
 * parsing, so the card does the parsing: user id first, the fingerprint in the
 * grouped hex a reader compares against, then the dates.
 */
export const PublicKey = () => <OpenPgpKeyCard content={PUBLIC} />;

/**
 * The same key's private block. Only one word on the card changes — and that
 * word is the whole point, because the first three lines of the armor are
 * identical for every OpenPGP key ever generated.
 */
export const PrivateKey = () => <OpenPgpKeyCard content={PRIVATE} />;

/**
 * `publicOnly` on a masked tile: the derived facts stay (they come off public
 * material either way), and only the armor toggle goes. Beside it, the same
 * card with the toggle — the armor is one click down, never taken away.
 */
export const MaskedAndOpen = () => (
  <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr)", gap: 14 }}>
    <OpenPgpKeyCard content={PRIVATE} publicOnly />
    <OpenPgpKeyCard content={PRIVATE} />
  </div>
);

/**
 * `traits.fingerprint` is drawn *before* the parse resolves, so a tile with a
 * large armor is never briefly anonymous. Here the parse is skipped entirely —
 * a body that is not armor at all — and the pre-computed id is the only thing
 * the card can say. It says that, and stops, rather than inventing a date.
 */
export const FingerprintBeforeParse = () => (
  <OpenPgpKeyCard content="" fingerprint="D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388" publicOnly />
);
