import { OpenPgpKeyCard } from "basilisk-portal";

/*
 * Real armor from `gpg.genkey name="Ada Lovelace" email="ada.lovelace@example.org"`,
 * run through `basilisk run`. Both blocks are the same Curve25519 key — the op
 * emits the private one as its tip and writes the public one beside it.
 *
 * The card parses these with `openpgp`'s `readKey`, so the user id, the grouped
 * fingerprint and the dates on screen are all read back out of the bytes below.
 * Substitute a plausible-looking fake and the card falls back to "OpenPGP key",
 * which is exactly the unreadable state it was written to replace.
 */

const PUBLIC = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEam4XaRYJKwYBBAHaRw8BAQdA8+AobcRqM6mF0HHPBLcvvqkCeJsmzQjh
LhNuc5p5mufNJ0FkYSBMb3ZlbGFjZSA8YWRhLmxvdmVsYWNlQGV4YW1wbGUu
b3JnPsLAEwQTFgoAhQWCam4XaQMLCQcJEJBJCKDw7PCrRRQAAAAAABwAIHNh
bHRAbm90YXRpb25zLm9wZW5wZ3Bqcy5vcmf1MV9+y/ueZDslNhoOvMo+v4vW
s8Zg3GaoNUG2Dj18tgUVCggODAQWAAIBAhkBApsDAh4BFiEE7xXNP3WUeENx
6CwKkEkIoPDs8KsAADuCAQDz9ztasAjXsN8oT0mAGmwzDdt1PSajdEbfvWEQ
2c1DQgEA5NfmtBIcJz79o5k+6CnUBOA48OG7lP9DFgsw2y11XgPOOARqbhdp
EgorBgEEAZdVAQUBAQdAY69jbuZTvA63DM+fpp6Xq/UOBKxxI8yhfZqjoeBH
XQ0DAQgHwr4EGBYKAHAFgmpuF2kJEJBJCKDw7PCrRRQAAAAAABwAIHNhbHRA
bm90YXRpb25zLm9wZW5wZ3Bqcy5vcmfpdy1K1vW6H6yajxGjQfj3VcQyFcm0
JnF/5a3qBUfbLQKbDBYhBO8VzT91lHhDcegsCpBJCKDw7PCrAAD0XgEA8N8Q
o0IxEX4N35CJyJf6ftg2rgNMjgBFRXMuCiCMLrcBAIChaMVoKQVwYVzK4vIp
a874GVWABikbRCjAXs6f3xsL
=do/f
-----END PGP PUBLIC KEY BLOCK-----`;

const PRIVATE = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEam4XaRYJKwYBBAHaRw8BAQdA8+AobcRqM6mF0HHPBLcvvqkCeJsmzQjh
LhNuc5p5mucAAP9nS14EPUaa8onWkPC0a0H+K2CcTbEaZxm2pdwchtyhJxCb
zSdBZGEgTG92ZWxhY2UgPGFkYS5sb3ZlbGFjZUBleGFtcGxlLm9yZz7CwBME
ExYKAIUFgmpuF2kDCwkHCRCQSQig8Ozwq0UUAAAAAAAcACBzYWx0QG5vdGF0
aW9ucy5vcGVucGdwanMub3Jn9TFffsv7nmQ7JTYaDrzKPr+L1rPGYNxmqDVB
tg49fLYFFQoIDgwEFgACAQIZAQKbAwIeARYhBO8VzT91lHhDcegsCpBJCKDw
7PCrAAA7ggEA8/c7WrAI17DfKE9JgBpsMw3bdT0mo3RG371hENnNQ0IBAOTX
5rQSHCc+/aOZPugp1ATgOPDhu5T/QxYLMNstdV4Dx10Eam4XaRIKKwYBBAGX
VQEFAQEHQGOvY27mU7wOtwzPn6ael6v1DgSscSPMoX2ao6HgR10NAwEIBwAA
/2r1MWlI2hcmW85KbP5cSb1kxy131K4LT1msXKimQYKwEGPCvgQYFgoAcAWC
am4XaQkQkEkIoPDs8KtFFAAAAAAAHAAgc2FsdEBub3RhdGlvbnMub3BlbnBn
cGpzLm9yZ+l3LUrW9bofrJqPEaNB+PdVxDIVybQmcX/lreoFR9stApsMFiEE
7xXNP3WUeENx6CwKkEkIoPDs8KsAAPReAQDw3xCjQjERfg3fkInIl/p+2Dau
A0yOAEVFcy4KIIwutwEAgKFoxWgpBXBhXMri8ilrzvgZVYAGKRtEKMBezp/f
Gws=
=2svL
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
  <OpenPgpKeyCard content="" fingerprint="EF15CD3F7594784371E82C0A904908A0F0ECF0AB" publicOnly />
);
