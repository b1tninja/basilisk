import { cn } from "@/lib/cn";
import { qrDataUri } from "../../lib/toolkit/artifact-readouts.js";

/**
 * The QR read-out (§37b, design_handoff_artifact_actions).
 *
 * A `qr` artifact's content is SVG source. Rendered as text it is the one
 * artifact in the notebook that is *useless* in its raw form — nobody reads a
 * QR by reading its path data, and nobody can scan it either.
 *
 * Drawn as an `<img>` with a `data:image/svg+xml;base64,` source, which
 * `img-src 'self' data:` permits. Not `dangerouslySetInnerHTML`: inlining the
 * SVG string would be a script-injection surface for a value that came out of
 * the pipeline, and a QR is exactly the kind of value that arrives from
 * somewhere else.
 *
 * A sensitive QR — the QR of a share — never reaches this component: the tile
 * masks it and a kind's `view` does not run on a masked value. There is no
 * `publicView` here on purpose. A QR *is* the secret, in a form a camera
 * across the room can read, so there is nothing about it that is public.
 *
 * ## The size is the tile's decision, not the producer's
 *
 * It was `max-h-40 max-w-40` — a *maximum* of 160px, against an intrinsic size
 * that never reached it. Measured on `#artifacttiles`: a 29-module code at
 * `moduleSize: 3` is a 95×95 SVG, so the `<img>` drew 103×103 CSS px including
 * its padding and the cap was decoration. Expanding into the 560px Sheet
 * changed nothing, because the intrinsic size still won and a maximum is not a
 * target — so the one artifact whose entire purpose is to be read by a camera
 * had no affordance that made it bigger.
 *
 * The intrinsic size is `moduleSize`, a parameter of the `qr` **op**: how big
 * a code draws in the notebook was being decided by an argument written three
 * layers away, for a value that is the same code at any scale. That is a
 * layout decision in the wrong layer, and the fix is for the tile to state a
 * size. The source is SVG, so the browser rasterizes at whatever it is given
 * and upscaling is exact — no interpolation, no `moduleSize` dependence.
 *
 * `QR_TILE_EDGE` is what makes the claim checkable: at 192 CSS px, a code
 * stays at or above the ~3 device pixels per module that phone scanning wants
 * up to **96 modules** at `devicePixelRatio` 1.5 — QR version 22, far past
 * anything this app emits (a 24-word BLIP39 share is version 7, 45 modules).
 * In the Sheet it takes the available width instead, which is where a code too
 * dense for the row is meant to go.
 */

/**
 * The tile's target edge in CSS pixels — a target, not a maximum.
 *
 * Applied as a class rather than a style attribute (`style-src 'self'` refuses
 * an inline write, and a test asserts it), and stated here so the module-count
 * arithmetic above has a number to be arithmetic about.
 */
export const QR_TILE_EDGE = 192;

export function QrArtifact({
  content,
  label,
  className,
}: {
  content: string;
  label?: string;
  className?: string;
}) {
  const src = qrDataUri(content);
  if (!src) return null;
  return (
    <img
      src={src}
      alt={label ? `QR code for ${label}` : "QR code"}
      className={cn(
        // `w-48` is QR_TILE_EDGE; `max-w-full` keeps it inside a narrow panel,
        // and `h-auto` keeps it square when it does. The Sheet overrides the
        // width from outside (see `OutputList`) rather than this component
        // growing a size prop the kind table would have to thread through.
        "h-auto w-48 max-w-full self-start rounded-[4px] bg-white p-1 [image-rendering:pixelated]",
        className
      )}
      data-qr-artifact
    />
  );
}
