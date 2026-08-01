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
 */
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
        "max-h-40 max-w-40 self-start rounded-[4px] bg-white p-1 [image-rendering:pixelated]",
        className
      )}
      data-qr-artifact
    />
  );
}
