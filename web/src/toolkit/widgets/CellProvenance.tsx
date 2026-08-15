import { cn } from "@/lib/cn";

/**
 * Whose values a cell's last run used, when any of them came from another
 * machine — dealer-absent finding 7a's fix, on the surface that finding names.
 *
 * The recovering machine's gather takes shares off the room and recombines
 * them, and until this line existed the sender's fingerprint rode on
 * `meta.from` and reached "no tile, no slot row and no receipt": the one
 * machine that ends up with the secret was the one machine with no readable
 * record of where it came from. The record lives on the run now
 * (`lib/toolkit/run.js`), the kernel keeps each cell's slice of it, and this
 * draws that slice inside the cell it is about — the thing a person is
 * reading when the secret comes back.
 *
 * What it claims is only what is known. A row appears for each value that
 * verifiably arrived from elsewhere; values made locally are simply not
 * listed, and the heading says "arrived from other machines" rather than
 * implying the list is everything the cell touched (the receipt carries the
 * full read/write record). Two shapes of origin, kept visibly distinct:
 *
 * - a **fingerprint** — whole, never shortened, because provenance names
 *   peers by whole fingerprint — for a value the exchange delivered from a
 *   key-confirmed sender;
 * - a **link name** for a value off a hand-carried `peer.*` link, said with
 *   "sender not identified by any key" — the sender there is genuinely
 *   unknown, and an unknown origin must say so rather than borrow the shape
 *   of a verified one.
 */

/** One row of the kernel's per-cell record (`kernel.js` CellProvenance). */
type OriginRow = { slot?: string; step?: string; from?: string; link?: string };

export type CellProvenanceData = {
  reads: OriginRow[];
  writes: OriginRow[];
  received: OriginRow[];
};

/**
 * The rows worth drawing: everything with an origin, deduplicated.
 *
 * Slot rows lead and in-pipeline arrivals follow, with one asymmetric rule:
 * an arrival whose origin already appears on a slot row is dropped. The
 * receive cell (`quorum.recv from=X | out $share-2`) both receives from X and
 * writes a slot holding X's value — one fact, and two lines saying it would
 * read as two. The gather's fresh `quorum.recv`, whose message no slot ever
 * holds, survives the rule, which is the row finding 7a is about.
 *
 * Exported and pure so the copy and the dedupe can be pinned without a
 * renderer.
 */
export function provenanceRows(
  provenance: CellProvenanceData | null | undefined
): { key: string; slot?: string; from?: string; link?: string }[] {
  if (!provenance) return [];
  const out: { key: string; slot?: string; from?: string; link?: string }[] = [];
  const seen = new Set<string>();
  const originKey = (r: OriginRow) => (r.from ? `from:${r.from}` : `link:${r.link}`);
  const slotOrigins = new Set<string>();
  for (const r of [...provenance.reads, ...provenance.writes]) {
    if (!r.from && !r.link) continue;
    slotOrigins.add(originKey(r));
    const key = `${r.slot}·${originKey(r)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ key, slot: r.slot, from: r.from, link: r.link });
  }
  for (const r of provenance.received) {
    if (!r.from && !r.link) continue;
    if (slotOrigins.has(originKey(r))) continue;
    const key = `recv·${originKey(r)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ key, from: r.from, link: r.link });
  }
  return out;
}

export function CellProvenance({
  provenance,
  className,
}: {
  provenance: CellProvenanceData | null;
  className?: string;
}) {
  const rows = provenanceRows(provenance);
  if (!rows.length) return null;
  return (
    <div className={cn("text-[10.5px] text-[var(--muted-foreground)]", className)} data-cell-provenance>
      <p>This cell&rsquo;s last run used values that arrived from other machines:</p>
      <ul className="mt-0.5 space-y-0.5">
        {rows.map((r) => (
          <li key={r.key} className="flex flex-wrap items-baseline gap-x-1.5">
            {r.slot ? (
              <code className="font-mono text-[var(--foreground)]">${r.slot}</code>
            ) : (
              <span>received in this run</span>
            )}
            {r.from ? (
              <>
                <span>— from</span>
                {/* One element, so the 40 hex read off the screen are the 40
                    hex a test or a person compares; CSS may wrap it, the
                    string does not break. */}
                <code className="break-all font-mono">{r.from}</code>
              </>
            ) : (
              <span>
                — over link <code className="font-mono">{r.link}</code>, whose sender is not
                identified by any key
              </span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
