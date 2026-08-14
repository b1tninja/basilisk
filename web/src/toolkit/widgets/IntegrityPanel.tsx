import { useCallback, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import {
  LIMIT_NOTE,
  SINGLE_SOURCE_NOTE,
  checkDeployment,
  type DeploymentVerdict,
} from "../../lib/toolkit/deployment-check.js";

export type IntegrityPanelProps = {
  /** Catalog fixture. Omitted, the panel runs the real check on mount. */
  verdict?: DeploymentVerdict;
  /** The page's live CSP, for the "read it yourself" disclosure. */
  policy?: string;
  /** Suppresses the automatic run — the catalog shows fixed states. */
  live?: boolean;
};

const PENDING: DeploymentVerdict = {
  status: "checking",
  tone: "pending",
  headline: "Checking…",
  detail: "Folding this page's module hashes into a root and fetching the pin document.",
  root: "",
  expectedRoot: "",
  leafCount: 0,
  pageKey: "",
  pinUrls: [],
  fetched: 0,
  raw: "",
};

/** The CSP the page actually declares — read, not asserted. */
function livePolicy(): string {
  if (typeof document === "undefined") return "";
  return (
    document
      .querySelector('meta[http-equiv="Content-Security-Policy"]')
      ?.getAttribute("content") || ""
  );
}

/**
 * Verify-this-deployment.
 *
 * The threat model's first section says a served page can be tampered with
 * exactly once, for exactly one person, and then tells the reader to check the
 * module roots by hand. Almost nobody does. This is that check, run and
 * explained — see `lib/toolkit/deployment-check.js` for why four of its six
 * outcomes are "cannot verify" and why none of those is painted green.
 *
 * Two rules the layout enforces:
 *
 * - **The limitation is not in a disclosure.** It sits under every verdict,
 *   including the successful one, because a green tick here is precisely the
 *   moment a reader is most likely to stop reading. Collapsing it would make
 *   the panel more reassuring and less true.
 * - **The numbers are shown in full, not summarised.** The root is the thing a
 *   person compares against another machine or another person; a truncated one
 *   is decorative. It is selectable text for the same reason.
 */
export function IntegrityPanel({ verdict, policy, live = true }: IntegrityPanelProps) {
  const [state, setState] = useState<DeploymentVerdict>(verdict ?? PENDING);
  const [busy, setBusy] = useState(false);
  const csp = policy ?? livePolicy();

  const run = useCallback(async () => {
    setBusy(true);
    setState(PENDING);
    try {
      setState(await checkDeployment());
    } catch (err) {
      setState({
        ...PENDING,
        status: "unreachable",
        tone: "error",
        headline: "The check itself failed to run.",
        detail: `${err instanceof Error ? err.message : String(err)}. That is not a pass.`,
      });
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    if (verdict || !live) return;
    void run();
  }, [verdict, live, run]);

  return (
    <section className="integrity-panel" data-status={state.status}>
      <p className="integrity-verdict" data-tone={state.tone}>
        <strong className="integrity-headline">{state.headline}</strong>
        <span className="integrity-detail">{state.detail}</span>
      </p>

      <p className="integrity-limit">{LIMIT_NOTE}</p>

      <dl className="integrity-facts">
        <dt>Page</dt>
        <dd>
          <code>{state.pageKey || "—"}</code>
        </dd>
        <dt>Loaded root</dt>
        <dd>
          <code className="integrity-root">{state.root || "—"}</code>
          {state.leafCount ? (
            <span className="integrity-leaves">
              {" "}
              over {state.leafCount} module{state.leafCount === 1 ? "" : "s"}
            </span>
          ) : null}
        </dd>
        {/* Only shown when a pin was actually read. An "expected" row reading
            "—" invites the reader to assume there was something to compare. */}
        {state.expectedRoot ? (
          <>
            <dt>Pinned root</dt>
            <dd>
              <code className="integrity-root">{state.expectedRoot}</code>
            </dd>
          </>
        ) : null}
        <dt>Pin sources</dt>
        <dd>
          {state.pinUrls.length ? (
            <ul className="integrity-pins">
              {state.pinUrls.map((u) => (
                <li key={u}>
                  <code>{u}</code>
                </li>
              ))}
            </ul>
          ) : (
            "none configured"
          )}
          {/* Said here, next to the count, and not only in whichever verdict
              happens to be showing. One source is the configuration every
              deployment this repo builds actually has, so a reader who has just
              been told the pin matched is looking at the row that explains what
              that did and did not compare. */}
          {state.status !== "checking" && state.pinUrls.length < 2 ? (
            <p className="integrity-single-source">{SINGLE_SOURCE_NOTE}</p>
          ) : null}
        </dd>
      </dl>

      <details className="integrity-policy">
        <summary>The policy this page declares</summary>
        <p>
          Read it against the block in <code>docs/THREAT-MODEL.md</code>. It is quoted
          there verbatim, and a test pins the two together — but that test ran on a
          machine, and this is the page you were served.
        </p>
        <pre>{csp || "No Content-Security-Policy meta on this page."}</pre>
      </details>

      <div className="integrity-actions">
        {/* Busy, not refused. The check is running and the label says so, so
            there is no state to explain — only a re-entry to prevent. */}
        <Button variant="secondary" onClick={() => void run()} busy={busy}>
          {busy ? "Checking…" : "Check again"}
        </Button>
      </div>
    </section>
  );
}
