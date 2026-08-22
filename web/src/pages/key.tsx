// First import on the page, deliberately: it installs listeners for failures
// that happen *while the rest of this module graph loads*. Anything imported
// above it could fail unobserved.
import { installBootDiagnostics } from "../lib/boot-diagnostics.js";
import { createRoot } from "react-dom/client";
import { useEffect, useRef } from "react";
import { Layout } from "../components/Layout";
import { mountKey } from "../lib/key-mount.js";

function KeyPage() {
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    mountKey(el);
  }, []);

  return (
    <Layout active="key">
      <div ref={ref}>
        {/* The page's name, rendered by the page rather than by the fetch.
            `key-mount` used to write this `<h1>` as the first line of the
            success markup, which meant the two states where a reader most needs
            to be told where they are had no heading at all: "Loading key
            details…" was a headingless document, and so was every failure --
            missing `?fpr=`, key not found, server down. A screen reader's
            heading list was empty and the tab title was the only thing naming
            the page. What this page *is* does not depend on whether the fetch
            succeeded, so it is stated once here and holds in all three states.

            `mb-0` keeps the gap to the fingerprint line what it was when the
            two were siblings inside the header row and their margins collapsed. */}
        <h1 className="mb-0">OpenPGP key</h1>
        <p id="error" className="text-error hidden" />
        <p id="loading" className="muted">
          Loading key details…
        </p>
        <div id="content" className="hidden" />
      </div>
    </Layout>
  );
}

installBootDiagnostics();
createRoot(document.getElementById("app")!).render(<KeyPage />);
