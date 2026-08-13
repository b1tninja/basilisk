// First import on the page, deliberately: it installs listeners for failures
// that happen *while the rest of this module graph loads*. Anything imported
// above it could fail unobserved.
import { installBootDiagnostics } from "../lib/boot-diagnostics.js";
import { createRoot } from "react-dom/client";
import { useEffect, useRef } from "react";
import { Layout } from "../components/Layout";
import { mountPublished } from "../lib/published-mount.js";

/**
 * The public halves on your account — and nothing else.
 *
 * `/my-keys` drew two stores under one heading: "Your keys" (public keys the
 * server holds for your address) above "Your browser vault" (private keys in
 * this browser). A session told somebody with three of the first that they had
 * none of the second, and both statements were true. The vault's home is now
 * the toolkit's Keys tray, beside the run that needs it; this page is the other
 * half, named for the errand rather than for the possessive that hid it.
 */
function PublishedPage() {
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    return mountPublished(el);
  }, []);

  return (
    <Layout active="published">
      <div className="page-header">
        <h1>Published keys</h1>
        <p className="muted">
          The public halves you have published to this server under your
          verified address. Anyone can fetch them — that is what publishing is
          for. <strong>None of them can sign, decrypt or unlock anything.</strong>{" "}
          A public key has no private half, so nothing listed here proves you
          hold the key it names, and nothing here does any work on this machine.
        </p>
      </div>

      <div ref={ref}>
        <div id="content" />
        <p id="error" className="text-error hidden" />
      </div>
    </Layout>
  );
}

installBootDiagnostics();
createRoot(document.getElementById("app")!).render(<PublishedPage />);
