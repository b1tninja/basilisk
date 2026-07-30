// First import on the page, deliberately: it installs listeners for failures
// that happen *while the rest of this module graph loads*. Anything imported
// above it could fail unobserved.
import { installBootDiagnostics } from "../lib/boot-diagnostics.js";
import { createRoot } from "react-dom/client";
import { useEffect, useRef } from "react";
import { Layout } from "../components/Layout";
import { mountMyKeys } from "../lib/my-keys-mount.js";

function MyKeysPage() {
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    return mountMyKeys(el);
  }, []);

  return (
    <Layout active="my-keys">
      <div className="page-header">
        <h1>My Keys</h1>
        <p className="muted">
          Submit OpenPGP public keys and manage keys associated with your identity.
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
createRoot(document.getElementById("app")!).render(<MyKeysPage />);
