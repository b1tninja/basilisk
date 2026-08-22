// First import on the page, deliberately: it installs listeners for failures
// that happen *while the rest of this module graph loads*. Anything imported
// above it could fail unobserved.
import { installBootDiagnostics } from "../lib/boot-diagnostics.js";
import { createRoot } from "react-dom/client";
import { useEffect, useState } from "react";
import { Layout } from "../components/Layout";
import { ToolkitShell } from "../toolkit/ToolkitShell";
import { CryptoModuleError, runCryptoSelfTests } from "../lib/crypto-self-test.js";
import "../css/toolkit.css";

function ToolkitPage() {
  const [selfTestError, setSelfTestError] = useState("");

  useEffect(() => {
    void runCryptoSelfTests()
      .then((result) => {
        if (!result.passed) {
          throw new CryptoModuleError(result.error || "POST failed");
        }
      })
      .catch((err) => {
        setSelfTestError(err?.message || "Crypto self-test failed");
      });
  }, []);

  return (
    // `ToolkitShell` points a labelled `<main>` at the notebook pane; a
    // second one here would nest the landmarks and name the wrong region.
    <Layout active="toolkit" ownsMain>
      {selfTestError ? (
        <p className="text-error page-notice">
          {selfTestError}
        </p>
      ) : null}
      <ToolkitShell />
    </Layout>
  );
}

installBootDiagnostics();
// Automation hooks (mint session-only test keys, …) — dev server only. The
// condition is statically false in the build, so the module is tree-shaken
// out and production ships no e2e surface.
if (import.meta.env.DEV) {
  void import("../lib/e2e-hooks.js");
}
createRoot(document.getElementById("app")!).render(<ToolkitPage />);
