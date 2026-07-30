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
    <Layout active="toolkit">
      {selfTestError ? (
        <p className="text-error" style={{ margin: "0.5rem 1.25rem", flexShrink: 0 }}>
          {selfTestError}
        </p>
      ) : null}
      <ToolkitShell />
    </Layout>
  );
}

installBootDiagnostics();
createRoot(document.getElementById("app")!).render(<ToolkitPage />);
