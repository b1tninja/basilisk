import { createRoot } from "react-dom/client";
import { Auth } from "../lib/auth.js";
import {
  CryptoModuleError,
  runCryptoSelfTests,
} from "../lib/crypto-self-test.js";
import { ToolkitShell } from "./ToolkitShell";
import "../css/toolkit.css";

Auth.initWidget(document.getElementById("auth-widget"), "/toolkit");

const host = document.getElementById("toolkit-app");
if (!host) {
  throw new Error("#toolkit-app mount missing");
}

host.id = "toolkit-root";
createRoot(host).render(<ToolkitShell />);

void runCryptoSelfTests()
  .then((result) => {
    if (!result.passed) {
      throw new CryptoModuleError(result.error || "POST failed");
    }
  })
  .catch((err) => {
    const el = document.getElementById("error");
    if (el) {
      el.textContent = err?.message || "Crypto self-test failed";
      el.classList.remove("hidden");
    }
  });
