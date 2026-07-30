/**
 * Soft-migrate legacy /encrypt and /decrypt into Toolkit fragment entry points.
 * Dest comes from <html data-toolkit-hash="encrypt|decrypt">.
 */
import { installBootDiagnostics } from "../lib/boot-diagnostics.js";

// Watch even here: if this page ever fails to redirect (CSP, module error),
// diagnostics say why instead of leaving a silent blank page.
installBootDiagnostics();
const dest = document.documentElement.dataset.toolkitHash || "encrypt";
const starter =
  dest === "decrypt" || dest === "symencrypt" ? dest : "encrypt";
location.replace(`/toolkit#${starter}`);
