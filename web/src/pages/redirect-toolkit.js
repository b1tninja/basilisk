/**
 * Soft-migrate legacy /encrypt and /decrypt into Toolkit fragment entry points.
 * Dest comes from <html data-toolkit-hash="encrypt|decrypt">.
 */
const dest = document.documentElement.dataset.toolkitHash || "encrypt";
const starter =
  dest === "decrypt" || dest === "symencrypt" ? dest : "encrypt";
location.replace(`/toolkit#${starter}`);
