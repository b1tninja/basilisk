/**
 * Toolkit-run handler shared by crypto-worker and Node tests.
 * Keeps the worker message path testable without a browser Worker.
 */

import { readKey, readPrivateKey } from "openpgp";
import { runRecipe } from "./toolkit/engine.js";

/**
 * @param {{
 *   ast: import("./toolkit/recipe.js").RecipeAst,
 *   recipientKeysArmored?: string[],
 *   recipientFingerprints?: string[],
 *   inputs?: import("./toolkit/engine.js").RuntimeBindings["inputs"],
 *   privateKeyArmored?: string,
 *   passphrase?: string,
 *   encryption?: import("./toolkit/engine.js").RuntimeBindings["encryption"],
 *   fipsMode?: boolean,
 *   suiteStatus?: import("./toolkit/suite-gate.js").SuiteStatusMap,
 * }} msg
 * @returns {Promise<{ artifacts: import("./toolkit/engine.js").ToolkitArtifact[], privateKey: import("openpgp").PrivateKey|null }>}
 */
export async function executeToolkitRun(msg) {
  /** @type {import("openpgp").Key[]} */
  const recipients = [];
  for (const armored of msg.recipientKeysArmored || []) {
    recipients.push(await readKey({ armoredKey: armored }));
  }

  /** @type {import("./toolkit/engine.js").RuntimeBindings["inputs"]} */
  const inputs = msg.inputs ? { ...msg.inputs } : {};
  /** @type {import("openpgp").PrivateKey|null} */
  let privateKey = null;

  if (msg.privateKeyArmored && inputs.gpg) {
    inputs.gpg = {
      ...inputs.gpg,
      privateKeyArmored: String(msg.privateKeyArmored),
      passphrase: msg.passphrase || inputs.gpg.passphrase || "",
    };
    privateKey = await readPrivateKey({
      armoredKey: String(msg.privateKeyArmored),
    });
  }

  try {
    const artifacts = await runRecipe(msg.ast, {
      recipients,
      recipientFingerprints: msg.recipientFingerprints || [],
      inputs,
      encryption: msg.encryption,
      fipsMode: !!msg.fipsMode,
      suiteStatus: msg.suiteStatus,
    });
    return { artifacts, privateKey };
  } finally {
    if (inputs.gpg) inputs.gpg.privateKeyArmored = "";
  }
}
