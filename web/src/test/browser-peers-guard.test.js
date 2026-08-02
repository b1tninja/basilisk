/**
 * The e2e harness's skip guard, in the fast suite.
 *
 * `src/test/e2e/` needs a browser and so cannot run here. Its *guard* can, and
 * must: the guard decides whether a missing transport proof reads as "not
 * applicable" or as a failure, and a guard that gets that wrong is how a broken
 * transport ships green. `ssh-format.test.js` asserts its own guard's branches
 * for exactly this reason, and this is the same shape of test.
 */

import { describe, expect, it } from "vitest";
import { classifyLaunchFailure } from "./helpers/browser-peers.js";

describe("classifyLaunchFailure", () => {
  it("treats a browser that was never downloaded as absent", () => {
    // Playwright's real wording, both halves of the message it prints.
    expect(
      classifyLaunchFailure(
        "browserType.launch: Executable doesn't exist at C:\\ms-playwright\\chromium-1234\\chrome.exe"
      )
    ).toBe("absent");
    expect(classifyLaunchFailure("Please run the following command to download new browsers:\nnpx playwright install")).toBe(
      "absent"
    );
  });

  it("treats an uninstalled playwright as absent", () => {
    expect(classifyLaunchFailure("Cannot find package 'playwright' imported from x.js")).toBe(
      "absent"
    );
    expect(classifyLaunchFailure("ERR_MODULE_NOT_FOUND")).toBe("absent");
  });

  it("treats every other launch failure as broken, so it fails rather than skips", () => {
    // These are the ones that matter. A crash, a refused sandbox or a profile
    // that will not open are all environment faults; classifying any of them
    // as "absent" would turn a red transport suite green and silent.
    expect(classifyLaunchFailure("Target page, context or browser has been closed")).toBe("broken");
    expect(classifyLaunchFailure("Failed to launch: spawn EACCES")).toBe("broken");
    expect(classifyLaunchFailure("Chromium sandbox is not supported")).toBe("broken");
    expect(classifyLaunchFailure("browserType.launch: Timeout 30000ms exceeded")).toBe("broken");
    expect(classifyLaunchFailure("")).toBe("broken");
  });
});
