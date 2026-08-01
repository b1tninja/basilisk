/**
 * The modal scroll lock, minus the `<style>` element the CSP refuses.
 *
 * `@radix-ui/react-dialog` and `@radix-ui/react-menu` — every Sheet and every
 * dropdown in the app — wrap their content in `react-remove-scroll`. Most of
 * what that does is script: wheel and touch capture, the "shard" that keeps
 * the open panel scrollable while the page behind it is not, pinch-zoom
 * allowance. All of that works fine under our policy. One part did not.
 *
 * `react-remove-scroll-bar` delivered its half — `body[data-scroll-locked] {
 * overflow: hidden }` and the scrollbar-gap compensation — by creating a
 * `<style>` element at runtime and appending a text node to it. Under
 * `style-src 'self'` that is refused: measured on the built site, opening the
 * ceremony Sheet on /toolkit or any dropdown on /my-keys produced a
 * `style-src-elem` violation with disposition `enforce`, the element landed in
 * `<head>` with a null `.sheet`, and the page behind the open dropdown still
 * scrolled. The lock had been decorative in production for as long as the
 * policy has been strict, and nothing failed loudly enough to say so.
 *
 * This module is aliased over the package in `vite.config.js`. It keeps the
 * part that genuinely needs script — counting nested locks and putting
 * `data-scroll-locked` on `<body>` — and drops the injection. The rules
 * themselves are stated in `site.css`, which is loaded on every page. That is
 * the same trade the ScrollArea took (see `components/ui/scroll-area.tsx`):
 * the library keeps the behaviour, the stylesheet keeps the declarations. The
 * alternative was a `sha256-` exemption in the policy, which would have
 * silenced the report while leaving a runtime `<style>` write on the page —
 * the exact thing `style-src` is there to prevent — and would have to be
 * re-derived every time the library changed a byte of that CSS.
 *
 * The one thing here that cannot be a static rule is the width of the
 * scrollbar being hidden: it is 0 where the platform draws overlay scrollbars
 * and about 15px where it does not. That value goes out through
 * `lib/css-vars`, whose constructed stylesheet is the app's established way to
 * get a continuous number into CSS without an inline style. What it feeds is
 * padding on the scroll container, not the margin rewrite the library did —
 * see the note in `site.css` for why that distinction matters on a centred
 * page — and it goes out under a name of ours rather than the library's, for
 * the reason on `gutterVariable` below.
 *
 * @module lib/scroll-lock
 */
import { useEffect } from "react";
import { setCssVar } from "./css-vars.js";

/**
 * Re-exported from paths the alias does not match, so the class names and the
 * measurement helper cannot drift from the library that defines them. Nothing
 * in the tree imports these from the bare specifier today; they are here so
 * that this module is a whole answer to `react-remove-scroll-bar`, and
 * `scroll-lock.test.js` fails if the package ever grows an export it does not
 * cover.
 */
export {
  zeroRightClassName,
  fullWidthClassName,
  noScrollbarsClassName,
  removedBarSizeVariable,
} from "react-remove-scroll-bar/constants";
export { getGapWidth } from "react-remove-scroll-bar/dist/es2015/utils.js";

/** Matches the library's attribute name; `site.css` selects on it. */
export const lockAttribute = "data-scroll-locked";

/**
 * Where the measured scrollbar width is published for `site.css` to read.
 *
 * Deliberately *not* `removedBarSizeVariable`. The library scoped that name to
 * `body[data-scroll-locked]`, so it existed only while a lock was held and its
 * own docs say to expect it undefined and fall back. `lib/css-vars` writes to
 * `:root` and never clears, so reusing the name would leave
 * `--removed-body-scroll-bar-size: 15px` standing on an unlocked page, and the
 * documented uses of it — `right:` on `.right-scroll-bar-position`,
 * `margin-right:` on `.width-before-scroll-bar` — would silently lay out
 * against a scrollbar that is on screen. A private name cannot be mistaken for
 * the library's contract; `removedBarSizeVariable` stays exported and unset, so
 * anything reaching for it gets the fallback it was told to expect.
 */
export const gutterVariable = "--scroll-lock-gutter";

function currentCount() {
  const n = parseInt(document.body.getAttribute(lockAttribute) || "0", 10);
  return Number.isFinite(n) ? n : 0;
}

/**
 * How much width the scrollbar is currently taking from the viewport.
 *
 * Only meaningful before the lock applies — once `overflow: hidden` is on, the
 * scrollbar is gone and this reads 0, which is why only the outermost lock
 * measures.
 */
function measureGutter() {
  return Math.max(0, window.innerWidth - document.documentElement.clientWidth);
}

/**
 * Reference-count the lock on `<body>`.
 *
 * A count rather than a boolean because locks nest: a dropdown inside an open
 * Sheet unmounts after the Sheet has already re-locked, and a boolean would
 * unlock the page underneath a modal that is still open. The count is kept on
 * the attribute itself, exactly as the library kept it, so a stray unmount
 * cannot leave the two out of step.
 */
export const useLockAttribute = () => {
  useEffect(() => {
    const depth = currentCount();
    // The effect runs after layout and before the attribute lands, so the
    // scrollbar is still on screen here. A nested lock would measure 0 and
    // undo the outer one's compensation, so it does not measure at all.
    if (depth === 0) setCssVar(gutterVariable, measureGutter(), "px");
    document.body.setAttribute(lockAttribute, String(depth + 1));
    return () => {
      const next = currentCount() - 1;
      if (next <= 0) document.body.removeAttribute(lockAttribute);
      else document.body.setAttribute(lockAttribute, String(next));
    };
  }, []);
};

/**
 * Drop-in for the library component. Renders nothing; the attribute is the
 * whole contract between this module and the stylesheet.
 *
 * `noRelative` and `gapMode` are accepted and ignored: both only ever tuned
 * declarations that now live in `site.css`, and Radix passes neither.
 */
export const RemoveScrollBar = () => {
  useLockAttribute();
  return null;
};
