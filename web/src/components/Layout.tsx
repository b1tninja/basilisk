import type { ReactNode } from "react";
import { ProfileMenu } from "./ProfileMenu";
import { BasiliskMark } from "./BasiliskMark";
import "../css/site.css";

/**
 * The nav, and the two words it stopped conflating.
 *
 * "My Keys" named one page holding two stores — public keys on your account
 * and private keys in this browser — and a possessive is the one thing they
 * have in common. It is two entries now, each named for its errand: **Keys**
 * is the vault, in the toolkit tray where the run that needs it is;
 * **Published** is what this server hands out under your address.
 *
 * Encrypt and Decrypt keep their entries although their pages are gone. They
 * are the words a newcomer arrives with, and "Toolkit" names neither — the
 * fragments load the same two starters those pages used to redirect to.
 */
const NAV_LINKS: { id: string; label: string; href: string }[] = [
  { id: "search", label: "Search", href: "/" },
  { id: "encrypt", label: "Encrypt", href: "/toolkit#encrypt" },
  { id: "decrypt", label: "Decrypt", href: "/toolkit#decrypt" },
  { id: "verify", label: "Verify", href: "/verify" },
  { id: "keys", label: "Keys", href: "/toolkit#keys" },
  { id: "published", label: "Published", href: "/published" },
  { id: "toolkit", label: "Toolkit", href: "/toolkit" },
  { id: "preferences", label: "Preferences", href: "/preferences" },
  { id: "stats", label: "Stats", href: "/stats" },
];

export function Layout({
  active,
  children,
  ownsMain = false,
}: {
  active: string;
  children: ReactNode;
  /**
   * The children already provide the page's `<main>`, so this component must
   * not add a second one.
   *
   * `/toolkit` is the only caller that sets it, and the reason is structural
   * rather than a quirk: the shell is a three-column workspace, and the region
   * a person means by "the main content" is the notebook -- not the shelf and
   * tray flanking it. `ToolkitShell` therefore points a labelled `<main>` at
   * the notebook alone, and wrapping the whole workspace in another one would
   * both nest the landmarks and claim the wrong thing.
   */
  ownsMain?: boolean;
}) {
  return (
    <>
      <nav>
        <a className="nav-logo" href="/">
          <BasiliskMark size="md" variant="light" />
          Basilisk
        </a>
        <div className="nav-links">
          {NAV_LINKS.map((link) => (
            <a
              key={link.id}
              className={link.id === active ? "nav-link active" : "nav-link"}
              href={link.href}
            >
              {link.label}
            </a>
          ))}
        </div>
        <ProfileMenu />
      </nav>
      {/* Every page built on this Layout had a `<nav>` and nothing else with a
          role, so the whole document body was one undifferentiated region and
          "skip to the content" had no content to skip to. `191f2ed` gave
          `/toolkit` its `<main>`; these six share one component, so they share
          one fix.

          A plain block box on purpose. `body` here is `max-width` plus `margin:
          0 auto` with no flex or grid and no `body > *` selector anywhere in
          `site.css`, so this element inherits the layout it wraps and changes
          none of it -- checked before adding it, because a landmark that
          reflows the page it labels would trade one defect for a worse one. */}
      {ownsMain ? children : <main>{children}</main>}
    </>
  );
}
