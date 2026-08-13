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

export function Layout({ active, children }: { active: string; children: ReactNode }) {
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
      {children}
    </>
  );
}
