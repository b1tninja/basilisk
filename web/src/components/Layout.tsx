import type { ReactNode } from "react";
import { ProfileMenu } from "./ProfileMenu";
import { BasiliskMark } from "./BasiliskMark";
import "../css/site.css";

const NAV_LINKS: { id: string; label: string; href: string }[] = [
  { id: "search", label: "Search", href: "/" },
  { id: "encrypt", label: "Encrypt", href: "/toolkit#encrypt" },
  { id: "decrypt", label: "Decrypt", href: "/toolkit#decrypt" },
  { id: "verify", label: "Verify", href: "/verify" },
  { id: "my-keys", label: "My Keys", href: "/my-keys" },
  { id: "quorum", label: "Quorum", href: "/quorum" },
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
