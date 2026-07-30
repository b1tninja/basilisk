import { useEffect, useState } from "react";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { Auth } from "../lib/auth.js";

interface User {
  authenticated: boolean;
  email: string;
}

function initialsFor(email: string): string {
  const local = String(email || "").split("@")[0];
  const letters = local.replace(/[^a-zA-Z0-9]/g, "");
  return (letters.slice(0, 2) || "?").toUpperCase();
}

function loginHref(provider: "aad" | "google", redirectPath: string): string {
  const target = new URL(redirectPath, window.location.origin).href;
  return `/.auth/login/${provider}?post_login_redirect_uri=${encodeURIComponent(target)}`;
}

function MicrosoftIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 21 21" aria-hidden="true">
      <rect width="10" height="10" fill="#f25022" />
      <rect x="11" width="10" height="10" fill="#7fba00" />
      <rect y="11" width="10" height="10" fill="#00a4ef" />
      <rect x="11" y="11" width="10" height="10" fill="#ffb900" />
    </svg>
  );
}

function GoogleIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true">
      <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
      <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
      <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
      <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
    </svg>
  );
}

function KeyringIcon() {
  return (
    <svg viewBox="0 0 24 24" width="16" height="16">
      <circle cx="8" cy="9" r="3" fill="none" stroke="currentColor" strokeWidth="1.75" />
      <line x1="10.2" y1="11.2" x2="18" y2="19" stroke="currentColor" strokeWidth="1.75" />
      <line x1="15" y1="16" x2="17" y2="14" stroke="currentColor" strokeWidth="1.75" />
      <line x1="17" y1="18" x2="19" y2="16" stroke="currentColor" strokeWidth="1.75" />
    </svg>
  );
}

function PreferencesIcon() {
  return (
    <svg viewBox="0 0 24 24" width="16" height="16">
      <circle cx="12" cy="12" r="4" fill="none" stroke="currentColor" strokeWidth="1.75" />
      <line x1="12" y1="2" x2="12" y2="5" stroke="currentColor" strokeWidth="1.75" />
      <line x1="12" y1="19" x2="12" y2="22" stroke="currentColor" strokeWidth="1.75" />
      <line x1="2" y1="12" x2="5" y2="12" stroke="currentColor" strokeWidth="1.75" />
      <line x1="19" y1="12" x2="22" y2="12" stroke="currentColor" strokeWidth="1.75" />
    </svg>
  );
}

function StatsIcon() {
  return (
    <svg viewBox="0 0 24 24" width="16" height="16">
      <line x1="6" y1="19" x2="6" y2="12" stroke="currentColor" strokeWidth="1.75" />
      <line x1="12" y1="19" x2="12" y2="6" stroke="currentColor" strokeWidth="1.75" />
      <line x1="18" y1="19" x2="18" y2="15" stroke="currentColor" strokeWidth="1.75" />
    </svg>
  );
}

function SignOutIcon() {
  return (
    <svg viewBox="0 0 24 24" width="16" height="16">
      <path d="M9 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h3" fill="none" stroke="currentColor" strokeWidth="1.75" />
      <line x1="20" y1="12" x2="10" y2="12" stroke="currentColor" strokeWidth="1.75" />
      <polyline points="16,8 20,12 16,16" fill="none" stroke="currentColor" strokeWidth="1.75" />
    </svg>
  );
}

/** Signed-in avatar button + account dropdown (Keyring/Preferences/Stats/Sign out). */
export function ProfileMenu({ redirectPath }: { redirectPath?: string }) {
  const [user, setUser] = useState<User | null | undefined>(undefined);
  const [providers, setProviders] = useState<string[]>([]);

  useEffect(() => {
    let cancelled = false;
    Promise.all([Auth.getUser(), Auth.getProviders()]).then(([u, p]) => {
      if (cancelled) return;
      setUser(u);
      setProviders(p);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  if (user === undefined) return <div className="auth-widget" />;

  const redirect = redirectPath || window.location.pathname + window.location.search;

  if (!user || !user.authenticated) {
    if (!providers.length) return <div className="auth-widget" />;
    return (
      <div className="auth-widget">
        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <button type="button" className="btn-sign-in">Sign in ▾</button>
          </DropdownMenu.Trigger>
          <DropdownMenu.Portal>
            <DropdownMenu.Content className="sign-in-menu" align="end" sideOffset={8}>
              {providers.includes("microsoft") && (
                <DropdownMenu.Item asChild>
                  <a href={loginHref("aad", redirect)}><MicrosoftIcon /> Sign in with Microsoft</a>
                </DropdownMenu.Item>
              )}
              {providers.includes("google") && (
                <DropdownMenu.Item asChild>
                  <a href={loginHref("google", redirect)}><GoogleIcon /> Sign in with Google</a>
                </DropdownMenu.Item>
              )}
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
      </div>
    );
  }

  const initials = initialsFor(user.email);
  const home = encodeURIComponent(`${window.location.origin}/`);

  return (
    <div className="auth-widget">
      <DropdownMenu.Root>
        <DropdownMenu.Trigger asChild>
          <button type="button" className="profile-trigger" aria-label="Account menu">
            <span className="profile-avatar">{initials}</span>
            <span className="profile-chevron">▾</span>
          </button>
        </DropdownMenu.Trigger>
        <DropdownMenu.Portal>
          <DropdownMenu.Content className="profile-dropdown" align="end" sideOffset={8}>
            <div className="profile-dropdown-header">
              <span className="profile-avatar profile-avatar-lg">{initials}</span>
              <span className="profile-dropdown-email" title={user.email}>{user.email}</span>
            </div>
            <div className="profile-dropdown-items">
              <DropdownMenu.Item asChild>
                <a className="profile-dropdown-item" href="/my-keys"><KeyringIcon />Keyring</a>
              </DropdownMenu.Item>
              <DropdownMenu.Item asChild>
                <a className="profile-dropdown-item" href="/preferences"><PreferencesIcon />Preferences</a>
              </DropdownMenu.Item>
              <DropdownMenu.Item asChild>
                <a className="profile-dropdown-item" href="/stats"><StatsIcon />Stats</a>
              </DropdownMenu.Item>
            </div>
            <DropdownMenu.Separator className="profile-dropdown-divider" />
            <div className="profile-dropdown-items">
              <DropdownMenu.Item asChild>
                <a
                  className="profile-dropdown-item profile-dropdown-signout"
                  href={`/.auth/logout?post_logout_redirect_uri=${home}`}
                >
                  <SignOutIcon />Sign out
                </a>
              </DropdownMenu.Item>
            </div>
          </DropdownMenu.Content>
        </DropdownMenu.Portal>
      </DropdownMenu.Root>
    </div>
  );
}
