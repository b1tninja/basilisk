import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
  SheetFooter,
  SheetClose,
  Button,
  Input,
  Separator,
} from "basilisk-portal";

/*
 * The overlay primitive every shared-notebook flow is built on — inviting a
 * peer, inspecting one, reviewing what a cell is about to do.
 *
 * Each cell renders `open` with no `onOpenChange`, which pins the sheet in the
 * shot. A closed sheet photographs as an empty frame, and a preview of a
 * dialog that shows no dialog teaches the design tool nothing.
 *
 * The content below is real: these are the panels the session actually needs,
 * not lorem. A dialog primitive shown with placeholder text gets composed with
 * placeholder text, so the examples carry the copy and the control order the
 * flows really use.
 */

const body = { display: "flex", flexDirection: "column" as const, gap: 12, padding: "4px 0" };
const row = { display: "grid", gap: 5 };
const fieldLabel = {
  fontSize: 11,
  fontWeight: 600,
  color: "var(--muted-foreground)",
};
const mono = {
  fontFamily: "var(--font-mono, ui-monospace, monospace)",
  fontSize: 11,
  color: "var(--foreground)",
  wordBreak: "break-all" as const,
};

/**
 * The invite panel — the share moment, as a sheet.
 *
 * The link and the room code are both present because they are checked over
 * different channels: the link is pasted, the code is read aloud to confirm
 * the person who joined is the person you meant. Only showing the link removes
 * the out-of-band comparison entirely.
 */
export const InvitePeer = () => (
  <Sheet open>
    <SheetContent side="right" onOpenAutoFocus={(e) => e.preventDefault()}>
      <SheetHeader>
        <SheetTitle>Invite a peer</SheetTitle>
        <SheetDescription>
          The invite carries this session's public key in its fragment, so it
          never reaches a server. Anyone holding the link can ask to join; you
          still approve them.
        </SheetDescription>
      </SheetHeader>
      <div style={body}>
        <div style={row}>
          <span style={fieldLabel}>Invite link</span>
          <Input
            readOnly
            value="https://basilisk.pages.dev/toolkit#s=KJ8X4M2Q7T9FQ&k=mDMEZHhhDBYJKwYB"
          />
        </div>
        <Separator />
        <div style={row}>
          <span style={fieldLabel}>Room code — read this aloud to confirm</span>
          <span style={{ ...mono, fontSize: 15, letterSpacing: "0.12em" }}>KJ8X…9FQ</span>
        </div>
      </div>
      <SheetFooter>
        <SheetClose asChild>
          <Button variant="ghost">Close</Button>
        </SheetClose>
        <Button>Copy invite</Button>
      </SheetFooter>
    </SheetContent>
  </Sheet>
);

/**
 * A peer, opened from the roster. The fingerprint is shown in full and
 * grouped — this is the string a person compares character by character
 * against what the other side reads out, and truncating it would defeat the
 * only check that establishes who is actually on the far end.
 *
 * Remove is a destructive control and sits apart from Close for that reason.
 */
export const PeerDetail = () => (
  <Sheet open>
    <SheetContent side="right" onOpenAutoFocus={(e) => e.preventDefault()}>
      <SheetHeader>
        <SheetTitle>@ada</SheetTitle>
        <SheetDescription>
          Verified against a published key. This peer can be assigned cells.
        </SheetDescription>
      </SheetHeader>
      <div style={body}>
        <div style={row}>
          <span style={fieldLabel}>Fingerprint</span>
          <span style={mono}>D772 078C 5C7C 2A0E DCA0 9ED3 2C5E BBB4 6AD0 1388</span>
        </div>
        <div style={row}>
          <span style={fieldLabel}>Transport</span>
          <span style={mono}>host · DTLS · authenticated</span>
        </div>
        <div style={row}>
          <span style={fieldLabel}>Joined</span>
          <span style={mono}>2023-06-01 09:14</span>
        </div>
      </div>
      <SheetFooter>
        <SheetClose asChild>
          <Button variant="ghost">Close</Button>
        </SheetClose>
        <Button variant="destructive">Remove from session</Button>
      </SheetFooter>
    </SheetContent>
  </Sheet>
);

/**
 * Anchored left instead of right. The side is a real prop and worth showing,
 * because a panel that pushes in from the same edge as the roster it was
 * opened from reads as replacing it rather than describing it.
 */
export const LeftSide = () => (
  <Sheet open>
    <SheetContent side="left" onOpenAutoFocus={(e) => e.preventDefault()}>
      <SheetHeader>
        <SheetTitle>Session</SheetTitle>
        <SheetDescription>Room KJ8X…9FQ · 3 of 3 connected</SheetDescription>
      </SheetHeader>
      <div style={body}>
        <span style={mono}>@ada · verified</span>
        <span style={mono}>@grace · verified</span>
        <span style={mono}>@lin · verified</span>
      </div>
    </SheetContent>
  </Sheet>
);
