import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuGroup,
  Button,
} from "basilisk-portal";

/*
 * The menu behind every per-row action in the session: what to do with a peer,
 * where to send a cell, which template to start from.
 *
 * Each cell is pinned `open`, for the same reason the Sheet previews are — a
 * closed menu photographs as a button, and the point of the card is the menu.
 * `modal={false}` keeps the open menu from taking a scroll lock the preview
 * frame never releases.
 *
 * The items are the real ones. A menu primitive demonstrated with "Item 1 /
 * Item 2" gets composed with "Item 1 / Item 2", so these carry the verbs the
 * session actually offers and the order it offers them in.
 */

const frame = { padding: "0 0 190px" };

/**
 * Peer actions, as opened from a roster row.
 *
 * Assign a cell sits at the top because it is the one constructive thing you
 * do to a peer; the destructive item is separated and last. Between them is
 * the identity check — pulled out as its own item rather than buried, since
 * comparing a fingerprint is the action that makes every other one meaningful.
 */
export const PeerActions = () => (
  <div style={frame}>
    <DropdownMenu open modal={false}>
      <DropdownMenuTrigger asChild>
        <Button variant="outline">@ada</Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start">
        <DropdownMenuLabel>@ada · verified</DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuGroup>
          <DropdownMenuItem>Assign this cell…</DropdownMenuItem>
          <DropdownMenuItem>Compare fingerprint</DropdownMenuItem>
          <DropdownMenuItem>Copy public key</DropdownMenuItem>
        </DropdownMenuGroup>
        <DropdownMenuSeparator />
        <DropdownMenuItem>Remove from session</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  </div>
);

/**
 * Where a cell runs. This is the menu that makes placement a choice a person
 * makes rather than something inferred silently.
 *
 * "Wherever the input lives" is first and is the default: placement is
 * normally derived from which peer holds the private input, and naming a peer
 * explicitly is the override, not the norm.
 */
export const AssignCell = () => (
  <div style={frame}>
    <DropdownMenu open modal={false}>
      <DropdownMenuTrigger asChild>
        <Button variant="outline">Runs on…</Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start">
        <DropdownMenuLabel>Run this cell on</DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem>Wherever the input lives</DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem>@ada</DropdownMenuItem>
        <DropdownMenuItem>@grace</DropdownMenuItem>
        <DropdownMenuItem>@lin</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  </div>
);
