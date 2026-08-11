import {
  TooltipProvider,
  Tooltip,
  TooltipTrigger,
  TooltipContent,
  Button,
  Badge,
} from "basilisk-portal";

/*
 * Tooltips carry the explanation a dense session surface has no room to state
 * inline — what `srflx` means, why a peer is unverified, what a relay changes.
 *
 * Pinned `open` so the tip is in the shot. `TooltipProvider` must wrap any
 * tooltip; without it the primitive renders nothing at all, which is the most
 * common way this component is misused and the reason every cell here shows
 * the provider rather than assuming an app-level one.
 *
 * The rule these examples encode: a tooltip explains a term, it never carries
 * a fact you cannot get otherwise. Anything a decision depends on belongs on
 * the surface — a fingerprint hidden behind a hover is a fingerprint nobody
 * compares.
 */

const frame = { padding: "70px 0 24px", display: "flex", gap: 28, alignItems: "center" };

/**
 * Explaining a transport abbreviation. `srflx` is correct ICE vocabulary and
 * unreadable to most people; the row keeps the precise term and the tip
 * carries the translation.
 */
export const Default = () => (
  <div style={frame}>
    <TooltipProvider>
      <Tooltip open>
        <TooltipTrigger asChild>
          <Badge>srflx</Badge>
        </TooltipTrigger>
        <TooltipContent>
          Server-reflexive — your public address, discovered via STUN. The
          connection is still peer to peer.
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  </div>
);

/**
 * The tip on a control whose consequence is not obvious from its label.
 * Restart ICE keeps the room and the roster and renegotiates only the
 * transport — which is precisely what a person needs to know before pressing
 * something during a ceremony.
 */
export const OnAControl = () => (
  <div style={frame}>
    <TooltipProvider>
      <Tooltip open>
        <TooltipTrigger asChild>
          <Button variant="outline">Restart ICE</Button>
        </TooltipTrigger>
        <TooltipContent>
          Renegotiates the connection in place. The room code and everyone in
          it stay as they are.
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  </div>
);
