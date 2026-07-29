import { cn } from "@/lib/cn";

type Size = "sm" | "md" | "lg";
const SIZES: Record<Size, number> = { sm: 16, md: 28, lg: 48 };

type Variant = "light" | "dark";
type ColorScheme = "shield" | "keyring" | "monochrome";

interface Props {
  size?: Size;
  variant?: Variant;
  colorScheme?: ColorScheme;
  className?: string;
}

/**
 * Basilisk diadem shield mark — "king of serpents" guards the keyring.
 * Shield (protection) + keyhole + diadem (crown).
 * Legible at 16px favicon size.
 */
export function BasiliskMark({
  size = "md",
  variant = "light",
  colorScheme = "shield",
  className,
}: Props) {
  const px = SIZES[size];

  let shieldFill = "#2e7d4f"; // forest green (light)
  let diademFill = "#c9a227"; // gold (light)
  let keyholeStroke = "#fff";

  if (variant === "dark") {
    shieldFill = "#4cde82"; // bright green (dark)
    diademFill = "#d4b84a"; // gold (dark)
    keyholeStroke = "#0d1117"; // background
  }

  if (colorScheme === "monochrome") {
    diademFill = shieldFill;
  }

  return (
    <svg
      width={px}
      height={px}
      viewBox="0 0 24 24"
      fill="none"
      className={cn("flex-shrink-0", className)}
      aria-hidden="true"
      focusable="false"
    >
      {/* Shield */}
      <polygon points="12,2 20,6 20,14 12,22 4,14 4,6" fill={shieldFill} />

      {/* Diadem: 3 crown points */}
      <circle cx="9" cy="4.3" r="0.9" fill={diademFill} />
      <circle cx="12" cy="3.4" r="0.9" fill={diademFill} />
      <circle cx="15" cy="4.3" r="0.9" fill={diademFill} />

      {/* Keyhole: outer circle + shaft */}
      <circle cx="12" cy="11" r="2.6" fill={keyholeStroke} />
      <rect x="10.8" y="13" width="2.4" height="5.5" rx="1" fill={keyholeStroke} />

      {/* Keyhole accent (gem) */}
      <circle cx="12" cy="11" r="1" fill={diademFill} />
    </svg>
  );
}
