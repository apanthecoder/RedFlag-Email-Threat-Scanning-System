/** A red flag on a pole. Red is otherwise only used for the DANGEROUS
 * verdict, and that's on purpose: a red flag means danger, which is the
 * whole idea of the product.
 *
 * Hovering the link around it (which has the `group` class) makes the
 * flag wave once. */
export default function Logo({ className = "" }) {
  return (
    <span className={`flex items-center gap-2 ${className}`}>
      <svg viewBox="0 0 20 22" className="h-5 w-[18px] shrink-0" aria-hidden="true">
        <path d="M3 1v20" className="stroke-muted" strokeWidth="1.8" strokeLinecap="round" />
        <path
          d="M3 2.5h13l-2.6 4.2L16 11H3z"
          className="fill-risk-danger motion-safe:group-hover:animate-wave"
          style={{ transformBox: "fill-box", transformOrigin: "left center" }}
        />
      </svg>
      <span className="text-lead font-semibold tracking-tight text-paper">RedFlag</span>
    </span>
  );
}
