import { useEffect, useRef, useState } from "react";

/** Copies a URL without showing it as a link. The label changes to
 * "Copied", with a tick, to confirm it worked. */
export default function CopyButton({ value }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef(null);

  useEffect(() => () => clearTimeout(timer.current), []);

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1600);
    } catch {
      // The Clipboard API doesn't work on plain http. Fail quietly; the URL
      // is on screen and can be selected by hand.
    }
  };

  return (
    <button
      type="button"
      onClick={onCopy}
      className={`press mt-2 inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-micro font-medium ${
        copied ? "bg-risk-safe/[0.12] text-risk-safe" : "bg-paper/[0.06] text-muted hover:text-paper"
      }`}
    >
      <svg
        viewBox="0 0 16 16"
        className="h-3 w-3"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        {copied ? (
          <path d="m3.5 8.5 3 3 6-7" />
        ) : (
          <>
            <rect x="5.5" y="5.5" width="8" height="8" rx="1.8" />
            <path d="M10.5 3.5v-.2A1.3 1.3 0 0 0 9.2 2H3.3A1.3 1.3 0 0 0 2 3.3v5.9a1.3 1.3 0 0 0 1.3 1.3h.2" />
          </>
        )}
      </svg>
      {copied ? "Copied" : "Copy address"}
    </button>
  );
}
