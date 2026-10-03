import { useCallback, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../services/api";
import useDocumentTitle from "../hooks/useDocumentTitle";
import AwarenessSection from "../components/AwarenessSection.jsx";
import SaveInstructions from "../components/SaveInstructions.jsx";

const MAX_SIZE_BYTES = 10 * 1024 * 1024;

function validateFile(file) {
  if (!file.name.toLowerCase().endsWith(".eml")) {
    return "That file is not a .eml email. There are instructions above for saving one.";
  }
  if (file.size === 0) {
    return "That file is empty. Choose the saved email and try again.";
  }
  if (file.size > MAX_SIZE_BYTES) {
    return `That file is ${(file.size / (1024 * 1024)).toFixed(1)} MB. The limit is 10 MB.`;
  }
  return null;
}

export default function UploadPage() {
  useDocumentTitle("Scan an email");
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState(null);
  const [uploading, setUploading] = useState(false);
  const inputRef = useRef(null);
  const navigate = useNavigate();

  const submitFile = useCallback(
    async (file) => {
      const validationError = validateFile(file);
      if (validationError) {
        setError(validationError);
        return;
      }
      setError(null);
      setUploading(true);
      try {
        const formData = new FormData();
        formData.append("file", file);
        // Don't set Content-Type. The browser adds the multipart boundary
        // itself, and overriding the header breaks the upload.
        const data = await api.post("/scan", formData);
        navigate(`/scan/${data.scan_id}`);
      } catch (err) {
        setError(err.message || "The server did not respond. Check your connection and try again.");
        setUploading(false);
      }
    },
    [navigate]
  );

  const onDrop = (event) => {
    event.preventDefault();
    setDragActive(false);
    const file = event.dataTransfer.files?.[0];
    if (file) submitFile(file);
  };

  // Moves the drop zone's light with the pointer. It writes CSS variables
  // directly, so moving the mouse doesn't re-render the page.
  const onPointerMove = (event) => {
    const rect = event.currentTarget.getBoundingClientRect();
    event.currentTarget.style.setProperty("--x", `${event.clientX - rect.left}px`);
    event.currentTarget.style.setProperty("--y", `${event.clientY - rect.top}px`);
  };

  const onFileChange = (event) => {
    const file = event.target.files?.[0];
    if (file) submitFile(file);
    event.target.value = ""; // so the same file can be picked again after an error
  };

  return (
    <main className="relative isolate mx-auto max-w-4xl px-5 pb-32 pt-14 sm:px-6 sm:pt-20">
      <div
        aria-hidden="true"
        className="hero-glow pointer-events-none absolute inset-x-0 top-0 -z-10 h-[520px]"
      />

      {/* On load: heading, subheading, save instructions, then the drop
          zone, each slightly after the last. The instructions come before
          the drop zone because most people need to save a .eml first. */}
      <div className="mx-auto max-w-2xl text-center">
        <h1
          className="motion-safe:animate-surface text-display font-bold text-paper"
          style={{ animationDelay: "0ms" }}
        >
          Check an email before you trust it
        </h1>
        <p
          className="motion-safe:animate-surface mx-auto mt-5 max-w-prose text-lead text-muted"
          style={{ animationDelay: "90ms" }}
        >
          Upload the saved message. RedFlag examines the sender, every link and every
          attachment, then tells you plainly what it found and what to do next.
        </p>
      </div>

      <SaveInstructions
        className="motion-safe:animate-surface mt-12"
        style={{ animationDelay: "180ms" }}
      />

      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragActive(true);
        }}
        onDragLeave={() => setDragActive(false)}
        onDrop={onDrop}
        onPointerMove={onPointerMove}
        style={{ animationDelay: "270ms" }}
        className={`spotlight surface motion-safe:animate-surface relative mt-4 overflow-hidden !rounded-3xl transition-[background-color,box-shadow] duration-300 ease-spring ${
          dragActive
            ? "bg-ink-hover shadow-[0_0_0_2px_rgb(var(--paper)/0.5)]"
            : ""
        }`}
      >
        {/* The corner brackets move inward while a file is dragged over,
            like a camera viewfinder focusing. */}
        <Bracket corner="tl" active={dragActive} />
        <Bracket corner="tr" active={dragActive} />
        <Bracket corner="bl" active={dragActive} />
        <Bracket corner="br" active={dragActive} />

        {uploading && (
          <>
            <div className="absolute inset-x-0 top-0 h-0.5 overflow-hidden bg-ink-edge/60">
              <div className="motion-safe:animate-sweep h-0.5 w-1/2 rounded-full bg-paper" />
            </div>
            <div
              aria-hidden="true"
              className="motion-safe:animate-scanline pointer-events-none absolute inset-x-0 h-12 -translate-y-full bg-gradient-to-b from-transparent to-paper/10 motion-reduce:hidden"
            >
              <div className="absolute inset-x-0 bottom-0 h-px bg-paper/60" />
            </div>
          </>
        )}

        <div className="flex flex-col items-center px-6 py-16 text-center">
          <span
            className={`flex h-16 w-16 items-center justify-center rounded-2xl transition-[background-color,transform] duration-300 ease-spring ${
              dragActive || uploading ? "bg-paper/[0.12]" : "bg-paper/[0.06]"
            } ${dragActive ? "-translate-y-1" : ""}`}
          >
            <EnvelopeMark active={dragActive} uploading={uploading} />
          </span>
          <p className="mt-6 text-title font-semibold text-paper">
            {uploading ? "Sending the file" : dragActive ? "Release to begin" : "Drop a .eml file here"}
          </p>
          <p className="mt-1.5 text-muted">or select it from your computer</p>

          <label className="mt-8 inline-block">
            {/* The real input is visually hidden but still takes keyboard
                focus. `peer` lets the visible button show the focus ring. */}
            <input
              ref={inputRef}
              type="file"
              accept=".eml"
              className="peer sr-only"
              onChange={onFileChange}
              disabled={uploading}
              aria-label="Choose a .eml file to scan"
            />
            <span
              className={`btn-primary px-6 peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-paper/75 ${
                uploading ? "cursor-not-allowed !bg-paper/40" : "cursor-pointer"
              }`}
            >
              {uploading ? "Uploading" : "Choose file"}
            </span>
          </label>

          <p className="mt-8 text-micro text-faint">
            Up to 10 MB. The file is examined in memory and never stored.
          </p>
        </div>
      </div>

      {error && (
        <p role="alert" className="callout-danger motion-safe:animate-surface mt-4">
          <AlertIcon />
          <span>{error}</span>
        </p>
      )}

      <AwarenessSection />
    </main>
  );
}

function AlertIcon() {
  return (
    <svg
      viewBox="0 0 20 20"
      className="mt-0.5 h-4 w-4 shrink-0 text-risk-danger"
      fill="currentColor"
      aria-hidden="true"
    >
      <path d="M10 1.8a8.2 8.2 0 1 0 0 16.4 8.2 8.2 0 0 0 0-16.4Zm-.9 4.4a.9.9 0 0 1 1.8 0v4.6a.9.9 0 0 1-1.8 0V6.2ZM10 15a1.1 1.1 0 1 1 0-2.2 1.1 1.1 0 0 1 0 2.2Z" />
    </svg>
  );
}

const CORNERS = {
  tl: { place: "left-4 top-4 rounded-tl-lg border-l-2 border-t-2", inward: "translate-x-2 translate-y-2" },
  tr: { place: "right-4 top-4 rounded-tr-lg border-r-2 border-t-2", inward: "-translate-x-2 translate-y-2" },
  bl: { place: "bottom-4 left-4 rounded-bl-lg border-b-2 border-l-2", inward: "translate-x-2 -translate-y-2" },
  br: { place: "bottom-4 right-4 rounded-br-lg border-b-2 border-r-2", inward: "-translate-x-2 -translate-y-2" },
};

function Bracket({ corner, active }) {
  const { place, inward } = CORNERS[corner];
  return (
    <span
      aria-hidden="true"
      className={`pointer-events-none absolute transition-[transform,border-color,width,height] duration-500 ease-spring ${
        active ? `h-7 w-7 border-paper/80 ${inward}` : "h-5 w-5 border-ink-edge"
      } ${place}`}
    />
  );
}

/** Envelope icon. It lifts when a file is dragged over the drop zone, and
 * the flap opens while the file uploads. */
function EnvelopeMark({ active, uploading }) {
  const open = active || uploading;
  return (
    <svg
      viewBox="0 0 48 36"
      className={`h-7 w-9 text-muted transition-colors duration-300 ${
        active || uploading ? "text-paper" : ""
      }`}
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <rect x="2" y="8" width="44" height="26" rx="2.5" />
      <path
        d="M2.8 9.5 24 24l21.2-14.5"
        className="transition-transform duration-500 ease-spring"
        style={{
          transformBox: "view-box",
          transformOrigin: "24px 8px",
          transform: open ? "scaleY(-0.55)" : "none",
        }}
      />
    </svg>
  );
}
