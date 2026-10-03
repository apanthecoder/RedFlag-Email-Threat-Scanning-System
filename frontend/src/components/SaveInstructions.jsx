import { useLayoutEffect, useRef, useState } from "react";

/** How to save an email as a .eml file, per email client.
 *
 * It sits right above the drop zone, so it's kept to one small card: the
 * heading and the client tabs share a row, and the four steps are in two
 * columns, read down the first column and then the second.
 *
 * People use one client, so the clients are tabs, not side-by-side lists.
 * They look like a segmented control: the selected tab sits on a raised
 * thumb that slides across to whichever tab you pick.
 *
 * The Outlook steps are the ones Microsoft documents for .eml. Classic
 * Outlook's File > Save As gives Outlook Message Format, which is a .msg
 * file and gets rejected on upload, so those steps aren't used here.
 *
 * Yahoo Mail can't download a message directly. "View raw message" opens
 * the full source in a new tab, and saving that page with a name ending in
 * .eml gives a file the parser accepts.
 */
const CLIENTS = [
  {
    id: "outlook",
    label: "Outlook",
    steps: [
      { text: "Select the message in your inbox, or open it." },
      { text: "Choose", chip: "More actions", after: "or right-click the message." },
      { text: "Select", chip: "Save as" },
      { text: "Pick a folder and save. The file is saved as .eml." },
    ],
  },
  {
    id: "gmail",
    label: "Gmail",
    steps: [
      { text: "Open the email." },
      { text: "Click the three dots at the top right of the message." },
      { text: "Choose", chip: "Show original" },
      { text: "Click", chip: "Download Original" },
    ],
  },
  {
    id: "yahoo",
    label: "Yahoo",
    steps: [
      { text: "Open the email." },
      { text: "Click the three dots", chip: "More", after: "in the toolbar." },
      { text: "Choose", chip: "View raw message" },
      { text: "Press Ctrl+S and save it with a name ending in .eml." },
    ],
  },
];

export default function SaveInstructions({ className = "", style }) {
  const [active, setActive] = useState("outlook");
  const client = CLIENTS.find((c) => c.id === active) || CLIENTS[0];
  const tabRefs = useRef({});
  const [thumb, setThumb] = useState(null);

  // Measure the selected tab so the thumb can slide to it. Measured again
  // when the layout changes size, since the tabs can wrap onto a new row.
  useLayoutEffect(() => {
    const measure = () => {
      const tab = tabRefs.current[active];
      if (tab) setThumb({ left: tab.offsetLeft, width: tab.offsetWidth });
    };
    measure();
    const observer = new ResizeObserver(measure);
    const track = tabRefs.current[active]?.parentElement;
    if (track) observer.observe(track);
    return () => observer.disconnect();
  }, [active]);

  return (
    <section
      aria-labelledby="save-heading"
      style={style}
      className={`surface px-5 py-4 ${className}`}
    >
      <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-3">
        <div>
          <h2 id="save-heading" className="text-small font-semibold text-paper">
            Saving an email as a file
          </h2>
          <p className="mt-0.5 text-micro text-muted">
            RedFlag reads a saved message file. Here is how to get one out of your email.
          </p>
        </div>

        <div role="tablist" aria-label="Email client" className="segment-track">
          {thumb && (
            <span
              aria-hidden="true"
              className="segment-thumb left-0 transition-[transform,width] duration-500 ease-spring"
              style={{ width: thumb.width, transform: `translateX(${thumb.left}px)` }}
            />
          )}
          {CLIENTS.map((c) => {
            const selected = c.id === active;
            return (
              <button
                key={c.id}
                ref={(el) => {
                  tabRefs.current[c.id] = el;
                }}
                type="button"
                role="tab"
                id={`tab-${c.id}`}
                aria-selected={selected}
                aria-controls={`panel-${c.id}`}
                onClick={() => setActive(c.id)}
                className={`relative z-10 rounded-lg px-3.5 py-1 text-micro transition-colors ${
                  selected ? "font-semibold text-paper" : "font-medium text-muted hover:text-paper"
                }`}
              >
                {c.label}
              </button>
            );
          })}
        </div>
      </div>

      <div
        role="tabpanel"
        id={`panel-${client.id}`}
        aria-labelledby={`tab-${client.id}`}
        className="mt-4 border-t border-ink-edge/70 pt-4"
      >
        {/* Keyed on the client so the steps animate in again when the
            tab changes, which makes the switch easier to notice. */}
        <ol
          key={client.id}
          className="grid gap-x-8 gap-y-2.5 sm:grid-flow-col sm:grid-cols-2 sm:grid-rows-2"
        >
          {client.steps.map((step, index) => (
            <li
              key={step.text + index}
              className="motion-safe:animate-surface flex items-start gap-3 text-small"
              style={{ animationDelay: `${index * 60}ms` }}
            >
              <span className="tabular flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-paper/[0.07] text-micro font-semibold text-muted">
                {index + 1}
              </span>
              <span className="pt-px text-muted">
                {step.text}
                {step.chip && (
                  <>
                    {" "}
                    <span className="whitespace-nowrap rounded-md bg-paper/[0.08] px-1.5 py-px text-micro font-medium text-paper">
                      {step.chip}
                    </span>
                  </>
                )}
                {step.after && ` ${step.after}`}
              </span>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
