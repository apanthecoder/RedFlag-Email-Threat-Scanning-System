import CopyButton from "./CopyButton.jsx";

/** Raw technical data, collapsed by default and kept low-key. Most
 * readers only need the advice.
 *
 * URLs are shown as plain text with a copy button, never as links, so
 * nobody can click a phishing link from inside the tool that flagged it.
 * Monospace is only used for machine data, not labels.
 */
export default function TechnicalDetails({ headerResult, urlResults, attachmentResults }) {
  return (
    <details className="group">
      <summary className="press inline-flex cursor-pointer list-none items-center gap-2 rounded-full bg-paper/[0.06] px-3.5 py-1.5 text-small font-medium text-muted hover:bg-paper/[0.1] hover:text-paper [&::-webkit-details-marker]:hidden">
        <svg
          viewBox="0 0 16 16"
          className="h-3 w-3 transition-transform duration-300 ease-spring group-open:rotate-90"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <path d="M6 3.5 10.5 8 6 12.5" />
        </svg>
        Technical detail
      </summary>

      <div className="surface motion-safe:animate-surface mt-3 space-y-6 p-5 text-small">
        <section>
          <h3 className="text-micro font-semibold uppercase tracking-[0.06em] text-faint">Sender</h3>
          <dl className="mt-2.5 grid grid-cols-[6rem,1fr] gap-x-6 gap-y-1.5">
            <Row label="From" value={headerResult?.from_address} mono />
            <Row label="Reply to" value={headerResult?.reply_to} mono />
            <Row label="Server IP" value={headerResult?.sender_ip} mono />
            <Row label="SPF" value={headerResult?.spf_result} />
            <Row label="DKIM" value={headerResult?.dkim_result} />
            <Row label="DMARC" value={headerResult?.dmarc_result} />
          </dl>
        </section>

        <section>
          <h3 className="text-micro font-semibold uppercase tracking-[0.06em] text-faint">
            Links ({urlResults.length})
          </h3>
          {urlResults.length === 0 ? (
            <p className="mt-2 text-faint">This email contains no links.</p>
          ) : (
            <ul className="mt-2.5 space-y-2">
              {urlResults.map((url) => (
                <li key={url.id} className="rounded-xl bg-paper/[0.04] px-4 py-3">
                  <p className="break-all font-mono text-micro text-paper">{url.url}</p>
                  <p className="mt-1 text-micro text-faint">
                    Safe Browsing {url.safe_browsing_status.toLowerCase()}, URLScan{" "}
                    {url.urlscan_verdict.toLowerCase()}
                  </p>
                  <CopyButton value={url.url} />
                </li>
              ))}
            </ul>
          )}
        </section>

        <section>
          <h3 className="text-micro font-semibold uppercase tracking-[0.06em] text-faint">
            Attachments ({attachmentResults.length})
          </h3>
          {attachmentResults.length === 0 ? (
            <p className="mt-2 text-faint">This email has no attachments.</p>
          ) : (
            <ul className="mt-2.5 space-y-2">
              {attachmentResults.map((attachment) => (
                <li key={attachment.id} className="rounded-xl bg-paper/[0.04] px-4 py-3">
                  <p className="break-all font-medium text-paper">{attachment.filename}</p>
                  <p className="mt-1 break-all font-mono text-micro text-faint">
                    {attachment.sha256}
                  </p>
                  <p className="mt-1 text-micro text-faint">
                    VirusTotal {attachment.vt_status.toLowerCase()}
                    {attachment.vt_total_engines
                      ? `, ${attachment.vt_malicious_count} of ${attachment.vt_total_engines} engines`
                      : ""}
                  </p>
                  {(attachment.is_password_protected || attachment.has_macros) && (
                    <p className="mt-1 text-micro font-medium text-risk-caution">
                      {[
                        attachment.is_password_protected && "Password-protected archive",
                        attachment.has_macros && "Contains macros",
                      ]
                        .filter(Boolean)
                        .join(", ")}
                    </p>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </details>
  );
}

function Row({ label, value, mono = false }) {
  return (
    <>
      <dt className="text-faint">{label}</dt>
      <dd className={`break-all text-paper/90 ${mono ? "font-mono text-micro leading-[1.35rem]" : ""}`}>
        {value || <span className="text-faint">Not available</span>}
      </dd>
    </>
  );
}
