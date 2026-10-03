/** Helpers for displaying the signals in scan.signals. */

const SOURCE_PATTERNS = [
  [/^VT_/, "VirusTotal"],
  [/^SAFE_BROWSING/, "Google Safe Browsing"],
  [/^URLSCAN/, "URLScan.io"],
  [/^ABUSEIPDB/, "AbuseIPDB"],
];

export function sourceForSignal(signalName) {
  const match = SOURCE_PATTERNS.find(([pattern]) => pattern.test(signalName));
  return match ? match[1] : "RedFlag's own analysis";
}

// Plain-language titles for the backend's signal names (the keys of
// RISK_WEIGHTS in backend/config.py). Without these the UI showed things
// like "Spf Fail" and "Vt Malicious High".
const TITLES = {
  VT_MALICIOUS_HIGH: "Many antivirus engines flagged the attachment",
  VT_MALICIOUS_LOW: "Some antivirus engines flagged the attachment",
  VT_SUSPICIOUS_ONLY: "Antivirus engines found the attachment suspicious",
  EXTENSION_MISMATCH: "Attachment is not the file type it claims",
  EXECUTABLE_TYPE: "Attachment is a program file",
  PASSWORD_PROTECTED_ARCHIVE: "Password-protected archive",
  MACRO_ENABLED_DOCUMENT: "Document contains macros",
  SAFE_BROWSING_MALWARE_SOCIAL: "Google lists this link as dangerous",
  SAFE_BROWSING_UNWANTED_HARMFUL: "Google lists this link as unwanted software",
  URLSCAN_MALICIOUS: "Link behaved maliciously when tested",
  URLSCAN_HIGH_SCORE_UNFLAGGED: "Link got a high risk score when tested",
  DISPLAY_MISMATCH: "Link text doesn't match where it goes",
  SHORTENER: "Shortened link",
  RAW_IP_HOST: "Link goes to a bare IP address",
  PUNYCODE: "Link uses lookalike characters",
  ABUSEIPDB_75_100: "Sending server has many abuse reports",
  ABUSEIPDB_40_74: "Sending server has some abuse reports",
  ABUSEIPDB_15_39: "Sending server has a few abuse reports",
  SPF_FAIL: "Failed the SPF sender check",
  DKIM_FAIL: "Failed the DKIM signature check",
  DMARC_FAIL: "Failed the DMARC check",
  ALL_AUTH_ABSENT: "No sender authentication results",
  REPLY_TO_MISMATCH: "Replies go to a different domain",
  DISPLAY_NAME_SPOOF: "Sender name doesn't match the address",
};

export function titleForSignal(signalName) {
  if (TITLES[signalName]) return TITLES[signalName];
  return signalName
    .toLowerCase()
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

export function groupSignalsByCategory(signals) {
  return (signals || []).reduce((acc, signal) => {
    const key = signal.category;
    if (!acc[key]) acc[key] = [];
    acc[key].push(signal);
    return acc;
  }, {});
}
