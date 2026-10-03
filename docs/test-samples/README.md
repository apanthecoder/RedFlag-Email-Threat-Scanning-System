# Test samples

Nineteen fixtures covering every threat signal RedFlag's engine can raise.
All of them are generated, never hand-edited, so they can be rebuilt at any
time:

```bash
cd backend
python -m scripts.generate_test_samples
```

Each sample is named after the signal it is meant to raise. Weights come
from `backend/config.py` (`RISK_WEIGHTS`), and the bands are
Safe 0–24, Suspicious 25–59, Dangerous 60–100.

## Offline samples

These score identically with or without internet access: every signal comes
from the parser alone. Verified against the real parser on 2026-09-23.

| File | Signal(s) raised | Points | Expected verdict |
|---|---|---|---|
| `01_clean_no_links.eml` | none — SPF/DKIM/DMARC all pass, no links, no attachments | 0 | **Safe** |
| `02_clean_with_link.eml` | none — one ordinary link whose text matches its destination. The only sample whose link urlscan.io will actually visit, so use it to demonstrate the live sandbox check | 0 | **Safe** |
| `03_no_auth_headers.eml` | `ALL_AUTH_ABSENT` | 10 | **Safe** |
| `04_auth_fail_all.eml` | `SPF_FAIL`, `DKIM_FAIL`, `DMARC_FAIL` | 65 | **Dangerous** |
| `05_reply_to_mismatch.eml` | `REPLY_TO_MISMATCH` | 20 | **Safe** |
| `06_display_name_spoof.eml` | `DISPLAY_NAME_SPOOF` | 25 | **Suspicious** |
| `07_link_display_mismatch.eml` | `DISPLAY_MISMATCH` | 25 | **Suspicious** |
| `08_link_shortener.eml` | `SHORTENER` | 10 | **Safe** |
| `09_link_raw_ip.eml` | `RAW_IP_HOST` | 20 | **Safe** |
| `10_link_punycode.eml` | `PUNYCODE` | 25 | **Suspicious** |
| `11_attachment_extension_mismatch.eml` | `EXTENSION_MISMATCH` | 35 | **Suspicious** |
| `12_attachment_executable.eml` | `EXECUTABLE_TYPE` + the `EXECUTABLE_ATTACHMENT` override | 30 | **Suspicious** |
| `13_attachment_password_zip.eml` | `PASSWORD_PROTECTED_ARCHIVE` (ZIP) | 20 | **Safe** |
| `14_attachment_password_7z.eml` | `PASSWORD_PROTECTED_ARCHIVE` (7z) | 20 | **Safe** |
| `15_multi_signal_phishing.eml` | `SPF_FAIL`, `DKIM_FAIL`, `DMARC_FAIL`, `REPLY_TO_MISMATCH`, `DISPLAY_NAME_SPOOF`, `DISPLAY_MISMATCH` | 100 (capped) | **Dangerous** |
| `18_malformed.eml` | not an email at all — must be rejected | — | **Failed to process** |
| `19_no_received_headers.eml` | `ALL_AUTH_ABSENT`; no public sender IP, so AbuseIPDB is skipped rather than failed | 10 | **Safe** |

Samples 05, 08, 09, 13 and 14 land in the Safe band on purpose: one
moderate signal is not evidence of an attack. The finding is still listed
on the report, which is the behaviour to demonstrate.

`15_multi_signal_phishing.eml` is the best sample for a screenshot of a
full report: it reaches Dangerous with six findings and needs no provider.

## Samples that need a live provider

| File | Signal(s) | Needs | Expected verdict |
|---|---|---|---|
| `16_eicar_malware.eml.b64` | `VT_MALICIOUS_HIGH` + the `VT_MALICIOUS_THRESHOLD` override, plus `EXECUTABLE_TYPE` and three auth failures | VirusTotal | **Dangerous**, score 100 |
| `17_safe_browsing_phishing.eml` | `SAFE_BROWSING_MALWARE_SOCIAL` + its override | Google Safe Browsing | **Dangerous** *if Google still lists its own test page — verify on the day* |

Offline, sample 16 still scores 100 (Dangerous) from its header signals
alone, and sample 17 scores 0 and lands on Suspicious, because two of the
four checks could not run.

## A note on URLScan and the other samples

urlscan.io answers 400 and refuses to scan two kinds of address: domains on
its blocklist (Google's among them) and domains that do not resolve. Every
other sample here uses a `.example` address, which is reserved and never
resolves, so URLScan reports UNAVAILABLE on them and the scan is marked
partial. Confirmed on 2026-09-27: `example.com` submitted successfully
while `drive.google.com` and `invoice-settlement.example` were both
refused.

That affects the fixtures only. A real phishing link sits on a real
registered domain, which urlscan visits normally.

## Signals no fixture can produce

Stated plainly so the report does not claim more coverage than exists:

| Signal | Why there is no sample |
|---|---|
| `MACRO_ENABLED_DOCUMENT` | Needs a genuine OLE2 `vbaProject.bin` stream inside a `.docm`, which cannot be constructed without Office. Covered instead by mocking oletools in `backend/tests/test_attachment_detection.py`. |
| `VT_MALICIOUS_LOW`, `VT_SUSPICIOUS_ONLY` | Depend on how many VirusTotal engines flag a file. Only EICAR gives a stable answer, and that is the "high" tier. |
| `URLSCAN_MALICIOUS`, `URLSCAN_HIGH_SCORE_UNFLAGGED` | Depend on URLScan.io's live sandbox verdict, which cannot be fixed in advance. |
| `ABUSEIPDB_75_100`, `ABUSEIPDB_40_74`, `ABUSEIPDB_15_39` | Depend on an IP's live abuse score, which changes daily. The fixtures use 93.184.216.34, a real routable address with a clean record. |
| `SAFE_BROWSING_UNWANTED_HARMFUL` | Google rarely returns the unwanted-software categories for test URLs. |

All of these are covered by unit tests with mocked provider responses
(`backend/tests/test_api_clients.py`, `test_risk_scoring.py`,
`test_attachment_detection.py`).

## Why sample 16 is base64-wrapped

A plain `.eml` containing EICAR **cannot survive on disk** on a machine
running real-time antivirus. Windows Defender detects the signature inside
the MIME part the instant the file is written, deletes the attachment and
replaces it with a notice such as:

```
Original attachment (eicar_test.com) was Deleted. A virus was detected...
```

Sample 16 is therefore stored with one extra layer of base64 around the
whole message, which makes it opaque to that scan and lets the fixture
survive in the repository intact. This mirrors how eicar.org itself
distributes the file, as `eicar_com.zip` and `eicarcom2.zip` rather than
only as a bare `eicar.com`.

EICAR is the industry-standard antivirus test string. It is inert, it is
not malware, and it exists so that detection pipelines like this one can be
validated without handling anything dangerous.

## Using sample 16

```bash
cd backend

# verify the fixture is intact (nothing written)
python -m scripts.materialise_eicar

# send it straight to a running RedFlag over HTTP, never touching disk
python -m scripts.materialise_eicar --scan

# write the real .eml out (expect antivirus to eat it; the script says so)
python -m scripts.materialise_eicar --write
```

`--scan` is the one to use for a demonstration. RedFlag holds uploads in
memory and never writes them to disk, so the message reaches the parser
intact even with antivirus running.

Verified result with all four providers configured:

```
risk_level      : DANGEROUS      risk_score: 100
override_applied: VT_MALICIOUS_THRESHOLD
attachment      : invoice.pdf.exe | MALICIOUS 58/61 | virus.eicar/test
```

Together with sample 01 scoring Safe, this satisfies the calibration
requirement that clean samples land Safe and the EICAR sample lands
Dangerous.
