"""Decode the base64-wrapped EICAR test email into a usable form.

    python -m scripts.materialise_eicar              # verify only, nothing written
    python -m scripts.materialise_eicar --write      # write the real .eml to disk
    python -m scripts.materialise_eicar --scan       # POST it to a running RedFlag

The fixture is wrapped because a plain .eml carrying EICAR doesn't
survive on a machine with real-time antivirus. Windows Defender spots the
signature as soon as the file is written, deletes the attachment and puts
a notice in its place, so the fixture quietly becomes harmless.

EICAR is the standard antivirus test string. It isn't malware and does
nothing; it exists so that detection can be tested without handling
anything dangerous.

On a machine with antivirus, expect --write to fail. The script says so
and explains what happened. For a working demo use --scan, which sends
the email straight to the API over HTTP without writing a file.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import sys

SRC = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "docs", "test-samples", "16_eicar_malware.eml.b64",
)
OUT = SRC[: -len(".b64")]

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def decode() -> bytes:
    """Return the real .eml bytes from the wrapped fixture."""
    with open(SRC, "rb") as f:
        payload = b"".join(
            line.strip() for line in f if not line.lstrip().startswith(b"#")
        )
    return base64.b64decode(payload)


def attachment_sha256(raw: bytes) -> str | None:
    from email import policy
    from email.parser import BytesParser

    msg = BytesParser(policy=policy.default).parsebytes(raw)
    for part in msg.iter_attachments():
        return hashlib.sha256(part.get_payload(decode=True) or b"").hexdigest()
    return None


def _cleanup(path: str) -> None:
    """Remove a stub or locked leftover, without ever raising."""
    try:
        os.remove(path)
        print("  removed the leftover file")
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(f"  could not remove {path}: {exc.__class__.__name__}")
        print("  delete it manually once antivirus releases its lock, so it "
              "is not mistaken for a working fixture.")


def _write_and_report(raw: bytes) -> None:
    """Write the decoded email to disk and report what antivirus did to it.

    On a protected machine any of these outcomes can happen. Reading the
    file back is wrapped in try/except because Defender can also lock the
    file, so reopening it fails with PermissionError. That's the same
    problem that used to break RedFlag's upload cleanup.
    """
    try:
        with open(OUT, "wb") as f:
            f.write(raw)
    except OSError as exc:
        print(f"\ncould not write {OUT}: {exc}")
        print("Local antivirus blocked the write entirely. Use --scan instead.")
        return

    print(f"\nwrote {OUT}")
    try:
        after = attachment_sha256(open(OUT, "rb").read())
    except PermissionError:
        print("  ...but the file is now LOCKED by local antivirus and cannot "
              "be read back.")
        print("  This is the expected result on a machine with real-time "
              "protection, and is why RedFlag keeps uploads in memory.")
        print("  Use --scan for a working demonstration.")
        _cleanup(OUT)
        return
    except FileNotFoundError:
        print("  ...but local antivirus has already deleted it.")
        print("  Use --scan for a working demonstration.")
        return
    except OSError as exc:
        print(f"  ...but it could not be read back: {exc.__class__.__name__}")
        _cleanup(OUT)
        return

    if after == EICAR_SHA256:
        print("  survived intact: this machine is not scanning the folder.")
        print("  Remember this file is a real EICAR sample; it is inert, but "
              "antivirus elsewhere will quarantine it.")
    else:
        print("  ...but local antivirus has already altered it: the "
              "attachment is no longer EICAR.")
        print(f"  attachment sha256 is now {after}")
        print("  This file is NOT a usable fixture. Use --scan instead.")
        _cleanup(OUT)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write the decoded .eml to disk")
    parser.add_argument("--scan", action="store_true", help="POST it to a running RedFlag instance")
    parser.add_argument("--url", default="http://localhost:5000/api/scan")
    args = parser.parse_args()

    raw = decode()
    digest = attachment_sha256(raw)
    intact = digest == EICAR_SHA256
    print(f"decoded {len(raw)} bytes")
    print(f"attachment sha256 : {digest}")
    print(f"genuine EICAR     : {intact}")
    if not intact:
        print("The wrapped fixture is damaged; regenerate it with "
              "`python -m scripts.generate_test_samples`.", file=sys.stderr)
        sys.exit(1)

    if args.write:
        _write_and_report(raw)

    if args.scan:
        import requests

        resp = requests.post(
            args.url,
            files={"file": ("16_eicar_malware.eml", raw, "message/rfc822")},
            timeout=30,
        )
        print(f"\nPOST {args.url} -> {resp.status_code}")
        print(resp.json())


if __name__ == "__main__":
    main()
