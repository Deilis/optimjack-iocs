#!/usr/bin/env python3
"""Check Optimizely Web snippets for the 16 November 2026 loader without running them.

For each URL or saved file it prints the SHA-256, the Last-Modified header and every sign of the injected
loader: the payload host in plain text, the same host hidden in a base64 literal, the payload's own markers.
The snippet is only downloaded, hashed and searched as bytes. Nothing is evaluated.

    python check_snippet.py https://cdn.optimizely.com/js/<project id>.js
    python check_snippet.py saved-snippet.js

A Last-Modified time between 2026-11-16 03:55 and 21:52 UTC means the project was written during the
incident window: by the attacker, by the clean-up, or by your own team. Review its change history either way.
"""
import base64
import gzip
import hashlib
import re
import sys
import urllib.request
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

# The payload host is assembled here so that this file does not match its own search.
HOST = b"1688360" + b".cc"
# The payload's own guard flags are matched with their leading dot (w._k7, W._k7, w.__k7b) so that an
# unrelated minified identifier containing "_k7" does not count.
MARKERS = [HOST, b"webshell" + b".lol", b"._k7", b".__k7b", b"px.gif?e=", b"data-channel-code"]
WINDOW = (datetime(2026, 11, 16, 3, 55, tzinfo=timezone.utc), datetime(2026, 11, 16, 21, 52, tzinfo=timezone.utc))


def load(target):
    if not target.startswith(("http://", "https://")):
        return open(target, "rb").read(), None
    request = urllib.request.Request(target, headers={"User-Agent": "snippet-check/1.0", "Accept-Encoding": "gzip"})
    with urllib.request.urlopen(request, timeout=40) as response:
        body = response.read()
        modified = response.headers.get("Last-Modified")
    return (gzip.decompress(body) if body[:2] == b"\x1f\x8b" else body), modified


def hidden(body):
    """Decode base64 literals handed to atob(), forwards and reversed, and return the ones that name an indicator."""
    found = []
    for match in re.finditer(rb"""atob\(\s*['"]([A-Za-z0-9+/=]{16,})['"]""", body):
        for candidate in (match.group(1), match.group(1)[::-1]):
            try:
                decoded = base64.b64decode(candidate + b"=" * (-len(candidate) % 4))
            except ValueError:
                continue
            if any(marker in decoded for marker in MARKERS):
                found.append(decoded[:120].decode("latin-1"))
    return found


def main(targets):
    worst = 0
    for target in targets:
        body, modified = load(target)
        plain = [marker.decode() for marker in MARKERS if marker in body]
        encoded = hidden(body)
        in_window = False
        if modified:
            when = parsedate_to_datetime(modified)
            in_window = WINDOW[0] <= when <= WINDOW[1]
        verdict = "LOADER FOUND" if plain or encoded else "written during the incident window, review" if in_window else "no loader found"
        worst = max(worst, 2 if plain or encoded else 1 if in_window else 0)
        print(target)
        print("  sha256        ", hashlib.sha256(body).hexdigest())
        print("  bytes         ", len(body))
        print("  last-modified ", modified or "n/a (local file)")
        print("  plain markers ", ", ".join(plain) or "none")
        print("  base64 markers", "; ".join(encoded) or "none")
        print("  verdict       ", verdict)
    return worst


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1:]))
