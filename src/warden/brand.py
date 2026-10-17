"""WARDEN's mark, in every page's header (owner, 2026-10-16: "Ward Gem" - an emerald-cut five-sided shield with a
calm eye at its centre; bright, never dark).

`LOGO_SVG` is inline SVG drawn with fill attributes only (no style, no id, no script, no event handler, nothing
fetched), so it stays inside the pages' Content-Security-Policy. It sits beside the word WARDEN, so it is hidden from
screen readers rather than read out twice. An `xmlns` attribute is dropped here: inline SVG needs none, and the pages
hold no address.

`FAVICON_LINK` puts the same mark on the browser tab (owner, 2026-10-17). A browser loads a tab icon as an image, so
it is embedded as a `data:` address - nothing is fetched - and the pages allow images from `data:` alone
(`img-src data:`), which reaches no host.
"""

from __future__ import annotations

import base64
import re

# The approved icon (warden-icon.svg), its role and label swapped for a size and aria-hidden.
_RAW = """<svg class="logo" viewBox="0 0 64 64" width="30" height="30" aria-hidden="true" focusable="false">
<path d="M32 58.5 5.4 39.2 15.5 7.8h33l10.1 31.4z" fill="#12C483"/>
<path d="M15.5 7.8h33l-10 13.8h-13z" fill="#7DF2C4"/>
<path d="M48.5 7.8l10.1 31.4-16.1-5.3-4-12.3z" fill="#3DB9F5"/>
<path d="M58.6 39.2 32 58.5V41.5l10.5-7.6z" fill="#1A8FE3"/>
<path d="M32 58.5 5.4 39.2l16.1-5.3L32 41.5z" fill="#0A9A6A"/>
<path d="M5.4 39.2 15.5 7.8l10 13.8-4 12.3z" fill="#12C483"/>
<path d="M32 41.5 21.5 33.9l4-12.3h13l4 12.3z" fill="#E8FFF5"/>
<circle cx="32" cy="31" r="4" fill="#FF7E6B"/>
</svg>"""

LOGO_SVG = re.sub(r'\s+xmlns(?::\w+)?="[^"]*"', "", _RAW)

# A tab icon is a document of its own, so it carries the SVG namespace and drops the page-only attributes.
_TAB = re.sub(r'\s(?:class|width|height|aria-hidden|focusable)="[^"]*"', "", LOGO_SVG).replace(
    "<svg", '<svg xmlns="http://www.w3.org/2000/svg"', 1)
FAVICON_LINK = ('<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,'
                + base64.b64encode(_TAB.encode()).decode() + '">')
