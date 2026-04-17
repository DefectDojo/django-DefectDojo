import logging

import bleach
import markdown
import requests
from django.core.cache import cache

logger = logging.getLogger(__name__)

BUCKET_URL = "https://storage.googleapis.com/defectdojo-os-messages-dev/open_source_message.md"
CACHE_SECONDS = 3600
HTTP_TIMEOUT_SECONDS = 2
CACHE_KEY = "os_message:v1"

INLINE_TAGS = ["strong", "em", "a"]
INLINE_ATTRS = {"a": ["href", "title"]}

# Keep BLOCK_TAGS / BLOCK_ATTRS in sync with the DaaS publisher's
# MARKDOWNIFY["default"]["WHITELIST_TAGS"] / WHITELIST_ATTRS so previews
# on DaaS and rendering in OSS stay byte-identical.
BLOCK_TAGS = [
    "p", "ul", "ol", "li", "a", "strong", "em", "code", "pre",
    "blockquote", "h2", "h3", "h4", "hr", "br", "b", "i",
    "abbr", "acronym",
]
BLOCK_ATTRS = {
    "a": ["href", "title"],
    "abbr": ["title"],
    "acronym": ["title"],
}

_MISS = object()


def fetch_os_message():
    cached = cache.get(CACHE_KEY, default=_MISS)
    if cached is not _MISS:
        return cached

    try:
        response = requests.get(BUCKET_URL, timeout=HTTP_TIMEOUT_SECONDS)
    except Exception:
        logger.debug("os_message: fetch failed", exc_info=True)
        cache.set(CACHE_KEY, None, CACHE_SECONDS)
        return None

    if response.status_code != 200 or not response.text.strip():
        cache.set(CACHE_KEY, None, CACHE_SECONDS)
        return None

    cache.set(CACHE_KEY, response.text, CACHE_SECONDS)
    return response.text


def _strip_outer_p(html):
    stripped = html.strip()
    if stripped.startswith("<p>") and stripped.endswith("</p>"):
        return stripped[3:-4]
    return stripped


def parse_os_message(text):
    lines = text.splitlines()

    headline_source = None
    body_start = None
    for index, line in enumerate(lines):
        if line.startswith("# "):
            headline_source = line[2:].strip()
            body_start = index + 1
            break

    if not headline_source:
        return None

    headline_source = headline_source[:100]
    headline_rendered = markdown.markdown(headline_source)
    headline_cleaned = bleach.clean(
        headline_rendered,
        tags=INLINE_TAGS,
        attributes=INLINE_ATTRS,
        strip=True,
    )
    headline_html = _strip_outer_p(headline_cleaned)

    expanded_html = None
    expanded_marker = "## Expanded Message"
    expanded_body_lines = None
    for offset, line in enumerate(lines[body_start:], start=body_start):
        if line.strip() == expanded_marker:
            expanded_body_lines = lines[offset + 1:]
            break

    if expanded_body_lines is not None:
        expanded_source = "\n".join(expanded_body_lines).strip()
        if expanded_source:
            expanded_rendered = markdown.markdown(
                expanded_source,
                extensions=["extra", "fenced_code", "nl2br"],
            )
            expanded_html = bleach.clean(
                expanded_rendered,
                tags=BLOCK_TAGS,
                attributes=BLOCK_ATTRS,
                strip=True,
            )

    return {"message": headline_html, "expanded_html": expanded_html}


def get_os_banner():
    try:
        text = fetch_os_message()
        if not text:
            return None
        return parse_os_message(text)
    except Exception:
        logger.debug("os_message: get_os_banner failed", exc_info=True)
        return None
