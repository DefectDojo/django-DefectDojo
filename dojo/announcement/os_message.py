import base64
import binascii
import hashlib
import json
import logging
from urllib.parse import unquote, urlsplit

import bleach
import markdown
import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)

# Key under UserContactInfo.user_state_details holding the hash of the most
# recently dismissed open-source promo banner.
OS_MESSAGE_DISMISSED_KEY = "os_message_dismissed_hash"

# The signed copy of the banner. The publisher signs it with an Ed25519 key held in Cloud KMS; the
# plain open_source_message.md next to it is for older releases only and is never read here.
SIGNED_URL = "https://storage.googleapis.com/defectdojo-os-messages-prod/open_source_message.signed.json"
CACHE_SECONDS = 3600
HTTP_TIMEOUT_SECONDS = 2
# v2: the cached value is now a verified message, never an unverified object body.
CACHE_KEY = "os_message:v2"

# Raw Ed25519 public keys (base64) a banner may be signed with. More than one lets the publisher
# rotate keys without a gap. With none, no banner is shown.
PUBLIC_KEYS = (
    # DefectDojo banner-signing key, version 1.
    "PMxyX1pO0ig0xz2zO4gDkYI6Sk3mhRfYCs+BjeYy2WQ=",
)
# Domain-separates banner signatures from anything else the key could sign.
SIGNING_PREFIX = b"defectdojo-os-message-v1\n"
ENVELOPE_VERSION = 1

# A banner link must be https to one of these hosts or their subdomains, or to one of the GitHub
# organizations below. Any other link keeps its text and loses its href.
ALLOWED_LINK_DOMAINS = ("defectdojo.com", "defectdojo.org")
ALLOWED_GITHUB_ORGS = ("defectdojo", "defectdojo-inc")

INLINE_TAGS = ["strong", "em", "a"]

# Keep BLOCK_TAGS / BLOCK_ATTRS in sync with the DaaS publisher's
# MARKDOWNIFY["default"]["WHITELIST_TAGS"] / WHITELIST_ATTRS so previews
# on DaaS and rendering in OSS stay byte-identical.
BLOCK_TAGS = [
    "p", "ul", "ol", "li", "a", "strong", "em", "code", "pre",
    "blockquote", "h2", "h3", "h4", "hr", "br", "b", "i",
    "abbr", "acronym",
]


def is_allowed_link(url):
    """True when url is an https link to a company host (see ALLOWED_LINK_DOMAINS / ALLOWED_GITHUB_ORGS)."""
    # A backslash, whitespace or control character parses differently in browsers than in urlsplit
    # (https://evil.example\\@defectdojo.com goes to evil.example), so any of them is refused.
    if not url or any(ch == "\\" or ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in url):
        return False
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    if parts.scheme.lower() != "https" or parts.username is not None or parts.password is not None or port is not None:
        return False
    # Browsers resolve "." and ".." segments, percent-encoded or not, before they send the request, so
    # https://github.com/DefectDojo/../evil-org lands outside the allowed organization. A path that
    # decodes to such a segment, or hides a slash or backslash behind an escape, is refused.
    decoded_path = unquote(parts.path)
    if "\\" in decoded_path or "%2f" in parts.path.lower() or any(
        segment in {".", ".."} for segment in decoded_path.split("/")
    ):
        return False
    host = (parts.hostname or "").lower().rstrip(".")
    if any(host == domain or host.endswith("." + domain) for domain in ALLOWED_LINK_DOMAINS):
        return True
    if host == "github.com":
        org = parts.path.split("/")[1].lower() if parts.path.startswith("/") and len(parts.path) > 1 else ""
        return org in ALLOWED_GITHUB_ORGS
    return False


def _link_attr(tag, name, value):
    if name == "href":
        return is_allowed_link(value)
    return name == "title"


INLINE_ATTRS = {"a": _link_attr}
BLOCK_ATTRS = {
    "a": _link_attr,
    "abbr": ["title"],
    "acronym": ["title"],
}

_MISS = object()


def fetch_os_message():
    cached = cache.get(CACHE_KEY, default=_MISS)
    if cached is not _MISS:
        return cached

    try:
        response = requests.get(SIGNED_URL, timeout=HTTP_TIMEOUT_SECONDS)
    except Exception:
        logger.debug("os_message: fetch failed", exc_info=True)
        cache.set(CACHE_KEY, None, CACHE_SECONDS)
        return None

    # Pin UTF-8: the publisher always writes it, and a response without a charset
    # would otherwise be decoded as ISO-8859-1 (e.g. "→" -> "â").
    response.encoding = "utf-8"

    message = None
    if response.status_code == 200 and response.text.strip():
        message = verify_signed_message(response.text)
        if message is None:
            logger.warning("os_message: banner signature did not verify; not showing it")

    cache.set(CACHE_KEY, message, CACHE_SECONDS)
    return message


def verify_signed_message(body):
    """
    Return the banner markdown in body if one of PUBLIC_KEYS signed it, else None.

    Accepted risk: a signature carries no expiry, so whoever can write the bucket object can serve
    any banner DefectDojo ever signed, even after a takedown, until the key is rotated. That replays
    only DefectDojo's own past wording, with links still limited to is_allowed_link, so it cannot
    put a link of the writer's choice on an install, which is what the signature exists to stop.
    """
    try:
        envelope = json.loads(body)
    except ValueError:
        return None
    if not isinstance(envelope, dict) or envelope.get("version") != ENVELOPE_VERSION:
        return None
    message, signature = envelope.get("message"), envelope.get("signature")
    if not isinstance(message, str) or not message.strip() or not isinstance(signature, str):
        return None
    try:
        signature_bytes = base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError):
        return None
    signed_bytes = SIGNING_PREFIX + message.encode("utf-8")
    for public_key in PUBLIC_KEYS:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True)).verify(
                signature_bytes, signed_bytes,
            )
        except (InvalidSignature, binascii.Error, ValueError):
            continue
        return message
    return None


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


# (text, banner) for the last verified text parsed in this process. Every page render asks for the
# banner and the text changes at most once per CACHE_SECONDS, so the markdown and bleach pass runs
# once per new text instead of once per request.
_parsed_banner = None


def get_os_banner():
    global _parsed_banner  # noqa: PLW0603
    if not settings.OS_MESSAGE_ENABLED:
        return None
    try:
        text = fetch_os_message()
        if not text:
            return None
        parsed = _parsed_banner
        if parsed is None or parsed[0] != text:
            banner = parse_os_message(text)
            if banner:
                banner["dismiss_token"] = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
            parsed = _parsed_banner = (text, banner)
    except Exception:
        logger.debug("os_message: get_os_banner failed", exc_info=True)
        return None
    return dict(parsed[1]) if parsed[1] else None
