"""
Before the docs link check, give links the live site resolves a placeholder.

    python3 scripts/docs_live_link_stubs.py <built site dir> [<file> ...]

docs.defectdojo.com is built from this repo's docs/ together with the DefectDojo
Pro pages, which live in a separate repository. A build of this repo alone
lacks those pages and images, so a link from an Open Source page to a Pro page,
or a Pro screenshot on a shared page, cannot resolve in it.

For every internal link the local build cannot resolve, this asks the live site.
When the live site has the page or image, it writes an empty placeholder at that
path, so the link check that follows passes the link. A link the live site lacks
as well gets no placeholder and the link check reports it, as before.

Extra files (the in-app help links under dojo/) are scanned for absolute
docs.defectdojo.com URLs the same way.
"""

import re
import sys
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urljoin, urlsplit
from urllib.request import Request, urlopen

SITE = "https://docs.defectdojo.com"
ABSOLUTE = re.compile(r"https://docs\.defectdojo\.com/[^\s\"'<>)\]]*")


class Links(HTMLParser):

    """The href and src values of a page's tags (never text inside a script)."""

    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []

    def handle_starttag(self, tag, attrs) -> None:
        self.urls.extend(value for name, value in attrs if name in {"href", "src"} and value)


def links(html: Path) -> list[str]:
    parser = Links()
    parser.feed(html.read_text(encoding="utf-8", errors="ignore"))
    return parser.urls


def site_path(url: str, page: str) -> str | None:
    """The site-root path a link points at, or None for external and non-page links."""
    if url.startswith(SITE):
        url = url[len(SITE) :] or "/"
    if "{" in url or "%7B" in url.upper() or url.startswith(("#", "mailto:", "javascript:", "data:")):
        return None
    parts = urlsplit(urljoin(page, url))
    if parts.scheme or parts.netloc or not parts.path:
        return None
    return unquote(parts.path)


def resolves(root: Path, path: str) -> bool:
    target = root / path.lstrip("/")
    return target.is_file() or (target / "index.html").is_file()


def live(path: str) -> bool:
    # Always the fixed https site, never a scheme taken from the page.
    request = Request(SITE + quote(path), method="HEAD", headers={"User-Agent": "defectdojo-docs-ci"})  # noqa: S310
    try:
        with urlopen(request, timeout=15) as response:  # noqa: S310
            return response.status == 200
    except HTTPError:
        return False
    except URLError as error:
        print(f"could not reach {SITE}: {error.reason}", file=sys.stderr)
        return False


def main() -> None:
    root = Path(sys.argv[1]).resolve()
    wanted: set[str] = set()
    for html in root.rglob("*.html"):
        folder = html.parent.relative_to(root).as_posix()
        page = "/" if folder == "." else f"/{folder}/"
        for url in links(html):
            path = site_path(url, page)
            if path:
                wanted.add(path)
    for extra in sys.argv[2:]:
        for url in ABSOLUTE.findall(Path(extra).read_text(encoding="utf-8", errors="ignore")):
            path = site_path(url, "/")
            if path:
                wanted.add(path)

    missing = sorted(path for path in wanted if not resolves(root, path))
    with ThreadPoolExecutor(max_workers=16) as pool:
        found = [path for path, ok in zip(missing, pool.map(live, missing), strict=True) if ok]
    for path in found:
        target = root / path.lstrip("/")
        if not Path(path).suffix:
            target /= "index.html"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("<!-- placeholder: published from the Pro docs repository -->\n", encoding="utf-8")
    print(
        f"{len(missing)} links do not resolve in this build; {len(found)} exist on {SITE} "
        f"(placeholders written), {len(missing) - len(found)} are left for the link check",
    )


if __name__ == "__main__":
    main()
