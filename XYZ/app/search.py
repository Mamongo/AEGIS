"""Free, source-linked Wikipedia search through the guarded HTTP transport."""
from collections import OrderedDict
from copy import deepcopy
from http.client import HTTPException
from html import unescape
from html.parser import HTMLParser
import json
import threading
import time
from urllib.parse import unquote, urlencode

from app.controls import secrets
from app.controls.egress import EgressDenied, validate_destination
from app.tools.registry import WebSearch


WIKIPEDIA_API = "https://en.wikipedia.org/w/api.php"


class SearchUnavailable(RuntimeError):
    """The upstream could not provide a valid live result."""


class _PlainText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden = 0

    def handle_starttag(self, tag, _attrs):
        if tag in {"script", "style"}:
            self.hidden += 1
        elif tag in {"br", "p", "div", "li"} and not self.hidden:
            self.parts.append(" ")

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self.hidden:
            self.hidden -= 1
        elif tag in {"p", "div", "li"} and not self.hidden:
            self.parts.append(" ")

    def handle_data(self, value):
        if not self.hidden:
            self.parts.append(value)


def _plain_text(value, limit):
    if not isinstance(value, str):
        return ""
    parser = _PlainText()
    parser.feed(unescape(value))
    parser.close()
    value = "".join(parser.parts)
    value = "".join(character for character in value if character.isprintable() or character.isspace())
    return " ".join(value.split())[:limit]


class WikipediaSearch:
    """Returns encyclopedia excerpts, without API keys or generated answers."""

    def __init__(self, http_transport, *, ttl_seconds=300, max_entries=128, clock=time.monotonic):
        if ttl_seconds <= 0 or max_entries <= 0:
            raise ValueError("Search cache limits must be positive")
        self.http = http_transport
        self.ttl_seconds, self.max_entries, self.clock = ttl_seconds, max_entries, clock
        self._cache = OrderedDict()
        self._lock = threading.Lock()

    def search(self, query, policy, domains=None):
        query = WebSearch.model_validate({"query": query}).query
        # This floor also protects direct adapter use, including encoded tokens.
        decoded, seen = query, set()
        while decoded not in seen:
            seen.add(decoded)
            checks, _ = secrets.inspect(decoded)
            if checks:
                raise ValueError("Search query contains credential-like material")
            decoded = unquote(decoded)
        if policy is None:
            raise PermissionError("Search requires a policy")
        grant = policy.tools.allow.get("web.search")
        if grant is None or grant.action != "allow":
            raise PermissionError("Search is not authorized by policy")
        if domains is None:
            domains = grant.domains
        # Recheck the current grant before cache reads as well as network calls.
        validate_destination(WIKIPEDIA_API, policy, grant.domains)
        validate_destination(WIKIPEDIA_API, policy, domains)
        with self._lock:
            cached = self._cache.get(query)
            if cached is not None:
                expires, result = cached
                if expires > self.clock():
                    self._cache.move_to_end(query)
                    return deepcopy(result) | {"cached": True}
                del self._cache[query]
        url = WIKIPEDIA_API + "?" + urlencode({
            "action": "query", "generator": "search", "gsrsearch": query,
            "gsrlimit": 4, "gsrnamespace": 0, "prop": "extracts|info",
            "exintro": 1, "explaintext": 1, "exsentences": 3,
            "inprop": "url", "format": "json", "formatversion": 2,
        })
        try:
            response = self.http.request("GET", url, None, policy, domains)
            if not isinstance(response, dict) or response.get("status_code") != 200:
                raise SearchUnavailable("Live search is unavailable")
            body = response.get("body")
            if not isinstance(body, dict) or "error" in body:
                raise SearchUnavailable("Live search is unavailable")
            result = self._normalize(query, body)
        except EgressDenied:
            raise
        except (OSError, HTTPException, ValueError, TypeError, KeyError):
            raise SearchUnavailable("Live search is unavailable") from None
        # Output DLP still inspects the original result in the gateway, but a
        # provider excerpt containing credential-like data must not enter cache.
        secret_checks, _ = secrets.inspect(json.dumps(result, ensure_ascii=False))
        if secret_checks:
            return result
        with self._lock:
            now = self.clock()
            for key in [key for key, (expires, _) in self._cache.items() if expires <= now]:
                del self._cache[key]
            self._cache[query] = (now + self.ttl_seconds, deepcopy(result))
            self._cache.move_to_end(query)
            while len(self._cache) > self.max_entries:
                self._cache.popitem(last=False)
        return result

    @staticmethod
    def _normalize(query, body):
        if "query" not in body:
            if body.get("batchcomplete") is not True:
                raise ValueError("Search provider returned an incomplete response")
            pages = []
        else:
            data = body["query"]
            if not isinstance(data, dict) or not isinstance(data.get("pages"), list):
                raise ValueError("Search provider returned an invalid result list")
            pages = data["pages"]
        sources, ids = [], set()
        # Generator output order can differ from search rank; MediaWiki supplies index.
        pages = [page for page in pages if isinstance(page, dict)]
        pages.sort(key=lambda page: page["index"] if type(page.get("index")) is int and page["index"] > 0 else float("inf"))
        for page in pages:
            page_id = page.get("pageid")
            title = _plain_text(page.get("title"), 200)
            if type(page_id) is not int or page_id <= 0 or page_id in ids or not title or page.get("missing"):
                continue
            ids.add(page_id)
            sources.append({"title": title, "url": "https://en.wikipedia.org/?curid=" + str(page_id),
                            "snippet": _plain_text(page.get("extract"), 1200)})
            if len(sources) == 4:
                break
        return {"provider": "Wikipedia", "query": query,
                "answer": sources[0]["snippet"] if sources else "",
                "title": sources[0]["title"] if sources else "", "sources": sources,
                "google_url": "https://www.google.com/search?" + urlencode({"q": query}),
                "cached": False}
