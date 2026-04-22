"""
WAF verification script for emedevents.com.
Tests whether the WAF actually blocks automated scraping.

Usage:
    # Unauthenticated tests only
    python scripts/waf_check/check_waf.py

    # Include authenticated tests (uses your account session)
    python scripts/waf_check/check_waf.py --email you@example.com --password yourpass
"""
import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import requests
from bs4 import BeautifulSoup

BASE_URL = "https://www.emedevents.com"
LOGIN_URL = f"{BASE_URL}/login"
LISTING_URLS = [
    f"{BASE_URL}/medical-conferences/medical-conferences-2025",
    f"{BASE_URL}/medical-conferences/medical-conferences-2026",
]

# Simulates a real browser
BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

# Obvious bot signature — a real WAF should block this
BOT_HEADERS = {
    "User-Agent": "python-requests/2.32.0",
}


@dataclass
class CheckResult:
    name: str
    passed: bool       # True = WAF blocked it (good); False = WAF missed it (bad)
    status_code: int
    detail: str


@dataclass
class Report:
    results: list[CheckResult] = field(default_factory=list)

    def add(self, result: CheckResult) -> None:
        self.results.append(result)
        status = "BLOCKED (WAF working)" if result.passed else "NOT BLOCKED (WAF gap)"
        print(f"  {'✓' if result.passed else '✗'} [{result.status_code}] {result.name}: {status}")
        print(f"      {result.detail}")

    def summary(self) -> None:
        blocked = sum(1 for r in self.results if r.passed)
        total = len(self.results)
        print("\n" + "=" * 60)
        print(f"SUMMARY: {blocked}/{total} checks blocked by WAF")
        if blocked == total:
            print("WAF appears to be blocking all tested scraping patterns.")
        else:
            gaps = [r.name for r in self.results if not r.passed]
            print(f"WAF GAPS FOUND in: {', '.join(gaps)}")
        print("=" * 60)


def _is_blocked(response: requests.Response) -> bool:
    """Return True if the response looks like a WAF block."""
    if response.status_code in (403, 429, 503):
        return True
    # Some WAFs return 200 with a challenge/block page
    body = response.text.lower()
    return any(k in body for k in ["access denied", "blocked", "captcha", "cloudflare", "ray id"])


def check_bot_user_agent(session: requests.Session, report: Report) -> None:
    """Test 1: Probe a range of User-Agent strings to understand exactly what the WAF blocks.

    Agents are grouped into three categories:
      - BAD BOTS      : should be blocked (scrapers, generic HTTP clients)
      - GOOD CRAWLERS : must NOT be blocked (Googlebot etc. — SEO critical)
      - HEADLESS      : automation tools that may or may not be blocked
    """
    url = f"{BASE_URL}/medical-conferences"

    user_agents: list[tuple[str, str, str]] = [
        # (label, user_agent_string, category)

        # --- Bad bots — WAF should block these ---
        ("python-requests (original)",  "python-requests/2.32.0",                                                   "BAD BOT"),
        ("python-httpx",                "python-httpx/0.27.0",                                                       "BAD BOT"),
        ("curl",                        "curl/8.5.0",                                                                 "BAD BOT"),
        ("wget",                        "Wget/1.21.4",                                                                "BAD BOT"),
        ("scrapy",                      "Scrapy/2.11.0 (+https://scrapy.org)",                                        "BAD BOT"),
        ("Go http client",              "Go-http-client/2.0",                                                         "BAD BOT"),
        ("Java",                        "Java/21.0.2",                                                                "BAD BOT"),
        ("libwww-perl",                 "libwww-perl/6.72",                                                           "BAD BOT"),
        ("empty user-agent",            "",                                                                            "BAD BOT"),

        # --- Good crawlers — WAF must NOT block these (SEO critical) ---
        ("Googlebot",                   "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",   "GOOD CRAWLER"),
        ("Googlebot-Mobile",            "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "GOOD CRAWLER"),
        ("Bingbot",                     "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",    "GOOD CRAWLER"),
        ("DuckDuckBot",                 "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",                  "GOOD CRAWLER"),
        ("Twitterbot",                  "Twitterbot/1.0",                                                              "GOOD CRAWLER"),
        ("LinkedInBot",                 "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient/4.1.1 +http://www.linkedin.com)", "GOOD CRAWLER"),

        # --- Headless / automation — WAF ideally blocks these ---
        ("HeadlessChrome",              "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/124.0.0.0 Safari/537.36", "HEADLESS"),
        ("Selenium (Chrome)",           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Selenium/4.0", "HEADLESS"),
        ("PhantomJS",                   "Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) PhantomJS/1.9.8 Safari/534.34", "HEADLESS"),
    ]

    print(f"  Testing {len(user_agents)} User-Agent variants against {url}")
    print(f"\n  {'Category':<16} {'Label':<30} {'HTTP':<6} {'Result'}")
    print(f"  {'-' * 70}")

    by_category: dict[str, list[tuple[str, int, bool]]] = {}  # category → [(label, status, blocked)]

    for label, ua, category in user_agents:
        headers = {**BROWSER_HEADERS, "User-Agent": ua} if ua else {k: v for k, v in BROWSER_HEADERS.items() if k != "User-Agent"}
        try:
            resp    = requests.get(url, headers=headers, timeout=10)
            blocked = _is_blocked(resp)
            status  = resp.status_code
        except Exception as e:
            blocked = False
            status  = 0

        # For good crawlers, "passed" means NOT blocked (we want them through)
        # For bad bots and headless, "passed" means blocked
        if category == "GOOD CRAWLER":
            check_passed = not blocked
            verdict = "ALLOWED (correct)" if not blocked else "BLOCKED (SEO risk!)"
        else:
            check_passed = blocked
            verdict = "BLOCKED (correct)" if blocked else "NOT BLOCKED (WAF gap)"

        print(f"  {category:<16} {label:<30} {status:<6} {verdict}")
        by_category.setdefault(category, []).append((label, status, blocked, check_passed))
        time.sleep(0.2)

    # One CheckResult per category so the summary table stays readable
    print()
    for category, entries in by_category.items():
        passed_count = sum(1 for *_, cp in entries if cp)
        total        = len(entries)
        all_correct  = passed_count == total

        gaps = [label for label, _, _, cp in entries if not cp]
        if category == "GOOD CRAWLER":
            detail_ok  = f"All {total} legitimate crawlers correctly allowed through"
            detail_gap = f"SEO RISK — WAF is blocking legitimate crawlers: {gaps}"
        else:
            detail_ok  = f"All {total} {category.lower()} agents correctly blocked"
            detail_gap = f"WAF gap — these agents were NOT blocked: {gaps}"

        report.add(CheckResult(
            name=f"User-Agent check — {category}",
            passed=all_correct,
            status_code=0,
            detail=detail_ok if all_correct else detail_gap,
        ))


def check_rapid_requests(report: Report, total: int = 100, concurrency: int = 20) -> None:
    """Test 2: Concurrent burst of requests to find the WAF rate-limit threshold.
    Sends requests in batches of `concurrency` until blocked or `total` reached.
    Default: 100 requests, 20 at a time — configurable via --rate-limit CLI args.
    """
    url = f"{BASE_URL}/medical-conferences"
    print(f"  Sending {total} requests ({concurrency} concurrent) to {url}...")
    print(f"  {'Batch':<8} {'Sent so far':<14} {'Status codes seen'}")
    print(f"  {'-' * 50}")

    results: dict[int, int] = {}   # status_code → count
    blocked_at: int | None = None
    sent = 0

    def _fetch(n: int) -> tuple[int, int]:
        try:
            r = requests.get(url, headers=BROWSER_HEADERS, timeout=10)
            return n, r.status_code
        except Exception:
            return n, 0

    batch_num = 0
    while sent < total and blocked_at is None:
        batch_size = min(concurrency, total - sent)
        batch_num += 1

        with ThreadPoolExecutor(max_workers=batch_size) as ex:
            futures = {ex.submit(_fetch, sent + i): sent + i for i in range(batch_size)}
            for future in as_completed(futures):
                _, status = future.result()
                results[status] = results.get(status, 0) + 1
                if status in (403, 429, 503):
                    blocked_at = sent + 1

        sent += batch_size
        status_summary = "  ".join(f"HTTP {k}: {v}" for k, v in sorted(results.items()))
        print(f"  {batch_num:<8} {sent:<14} {status_summary}")

        if blocked_at:
            break

    if blocked_at:
        detail = f"WAF rate-limit triggered around request #{blocked_at} of {total} (batch size {concurrency})"
    else:
        detail = (
            f"Sent {sent} requests ({concurrency} concurrent) — no block detected. "
            f"Status codes: { {k: v for k, v in results.items()} }. "
            f"WAF threshold is higher than {total} or rate limiting is not configured."
        )

    report.add(CheckResult(
        name=f"Rate limiting ({total} requests, {concurrency} concurrent)",
        passed=blocked_at is not None,
        status_code=max(results, key=results.get) if results else 200,
        detail=detail,
    ))


def check_pagination_scrape(session: requests.Session, report: Report) -> None:
    """Test 3: Walk through pages 1-10 of each year listing like a scraper would."""
    for base_listing in LISTING_URLS:
        blocked_any = False
        last_status = 200
        conferences_scraped = 0
        print(f"  Paginating through pages 1-10 of {base_listing}...")
        for page in range(1, 11):
            url = f"{base_listing}?page={page}"
            resp = session.get(url, headers=BROWSER_HEADERS, timeout=10)
            last_status = resp.status_code
            if _is_blocked(resp):
                blocked_any = True
                print(f"    → Blocked on page {page} (HTTP {resp.status_code})")
                break
            soup = BeautifulSoup(resp.text, "html.parser")
            cards = soup.select("a[href*='/c/']")
            conferences_scraped += len(cards)
            time.sleep(0.3)
        year = base_listing.split("-")[-1]
        report.add(CheckResult(
            name=f"Pagination scrape {year} (pages 1-10)",
            passed=blocked_any,
            status_code=last_status,
            detail=(
                "Blocked before finishing all pages"
                if blocked_any
                else f"Scraped all 10 pages freely, found ~{conferences_scraped} conference links"
            ),
        ))


def check_authenticated_scrape(session: requests.Session, email: str, password: str, report: Report) -> None:
    """Test 4: Login then scrape — WAF should still throttle authenticated bots."""

    # --- Step 1: get CSRF token from login page ---
    login_page = session.get(LOGIN_URL, headers=BROWSER_HEADERS, timeout=10)
    soup = BeautifulSoup(login_page.text, "html.parser")
    csrf_input = soup.find("input", {"name": "_token"}) or soup.find("input", {"name": "csrf_token"})
    csrf_token = csrf_input["value"] if csrf_input else ""

    # --- Step 2: POST credentials ---
    payload = {"email": email, "password": password, "_token": csrf_token}
    resp = session.post(LOGIN_URL, data=payload, headers=BROWSER_HEADERS, timeout=10, allow_redirects=True)

    logged_in = "logout" in resp.text.lower() or "dashboard" in resp.url.lower() or resp.status_code == 200
    if not logged_in:
        report.add(CheckResult(
            name="Authenticated scrape",
            passed=False,
            status_code=resp.status_code,
            detail="Login failed — could not test authenticated scraping",
        ))
        return

    print("  Login successful. Now scraping 15 pages per year listing as authenticated user...")
    for base_listing in LISTING_URLS:
        blocked_any = False
        last_status = 200
        total_links = 0
        year = base_listing.split("-")[-1]
        print(f"  Scraping {base_listing}...")
        for page in range(1, 16):
            url = f"{base_listing}?page={page}"
            resp = session.get(url, headers=BROWSER_HEADERS, timeout=10)
            last_status = resp.status_code
            if _is_blocked(resp):
                blocked_any = True
                print(f"    → Blocked on page {page} (HTTP {resp.status_code})")
                break
            soup = BeautifulSoup(resp.text, "html.parser")
            links = soup.select("a[href*='/c/']")
            total_links += len(links)
            time.sleep(0.2)

        report.add(CheckResult(
            name=f"Authenticated scrape {year} (15 pages)",
            passed=blocked_any,
            status_code=last_status,
            detail=(
                "Blocked mid-scrape even when authenticated"
                if blocked_any
                else f"Scraped 15 pages freely as logged-in user, found ~{total_links} links — WAF not blocking authenticated bots"
            ),
        ))


def check_playwright_scrape(report: Report) -> None:
    """Test 5: Use a real headless browser to execute JavaScript, intercept the
    underlying API calls that load conference data, and count actual results.
    This is what a sophisticated scraper would do.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("  Playwright not installed. Run: pip install playwright && playwright install chromium")
        return

    SEARCH_URL = f"{BASE_URL}/Conferences/searchConference?keyword=Cardiology"
    api_calls: list[dict] = []

    print(f"  Launching headless Chromium → {SEARCH_URL}")
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent=BROWSER_HEADERS["User-Agent"],
            locale="en-US",
        )
        page = context.new_page()

        # Intercept responses to find which call actually returns conference JSON
        data_endpoints: list[dict] = []

        def on_response(response):
            url = response.url
            # Skip static assets
            if any(url.endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".svg", ".ico", ".woff2"]):
                return
            if any(k in url for k in ["api", "search", "conference", "json", "graphql", "_next/data"]):
                api_calls.append({"url": url, "method": response.request.method})
                try:
                    ct = response.headers.get("content-type", "")
                    if "json" in ct:
                        body = response.json()
                        # Look for a list of items that could be conferences
                        if isinstance(body, list) and len(body) > 0:
                            data_endpoints.append({"url": url, "count": len(body), "sample_keys": list(body[0].keys()) if isinstance(body[0], dict) else []})
                        elif isinstance(body, dict):
                            for k, v in body.items():
                                if isinstance(v, list) and len(v) > 0:
                                    data_endpoints.append({"url": url, "count": len(v), "key": k, "sample_keys": list(v[0].keys()) if isinstance(v[0], dict) else []})
                except Exception:
                    pass

        page.on("response", on_response)

        # Load the search page and wait for conference cards to appear
        blocked = False
        try:
            resp = page.goto(SEARCH_URL, wait_until="networkidle", timeout=30000)
            if resp and resp.status in (403, 429, 503):
                blocked = True
                print(f"  WAF blocked the page load: HTTP {resp.status}")
        except Exception as e:
            print(f"  Page load error: {e}")

        if not blocked:
            # Try common selectors for rendered conference cards
            RENDERED_SELECTORS = [
                "a[href*='/c/']",
                ".conference-item",
                ".event-item",
                ".card",
                "article",
                "[class*='conference']",
                "[class*='event']",
            ]
            conference_count = 0
            matched_selector = "none"
            for sel in RENDERED_SELECTORS:
                elements = page.query_selector_all(sel)
                if elements:
                    conference_count = len(elements)
                    matched_selector = sel
                    break

            print(f"\n  Conferences rendered in browser (page 1): {conference_count} (selector: {matched_selector})")

            # Print endpoints that returned actual conference data
            if data_endpoints:
                print(f"\n  *** DATA ENDPOINTS FOUND ({len(data_endpoints)}) ***")
                for ep in data_endpoints:
                    key_info = f"under key '{ep.get('key', 'root')}'" if "key" in ep else "as root list"
                    print(f"    URL   : {ep['url']}")
                    print(f"    Items : {ep['count']} {key_info}")
                    print(f"    Fields: {ep.get('sample_keys', [])}")
            else:
                print(f"\n  No JSON data endpoints identified (checked {len(api_calls)} calls)")
                print("  All intercepted calls:")
                for call in api_calls[:15]:
                    print(f"    {call['url']}")

            # Now paginate 5 more pages using the browser and count total
            total_count = conference_count
            print("\n  Paginating 5 more pages via headless browser...")
            for pg in range(2, 7):
                try:
                    page.goto(
                        f"{SEARCH_URL}&page={pg}",
                        wait_until="networkidle",
                        timeout=20000,
                    )
                    page_resp_status = 200
                    for sel in RENDERED_SELECTORS:
                        elements = page.query_selector_all(sel)
                        if elements:
                            total_count += len(elements)
                            print(f"    Page {pg}: {len(elements)} conferences (HTTP {page_resp_status})")
                            break
                    else:
                        print(f"    Page {pg}: 0 found")
                except Exception as e:
                    print(f"    Page {pg}: error — {e}")
                    break

            print(f"\n  Total conferences scraped across 6 pages: {total_count}")

        context.close()
        browser.close()

    report.add(CheckResult(
        name="Playwright headless scrape — Cardiology search (6 pages)",
        passed=blocked,
        status_code=403 if blocked else 200,
        detail=(
            "WAF blocked the headless browser request"
            if blocked
            else (
                f"DATA ENDPOINTS EXPOSED: {[e['url'] for e in data_endpoints]} "
                f"returning {[e['count'] for e in data_endpoints]} items each"
            ) if data_endpoints else
            f"Headless browser scraped freely. {len(api_calls)} API calls intercepted but no JSON data endpoint identified yet."
        ),
    ))


def _describe_props(props: dict, indent: str = "  ", expand_keys: set | None = None) -> list[str]:
    """Recursively describe the contents of a pageProps dict.

    expand_keys: set of key names to expand fully (all sub-keys), regardless of size.
    """
    lines = []
    for key, val in props.items():
        force_expand = expand_keys and key in expand_keys
        if isinstance(val, list):
            if len(val) == 0:
                lines.append(f"{indent}'{key}': [] (empty list)")
            elif isinstance(val[0], dict):
                lines.append(f"{indent}'{key}': list of {len(val)} objects — fields: {list(val[0].keys())}")
            else:
                lines.append(f"{indent}'{key}': list of {len(val)} scalars — sample: {val[:3]}")
        elif isinstance(val, dict):
            lines.append(f"{indent}'{key}': dict with {len(val)} keys — {list(val.keys())[:8]}")
            if force_expand or len(val) <= 10:
                for k2, v2 in val.items():
                    if isinstance(v2, (str, int, float, bool)) or v2 is None:
                        display = repr(v2) if not isinstance(v2, str) else repr(v2[:120])
                        lines.append(f"{indent}    '{k2}': {display}")
                    elif isinstance(v2, list):
                        if len(v2) == 0:
                            lines.append(f"{indent}    '{k2}': [] (empty list)")
                        elif isinstance(v2[0], dict):
                            lines.append(f"{indent}    '{k2}': list of {len(v2)} objects — fields: {list(v2[0].keys())}")
                        else:
                            lines.append(f"{indent}    '{k2}': list of {len(v2)} scalars — sample: {v2[:3]}")
                    elif isinstance(v2, dict):
                        lines.append(f"{indent}    '{k2}': dict with {len(v2)} keys — {list(v2.keys())[:8]}")
        elif isinstance(val, (str, int, float, bool)) or val is None:
            display = repr(val) if not isinstance(val, str) else repr(val[:120])
            lines.append(f"{indent}'{key}': {display}")
    return lines


def _print_summary(page_props: dict, json_url: str, response_kb: float) -> list[str]:
    """Print a human-readable summary of everything exposed by the JSON endpoint
    and return the bullet points for use in the CheckResult detail.
    """
    findings: list[str] = []

    print("\n  ══════════════════════════════════════════════════════")
    print("  WHAT IS EXPOSED — plain English summary")
    print("  ══════════════════════════════════════════════════════")

    print(f"\n  Endpoint : {json_url}")
    print(f"  Auth     : none required")
    print(f"  Size     : {response_kb:.1f} KB")
    findings.append(f"Endpoint {json_url} returns {response_kb:.1f} KB with no auth")

    # IP / UA leakage
    ip = page_props.get("ip")
    ua = page_props.get("uaString")
    if ip:
        print(f"\n  [!] Server echoes the caller's real IP back in the response: {ip}")
        findings.append(f"Caller IP leaked in response: {ip}")
    if ua:
        print(f"  [!] Server echoes the caller's User-Agent: {ua[:60]}...")
        findings.append("Caller User-Agent echoed in response")

    # Conference data
    list_resp = page_props.get("listRespData", {})
    if isinstance(list_resp, dict):
        conferences = list_resp.get("conferences")
        conf_count  = list_resp.get("conferences_count")
        recommended = list_resp.get("recommendedConferences")
        banners     = list_resp.get("banners")
        request_obj = list_resp.get("request")

        if isinstance(conferences, list):
            fields = list(conferences[0].keys()) if conferences and isinstance(conferences[0], dict) else []
            print(f"\n  [!] Conference list exposed: {len(conferences)} records per page")
            print(f"      Fields per record: {fields}")
            findings.append(f"Conference list: {len(conferences)} records/page, fields: {fields}")

        if conf_count is not None:
            print(f"  [!] Total conference count exposed: {conf_count}")
            findings.append(f"Total conference count: {conf_count}")

        if isinstance(recommended, list) and recommended:
            print(f"  [!] Recommended conferences list: {len(recommended)} records")
            findings.append(f"Recommended conferences: {len(recommended)} records")

        if isinstance(banners, list) and banners:
            print(f"  [!] Banner/ad data: {len(banners)} entries")
            findings.append(f"Banner/ad data: {len(banners)} entries")

        if isinstance(request_obj, dict):
            print(f"  [!] Search request params exposed: {request_obj}")
            findings.append(f"Search request params: {request_obj}")

        other_keys = [k for k in list_resp if k not in ("conferences", "conferences_count", "recommendedConferences", "banners", "request")]
        if other_keys:
            print(f"      Other listRespData keys: {other_keys}")
            findings.append(f"Other listRespData fields: {other_keys}")

    # Auth / session state
    initial_state = page_props.get("initialState", {})
    if isinstance(initial_state, dict):
        auth = initial_state.get("authentication", {})
        user = initial_state.get("user", {})
        cart = initial_state.get("cart", {})
        print(f"\n  [i] Redux store shape exposed (useful for session impersonation):")
        print(f"      authentication keys : {list(auth.keys()) if isinstance(auth, dict) else auth}")
        print(f"      user keys           : {list(user.keys()) if isinstance(user, dict) else user}")
        print(f"      cart keys           : {list(cart.keys()) if isinstance(cart, dict) else cart}")
        findings.append(f"Redux store structure exposed: authentication={list(auth.keys()) if isinstance(auth, dict) else []}, user={list(user.keys()) if isinstance(user, dict) else []}")

    token = page_props.get("token")
    uid   = page_props.get("uid")
    print(f"\n  [i] Session identifiers in response:")
    print(f"      token : {token!r}  (None = unauthenticated request)")
    print(f"      uid   : {uid!r}  (None = unauthenticated request)")
    findings.append(f"token={token!r}, uid={uid!r} (both None for unauthenticated call — would be populated for logged-in users)")

    org = page_props.get("orgAccount")
    if org is not None:
        print(f"  [i] orgAccount flag: {org!r} — server distinguishes org vs individual accounts")
        findings.append(f"orgAccount flag present: {org!r}")

    print("\n  ══════════════════════════════════════════════════════\n")
    return findings


def check_nextjs_api(session: requests.Session, report: Report) -> None:
    """Test 5: Extract the Next.js build ID from __NEXT_DATA__ and probe the
    /_next/data/<buildId>/ JSON endpoints directly.
    If accessible, these return pure structured JSON — no browser or HTML parsing needed.
    """
    SEARCH_URL = f"{BASE_URL}/Conferences/searchConference"

    print(f"  Fetching page to extract Next.js build ID...")
    resp = session.get(SEARCH_URL, params={"keyword": "Cardiology"}, headers=BROWSER_HEADERS, timeout=15)

    if _is_blocked(resp):
        report.add(CheckResult(
            name="Next.js JSON API probe",
            passed=True,
            status_code=resp.status_code,
            detail="WAF blocked initial page fetch",
        ))
        return

    # Extract __NEXT_DATA__ which contains buildId and pre-rendered props
    soup = BeautifulSoup(resp.text, "html.parser")
    next_data_tag = soup.find("script", {"id": "__NEXT_DATA__"})

    if not next_data_tag:
        report.add(CheckResult(
            name="Next.js JSON API probe",
            passed=False,
            status_code=200,
            detail="No __NEXT_DATA__ tag found — may not be Next.js or tag is obfuscated",
        ))
        return

    next_data = json.loads(next_data_tag.string)
    build_id  = next_data.get("buildId", "")
    page_path = next_data.get("page", "")
    query     = next_data.get("query", {})

    print(f"  Build ID : {build_id}")
    print(f"  Page     : {page_path}")
    if query:
        print(f"  Query    : {query}")

    # Top-level __NEXT_DATA__ keys outside of props (runtime config, etc.)
    top_level_keys = [k for k in next_data if k not in ("props", "buildId", "page", "query")]
    if top_level_keys:
        print(f"  Other __NEXT_DATA__ keys: {top_level_keys}")
        for k in top_level_keys:
            v = next_data[k]
            if isinstance(v, dict):
                print(f"    '{k}': dict — {list(v.keys())[:8]}")
            else:
                print(f"    '{k}': {repr(v)[:80]}")

    # Show any data already embedded in the page (pre-rendered props)
    props = next_data.get("props", {}).get("pageProps", {})
    print()
    if props:
        print(f"  ── __NEXT_DATA__ pageProps ({len(props)} keys) ──────────────")
        for line in _describe_props(props):
            print(line)
    else:
        print("  No pre-rendered pageProps found (data is fetched client-side after load)")

    if not build_id:
        report.add(CheckResult(
            name="Next.js JSON API probe",
            passed=False,
            status_code=200,
            detail="Could not extract build ID from __NEXT_DATA__",
        ))
        return

    # Probe the /_next/data/ JSON endpoint directly
    json_url = f"{BASE_URL}/_next/data/{build_id}/Conferences/searchConference.json"
    print(f"\n  Probing JSON endpoint: {json_url}")
    json_resp = session.get(
        json_url,
        params={"keyword": "Cardiology"},
        headers=BROWSER_HEADERS,
        timeout=15,
    )
    print(f"  Response: HTTP {json_resp.status_code} — {len(json_resp.content) / 1024:.1f} KB")

    if _is_blocked(json_resp):
        report.add(CheckResult(
            name="Next.js JSON API probe",
            passed=True,
            status_code=json_resp.status_code,
            detail=f"WAF blocked the /_next/data/ endpoint (HTTP {json_resp.status_code})",
        ))
        return

    if json_resp.status_code == 200:
        try:
            data       = json_resp.json()
            page_props = data.get("pageProps", {})
            response_kb = len(json_resp.content) / 1024

            print(f"\n  ── /_next/data/ pageProps ({len(page_props)} keys) ──────────────")
            for line in _describe_props(page_props, expand_keys={"listRespData"}):
                print(line)

            findings = _print_summary(page_props, json_url, response_kb)
            detail = "EXPOSED (no auth): " + " | ".join(findings)
        except Exception:
            detail = f"/_next/data/ endpoint returned HTTP 200 but response is not JSON. Size: {len(json_resp.content) / 1024:.1f} KB"
    else:
        detail = f"/_next/data/ endpoint returned HTTP {json_resp.status_code}"

    report.add(CheckResult(
        name="Next.js JSON API probe",
        passed=False,
        status_code=json_resp.status_code,
        detail=detail,
    ))


def _write_report(report: Report, email: str | None) -> None:
    logs_dir = Path(__file__).parent.parent.parent / "logs"
    logs_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = logs_dir / f"waf_check_{timestamp}.log"
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(f"WAF Check Report — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Target: {BASE_URL}\n")
        f.write(f"Authenticated: {'yes (' + email + ')' if email else 'no'}\n\n")
        for r in report.results:
            status = "BLOCKED" if r.passed else "NOT BLOCKED"
            f.write(f"[{r.status_code}] {r.name}: {status}\n")
            f.write(f"  {r.detail}\n\n")
        blocked = sum(1 for r in report.results if r.passed)
        f.write(f"\nSUMMARY: {blocked}/{len(report.results)} checks blocked by WAF\n")
    print(f"\nReport saved to: {log_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify WAF protection on emedevents.com")
    parser.add_argument("--email",       help="Your emedevents.com account email")
    parser.add_argument("--password",    help="Your emedevents.com account password")
    parser.add_argument("--rate-total",  type=int, default=100,  help="Total requests for rate-limit test (default: 100)")
    parser.add_argument("--rate-concurrency", type=int, default=20, help="Concurrent requests per batch (default: 20)")
    args = parser.parse_args()

    print(f"\nWAF Verification — {BASE_URL}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    report = Report()
    session = requests.Session()

    print("[ Test 1 ] User-Agent checks (bad bots / good crawlers / headless)")
    check_bot_user_agent(session, report)

    print("\n[ Test 2 ] Rate limiting")
    check_rapid_requests(report, total=args.rate_total, concurrency=args.rate_concurrency)

    print("\n[ Test 3 ] Pagination scrape")
    check_pagination_scrape(session, report)

    print("\n[ Test 4 ] Playwright headless browser scrape")
    check_playwright_scrape(report)

    print("\n[ Test 5 ] Next.js JSON API probe")
    check_nextjs_api(session, report)

    if args.email and args.password:
        print("\n[ Test 6 ] Authenticated scrape")
        check_authenticated_scrape(session, args.email, args.password, report)
    else:
        print("\n[ Test 6 ] Authenticated scrape — skipped (pass --email and --password to enable)")

    report.summary()
    _write_report(report, args.email)


if __name__ == "__main__":
    main()
