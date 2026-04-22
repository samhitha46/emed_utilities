"""
WAF Check — Test 4: Headless Browser Scrape
=============================================
WHAT WE ARE TESTING
-------------------
Tests 1–3 use plain HTTP requests. A sophisticated scraper goes further:
it launches a real browser engine (Chromium) in headless mode, executes
all the JavaScript the page runs, and intercepts the underlying API calls
that actually load the conference data.

This is important because modern sites like ours use JavaScript to fetch
data after the initial page load — so scraping the raw HTML (Test 3) may
return empty results. A headless browser gets the fully rendered page AND
reveals the backend API endpoints the frontend is calling.

We intercept every network response made during the page load and identify:
  - Which API endpoint actually returns the conference data
  - What fields are in each conference record
  - Whether pagination across 6 pages of the Cardiology search works freely

We also flag if the backend API is on a subdomain different from www.emedevents.com,
so the team is aware which server is serving the data.

WHY IT MATTERS
--------------
Even if the WAF blocks simple HTTP scrapers, a headless browser is much
harder to detect. It sends the same headers, executes the same JavaScript,
and behaves identically to a real user — except it does it programmatically
at scale. If this test passes unblocked, the site's data is freely
harvestable by anyone with basic automation skills.

Requirements:
    pip install playwright
    playwright install chromium

Usage:
    python scripts/waf_check/test4_headless_browser_scrape.py
"""
import time

from common import BASE_URL, BROWSER_HEADERS, CheckResult, Report

SEARCH_URL = f"{BASE_URL}/Conferences/searchConference?keyword=Cardiology"

RENDERED_SELECTORS = [
    "a[href*='/c/']",
    ".conference-item",
    ".event-item",
    ".card",
    "article",
    "[class*='conference']",
    "[class*='event']",
]


def run(report: Report) -> None:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("  Playwright not installed.")
        print("  Run: pip install playwright && playwright install chromium")
        return

    print(f"  Target     : {SEARCH_URL}")
    print(f"  Tool       : Playwright / headless Chromium")
    print(f"  User-Agent : real Chrome (same as a genuine browser)\n")
    print(f"  Launching headless Chromium...")

    api_calls:      list[dict] = []
    data_endpoints: list[dict] = []

    def on_response(response):
        url = response.url
        if any(url.endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".svg", ".ico", ".woff2"]):
            return
        if any(k in url for k in ["api", "search", "conference", "json", "graphql", "_next/data"]):
            api_calls.append({"url": url, "method": response.request.method})
            try:
                ct = response.headers.get("content-type", "")
                if "json" in ct:
                    body = response.json()
                    if isinstance(body, list) and len(body) > 0:
                        data_endpoints.append({
                            "url": url,
                            "count": len(body),
                            "sample_keys": list(body[0].keys()) if isinstance(body[0], dict) else [],
                        })
                    elif isinstance(body, dict):
                        for k, v in body.items():
                            if isinstance(v, list) and len(v) > 0:
                                data_endpoints.append({
                                    "url": url,
                                    "count": len(v),
                                    "key": k,
                                    "sample_keys": list(v[0].keys()) if isinstance(v[0], dict) else [],
                                })
            except Exception:
                pass

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent=BROWSER_HEADERS["User-Agent"],
            locale="en-US",
        )
        page = context.new_page()
        page.on("response", on_response)

        blocked = False
        try:
            resp = page.goto(SEARCH_URL, wait_until="networkidle", timeout=30000)
            if resp and resp.status in (403, 429, 503):
                blocked = True
                print(f"  WAF blocked the page load: HTTP {resp.status}")
        except Exception as e:
            print(f"  Page load error: {e}")

        if not blocked:
            # Count rendered conference cards
            conference_count = 0
            matched_selector = "none"
            for sel in RENDERED_SELECTORS:
                elements = page.query_selector_all(sel)
                if elements:
                    conference_count = len(elements)
                    matched_selector = sel
                    break

            print(f"  Conferences rendered in browser (page 1): {conference_count} (selector: {matched_selector})")

            # Report intercepted data endpoints
            if data_endpoints:
                print(f"\n  *** BACKEND API ENDPOINTS DISCOVERED ({len(data_endpoints)}) ***")
                seen_urls = set()
                for ep in data_endpoints:
                    if ep["url"] in seen_urls:
                        continue
                    seen_urls.add(ep["url"])
                    key_info = f"under key '{ep.get('key', 'root')}'" if "key" in ep else "as root list"
                    print(f"    URL    : {ep['url']}")
                    print(f"    Items  : {ep['count']} records {key_info}")
                    print(f"    Fields : {ep.get('sample_keys', [])}")
                    # Note the backend subdomain for visibility
                    if "emedevents.com" in ep["url"] and "www.emedevents.com" not in ep["url"]:
                        from urllib.parse import urlparse
                        subdomain = urlparse(ep["url"]).netloc
                        print(f"    ℹ  Backend API served from: {subdomain}")
            else:
                print(f"\n  No JSON data endpoints identified (checked {len(api_calls)} network calls)")
                for call in api_calls[:15]:
                    print(f"    {call['method']} {call['url']}")

            # Paginate 5 more pages
            total_count = conference_count
            print(f"\n  Paginating 5 more pages via headless browser...")
            for pg in range(2, 7):
                try:
                    page.goto(f"{SEARCH_URL}&page={pg}", wait_until="networkidle", timeout=20000)
                    for sel in RENDERED_SELECTORS:
                        elements = page.query_selector_all(sel)
                        if elements:
                            total_count += len(elements)
                            print(f"    Page {pg}: {len(elements)} conferences")
                            break
                    else:
                        print(f"    Page {pg}: 0 found")
                except Exception as e:
                    print(f"    Page {pg}: error — {e}")
                    break

            print(f"\n  Total conferences scraped across 6 pages: {total_count}")

        context.close()
        browser.close()

    # Summarise findings
    unique_data_urls = list({ep["url"] for ep in data_endpoints})
    if blocked:
        detail = "WAF blocked the headless Chromium request — headless browsers are being detected"
    elif data_endpoints:
        detail = (
            f"Headless browser scraped freely. "
            f"Backend API endpoint(s) exposed: {unique_data_urls}. "
            f"Records per page: {[ep['count'] for ep in data_endpoints[:3]]}. "
            f"Total scraped across 6 pages: {total_count if not blocked else 'N/A'}"
        )
    else:
        detail = (
            f"Headless browser scraped freely ({total_count} cards across 6 pages). "
            f"{len(api_calls)} API calls intercepted but no JSON data endpoint identified."
        )

    report.add(CheckResult(
        name="Headless browser scrape — Cardiology search (6 pages)",
        passed=blocked,
        status_code=403 if blocked else 200,
        detail=detail,
    ))


def main() -> None:
    print("=" * 60)
    print("Test 4 — Headless Browser Scrape")
    print("Can a real (but automated) browser scrape the site and")
    print("discover the backend API endpoints powering the pages?")
    print("=" * 60 + "\n")

    report = Report()
    run(report)
    report.summary()
    report.write_log("test4_headless_browser_scrape")


if __name__ == "__main__":
    main()
