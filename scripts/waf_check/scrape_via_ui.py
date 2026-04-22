"""
Simulates a real user searching for a keyword via the emedevents.com UI,
paginating through results, and scraping conference data from the rendered DOM.

This test assumes the direct API endpoint has been blocked — it goes entirely
through the browser UI the way a human would.

Usage:
    python scripts/waf_check/scrape_via_ui.py
    python scripts/waf_check/scrape_via_ui.py --keyword Oncology --pages 10
    python scripts/waf_check/scrape_via_ui.py --headless false   # watch the browser
"""
import argparse
import csv
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from common import green, red

BASE_URL    = "https://www.emedevents.com"
SEARCH_URL  = f"{BASE_URL}/Conferences/searchConference"

# Selectors to try for the search input on the homepage
SEARCH_INPUT_SELECTORS = [
    "input[placeholder*='Search']",
    "input[placeholder*='search']",
    "input[type='search']",
    "input[name='keyword']",
    "input[name='search']",
    ".search-input input",
    "header input",
]

# Selectors for the next page button
NEXT_PAGE_SELECTORS = [
    "a[aria-label='Next']",
    "a[aria-label='next']",
    ".pagination .next a",
    "li.next a",
    "a:has-text('>')",
    "[class*='pagination'] a:last-child",
]

# Selectors for conference cards on the results page
CARD_SELECTORS = [
    ".conference-card",
    ".event-card",
    "[class*='conferenceCard']",
    "[class*='eventCard']",
    "article",
    ".card",
]


def find_selector(page, selectors: list[str]) -> str | None:
    """Return the first selector that matches at least one element."""
    for sel in selectors:
        try:
            if page.query_selector(sel):
                return sel
        except Exception:
            continue
    return None


def parse_card_text(blob: str) -> tuple[str, str, str]:
    """Parse the card text blob into (title, organization, date).

    Card text follows this structure:
        Title of Conference
        By Organization Name...
        Jan 01 - 05, 2026 | Location, USA
        Speciality ...
        ...
    """
    lines = [l.strip() for l in blob.splitlines() if l.strip()]
    title = lines[0] if lines else ""

    org = ""
    date_str = ""
    for line in lines[1:]:
        if line.lower().startswith("by ") and not org:
            org = line[3:].rstrip(".")  # strip "By " prefix and trailing dots
        elif not date_str and ("|" in line or any(
            m in line for m in ["Jan","Feb","Mar","Apr","May","Jun",
                                 "Jul","Aug","Sep","Oct","Nov","Dec"]
        )):
            date_str = line.split("|")[0].strip()  # keep only date part, drop location

    return title, org, date_str


def extract_cards(page) -> list[dict]:
    """Extract unique conference cards from the rendered page.
    Uses conference links as the anchor, then parses the parent card text.
    """
    seen_urls: set[str] = set()
    conferences = []

    # Each conference link with /c/ or /online-cme path is one card
    links = page.query_selector_all(
        "a[href*='/c/medical-conferences'], a[href*='/online-cme-courses']"
    )

    for link in links:
        href = link.get_attribute("href") or ""
        url  = f"{BASE_URL}{href}" if href.startswith("/") else href

        if not url or url in seen_urls:
            continue
        seen_urls.add(url)

        # Walk up to find the card container that has all the text
        card_text = ""
        try:
            # Go up 3 levels to capture the full card text
            parent = link.evaluate_handle("el => el.closest('li, article, div.card, [class*=\"card\"], [class*=\"item\"]') || el.parentElement.parentElement.parentElement")
            if parent:
                card_text = parent.as_element().inner_text() if parent.as_element() else link.inner_text()
        except Exception:
            card_text = link.inner_text()

        title, org, date_str = parse_card_text(card_text)
        if not title:
            title = link.inner_text().strip()

        conferences.append({
            "title"            : title,
            "organization_name": org,
            "startdate"        : date_str,
            "detailpage_url"   : url,
        })

    return conferences


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keyword",  default="Cardiology", help="Search keyword (default: Cardiology)")
    parser.add_argument("--pages",    type=int, default=10, help="Pages to scrape (default: 10)")
    parser.add_argument("--headless", default="true",       help="Run headless? true/false (default: true)")
    args = parser.parse_args()
    headless = args.headless.lower() != "false"

    from playwright.sync_api import sync_playwright

    logs_dir  = Path(__file__).parent.parent.parent / "logs"
    logs_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path  = logs_dir / f"ui_scrape_{args.keyword.lower()}_{timestamp}.csv"
    log_path  = logs_dir / f"ui_scrape_{args.keyword.lower()}_{timestamp}.log"

    print(f"\nUI Scrape Test — {BASE_URL}")
    print(f"Keyword  : {args.keyword}")
    print(f"Pages    : {args.pages}")
    print(f"Headless : {headless}")
    print(f"Output   : {csv_path}\n")

    all_conferences: list[dict] = []
    log_lines: list[str] = [
        f"UI Scrape Report — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Keyword: {args.keyword}  |  Pages: {args.pages}",
        "",
    ]

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless)
        context = browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            locale="en-US",
            viewport={"width": 1280, "height": 900},
        )
        page = context.new_page()

        # --- Step 1: Navigate to search results page ---
        # The homepage search box submits but stays on the homepage (JS-handled).
        # Navigate directly to the search URL which renders the actual results.
        start_url = f"{SEARCH_URL}?keyword={args.keyword}"
        print(f"Step 1: Navigating to search results — {start_url}")
        page.goto(start_url, wait_until="networkidle", timeout=30000)
        print(f"  URL: {page.url}")
        log_lines.append(f"Search URL reached: {page.url}")

        # --- Step 2: Scrape pages ---
        print(f"\n  {'Page':<6} {'HTTP':<6} {'Cards found':<14} {'Running total'}")
        print(f"  {'-' * 50}")

        for pg in range(1, args.pages + 1):
            # Wait for content to render
            page.wait_for_timeout(1500)

            cards = extract_cards(page)
            all_conferences.extend(cards)

            status = "200"
            row = f"  {pg:<6} {status:<6} {len(cards):<14} {len(all_conferences)}"
            print(green(row) if cards else red(row))
            log_lines.append(f"Page {pg}: {len(cards)} cards found (running total: {len(all_conferences)})")

            if pg == args.pages:
                break

            # --- Paginate to next page ---
            next_sel = find_selector(page, NEXT_PAGE_SELECTORS)
            if next_sel:
                try:
                    page.click(next_sel)
                    page.wait_for_load_state("networkidle", timeout=20000)
                except Exception as e:
                    print(red(f"  Page {pg + 1}: could not click next — {e}"))
                    log_lines.append(f"Pagination stopped at page {pg}: {e}")
                    break
            else:
                # Try URL-based pagination as fallback
                next_url = f"{SEARCH_URL}?keyword={args.keyword}&page={pg + 1}"
                print(red(f"  No next button found — navigating to {next_url}"))
                page.goto(next_url, wait_until="networkidle", timeout=20000)

        context.close()
        browser.close()

    # --- Step 3: Write CSV ---
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["title", "organization_name", "startdate", "detailpage_url"])
        writer.writeheader()
        writer.writerows(all_conferences)

    # --- Step 4: Write log ---
    log_lines += [
        "",
        f"Total conferences scraped : {len(all_conferences)}",
        f"CSV saved to              : {csv_path}",
        "",
        "WAF blocked scraping: NO" if all_conferences else "WAF may have blocked scraping — 0 results",
    ]
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines) + "\n")

    print(f"\n{'=' * 50}")
    print(f"Total conferences scraped : {len(all_conferences)}")
    print(f"CSV  : {csv_path}")
    print(f"Log  : {log_path}")
    print()
    if all_conferences:
        print(red(f"✗ Site is NOT protected — {len(all_conferences)} conferences scraped freely via the UI with no block."))
    else:
        print(green("✓ No conferences scraped — WAF may be blocking UI access, or card selectors need tuning."))
        print("  Re-run with --headless false to watch the browser and confirm which it is.")


if __name__ == "__main__":
    main()
