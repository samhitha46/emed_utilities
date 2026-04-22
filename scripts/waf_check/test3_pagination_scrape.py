"""
WAF Check — Test 3: Pagination Scrape
=======================================
WHAT WE ARE TESTING
-------------------
A scraper's core workflow is simple: load page 1, collect all the data,
load page 2, repeat until done. This test mimics that exact behaviour
against our two conference listing URLs:

    /medical-conferences/medical-conferences-2025
    /medical-conferences/medical-conferences-2026

We walk through pages 1–10 for each URL using a real browser User-Agent,
count the conference links found on each page, and watch for any WAF
intervention.

We also run the same test while logged in as an authenticated user to
verify that the WAF treats authenticated bots the same as anonymous ones
(it should — legitimate users don't paginate 15 pages in seconds).

WHY IT MATTERS
--------------
If pagination is freely accessible, a scraper can download our entire
conference catalogue systematically — title, dates, organiser, location,
pricing — without ever being challenged. The WAF should detect the
sequential, high-speed page access pattern and block it.

Usage:
    # Unauthenticated only
    python scripts/waf_check/test3_pagination_scrape.py

    # Include authenticated test
    python scripts/waf_check/test3_pagination_scrape.py --email you@example.com --password yourpass
"""
import argparse
import time

import requests
from bs4 import BeautifulSoup

from common import BASE_URL, BROWSER_HEADERS, LOGIN_URL, LISTING_URLS, CheckResult, Report, is_blocked, green, red


def _scrape_pages(session: requests.Session, base_url: str, pages: int, report: Report, label: str) -> None:
    blocked_any = False
    last_status = 200
    total_links = 0

    print(f"  Paginating {pages} pages of {base_url}...")
    for page in range(1, pages + 1):
        url  = f"{base_url}?page={page}"
        resp = session.get(url, headers=BROWSER_HEADERS, timeout=10)
        last_status = resp.status_code

        if is_blocked(resp):
            blocked_any = True
            print(red(f"    → Blocked on page {page} (HTTP {resp.status_code})"))
            break

        soup  = BeautifulSoup(resp.text, "html.parser")
        links = soup.select("a[href*='/c/']")
        total_links += len(links)
        print(green(f"    Page {page}: HTTP {resp.status_code} — {len(links)} conference links found"))
        time.sleep(0.3)

    report.add(CheckResult(
        name=label,
        passed=blocked_any,
        status_code=last_status,
        detail=(
            "Blocked before finishing all pages — WAF detected scraping pattern"
            if blocked_any
            else f"Scraped all {pages} pages freely, collected ~{total_links} conference links — WAF gap"
        ),
    ))


def _login(session: requests.Session, email: str, password: str) -> bool:
    login_page = session.get(LOGIN_URL, headers=BROWSER_HEADERS, timeout=10)
    soup       = BeautifulSoup(login_page.text, "html.parser")
    csrf_input = soup.find("input", {"name": "_token"}) or soup.find("input", {"name": "csrf_token"})
    csrf_token = csrf_input["value"] if csrf_input else ""

    resp = session.post(
        LOGIN_URL,
        data={"email": email, "password": password, "_token": csrf_token},
        headers=BROWSER_HEADERS,
        timeout=10,
        allow_redirects=True,
    )
    return "logout" in resp.text.lower() or "dashboard" in resp.url.lower() or resp.status_code == 200


def run(report: Report, email: str | None = None, password: str | None = None) -> None:
    session = requests.Session()

    # --- Unauthenticated: 10 pages per year ---
    print("  [ Unauthenticated scrape ]")
    for listing_url in LISTING_URLS:
        year  = listing_url.split("-")[-1]
        _scrape_pages(session, listing_url, pages=10, report=report,
                      label=f"Pagination scrape {year} — unauthenticated (10 pages)")

    # --- Authenticated: 15 pages per year ---
    if email and password:
        print("\n  [ Authenticated scrape ]")
        if _login(session, email, password):
            print("  Login successful.")
            for listing_url in LISTING_URLS:
                year = listing_url.split("-")[-1]
                _scrape_pages(session, listing_url, pages=15, report=report,
                              label=f"Pagination scrape {year} — authenticated (15 pages)")
        else:
            report.add(CheckResult(
                name="Authenticated scrape",
                passed=False,
                status_code=0,
                detail="Login failed — could not test authenticated pagination",
            ))
    else:
        print("\n  Authenticated scrape skipped — pass --email and --password to enable")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--email",    help="emedevents.com account email")
    parser.add_argument("--password", help="emedevents.com account password")
    args = parser.parse_args()

    print("=" * 60)
    print("Test 3 — Pagination Scrape")
    print("Can a scraper walk through our conference listings page")
    print("by page without being detected or stopped?")
    print("=" * 60 + "\n")

    report = Report()
    run(report, email=args.email, password=args.password)
    report.summary()
    report.write_log("test3_pagination_scrape")


if __name__ == "__main__":
    main()
