"""
Pulls conference data from the exposed newdev.emedevents.com API.

Test 1 — Direct HTTP POST (no session)
    Calls the API exactly as a raw HTTP client would — no browser, no cookies.
    Expected result: HTTP 401 (auth required).

Test 2 — Headless browser (with page session)
    Loads www.emedevents.com in a real Chromium first so the frontend JS
    establishes a guest session, then intercepts the authenticated API
    response the browser receives.
    Also prints a complete human-readable attribute dump of one conference.

Usage:
    python scripts/waf_check/pull_exposed_api.py
    python scripts/waf_check/pull_exposed_api.py --keyword Oncology --pages 5
"""
import argparse
import csv
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from common import green, red

API_URL     = "https://newdev.emedevents.com/Conference/conferenceList"
SITE_URL    = "https://www.emedevents.com"
SEARCH_PATH = "/Conferences/searchConference"
PAGE_SIZE   = 9

HEADERS = {
    "User-Agent"       : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Content-Type"     : "application/json",
    "Accept"           : "application/json, text/plain, */*",
    "Referer"          : f"{SITE_URL}/",
    "emedauthorization": "undefined",
    "trackinguid"      : "",
    "referrerurl"      : "",
}

CSV_FIELDS = ["title", "organization_name", "startdate", "detailpage_url", "email"]


# ── Helpers ───────────────────────────────────────────────────────────────────

def fetch_page_direct(keyword: str, pageno: int) -> tuple[list[dict], int]:
    """Direct HTTP POST — no browser session."""
    headers = {**HEADERS, "clickedurl": f"{SITE_URL}{SEARCH_PATH}?keyword={keyword}"}
    payload = {"pageno": pageno, "limit": PAGE_SIZE, "request_type": "normallist"}
    resp    = requests.post(API_URL, json=payload, headers=headers, timeout=15)
    conferences = resp.json().get("conferences", []) if resp.status_code == 200 else []
    return conferences, resp.status_code


def _format_value(val) -> str:
    """Return a human-readable string for any field value."""
    if val is None:
        return "—"
    if isinstance(val, bool):
        return "Yes" if val else "No"
    if isinstance(val, list):
        if not val:
            return "(empty list)"
        if isinstance(val[0], dict):
            # e.g. speakers list — show count then each item indented
            lines = [f"({len(val)} items)"]
            for i, item in enumerate(val, 1):
                lines.append(f"         [{i}]")
                for k, v in item.items():
                    lines.append(f"              {k}: {v}")
            return "\n".join(lines)
        return ", ".join(str(v) for v in val)
    if isinstance(val, dict):
        if not val:
            return "(empty)"
        pairs = ", ".join(f"{k}: {v}" for k, v in list(val.items())[:6])
        suffix = f"  … (+{len(val)-6} more)" if len(val) > 6 else ""
        return "{" + pairs + suffix + "}"
    return str(val)


def print_conference_detail(conf: dict) -> None:
    """Print every attribute and its value for one conference record."""
    width = max(len(k) for k in conf) + 2
    sep   = "─" * (width + 52)
    print(f"\n  ┌{sep}┐")
    print(f"  │  {'FULL ATTRIBUTE DUMP — first conference record':<{width + 50}}│")
    print(f"  ├{sep}┤")
    for key, val in conf.items():
        formatted = _format_value(val)
        # Multi-line values (e.g. speaker list)
        lines = formatted.split("\n")
        print(f"  │  {key:<{width}} {lines[0]}")
        for extra in lines[1:]:
            print(f"  │  {'':<{width}} {extra}")
    print(f"  └{sep}┘\n")


def _write_csv(conferences: list[dict], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_FIELDS)
        for c in conferences:
            writer.writerow([
                c.get("title", ""),
                c.get("organization_name", ""),
                c.get("startdate", ""),
                f"{SITE_URL}/{c.get('detailpage_url', '')}",
                c.get("email", ""),
            ])


# ── Test 1 — Direct HTTP ──────────────────────────────────────────────────────

def run_test1(keyword: str, pages: int, base_path: Path) -> None:
    print(f"\n{'═'*60}")
    print("Test 1 — Direct HTTP POST  (no browser session)")
    print(f"{'═'*60}")
    print(f"  Calls the API directly as a raw HTTP client would.")
    print(f"  Target  : {API_URL}")
    print(f"  Keyword : {keyword}  |  Pages: {pages}\n")

    total      = 0
    blocked    = False
    block_code = None
    all_confs  : list[dict] = []

    for pageno in range(pages):
        try:
            conferences, status = fetch_page_direct(keyword, pageno)
        except Exception as e:
            print(red(f"  Page {pageno+1}: request failed — {e}"))
            blocked = True
            break

        if status in (401, 403, 429, 503):
            print(red(f"  Page {pageno+1}: HTTP {status} — blocked / auth required, stopping"))
            blocked    = True
            block_code = status
            break

        if not conferences:
            print(red(f"  Page {pageno+1}: HTTP {status} — no conferences returned, stopping"))
            break

        all_confs.extend(conferences)
        total += len(conferences)
        print(green(f"  Page {pageno+1}: HTTP {status} — {len(conferences)} conferences  (running total: {total})"))
        time.sleep(0.2)

    csv_path = base_path.with_name(base_path.name + "_test1.csv")
    _write_csv(all_confs, csv_path)

    print()
    if blocked:
        print(green(f"  ✓  PROTECTED — direct HTTP calls blocked (HTTP {block_code})."))
        print(f"     A plain HTTP client cannot pull data without a valid session.")
    else:
        print(red(f"  ✗  EXPOSED — {total} conferences pulled with no browser session."))
        print(f"     CSV: {csv_path}")


# ── Test 2 — Headless browser ─────────────────────────────────────────────────

def run_test2(keyword: str, pages: int, base_path: Path) -> None:
    print(f"\n{'═'*60}")
    print("Test 2 — Headless browser  (with page session)")
    print(f"{'═'*60}")
    print(f"  Loads www.emedevents.com so the frontend JS establishes a guest")
    print(f"  session, then intercepts the authenticated API response.")
    print(f"  Keyword : {keyword}  |  Pages: {pages}\n")

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(red("  Playwright not installed — run: pip install playwright && playwright install chromium"))
        return

    all_confs     : list[dict] = []
    detail_printed = False
    captured      : list[dict] = []

    def on_response(response):
        if "conferenceList" in response.url:
            try:
                body = response.json()
                captured.append(body)
            except Exception:
                pass

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent=HEADERS["User-Agent"],
            locale="en-US",
            viewport={"width": 1280, "height": 900},
        )
        page = context.new_page()
        page.on("response", on_response)

        for pg in range(1, pages + 1):
            captured.clear()
            url = f"{SITE_URL}{SEARCH_PATH}?keyword={keyword}&page={pg}"
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=45000)
                page.wait_for_timeout(3000 if pg == 1 else 2000)
            except Exception as e:
                print(red(f"  Page {pg}: load error — {e}"))
                break

            if not captured:
                print(red(f"  Page {pg}: no API response intercepted — stopping"))
                break

            conferences = captured[0].get("conferences", [])
            if not conferences:
                print(red(f"  Page {pg}: API returned 0 conferences — stopping"))
                break

            # Print full attribute dump for the very first conference
            if not detail_printed:
                detail_printed = True
                print_conference_detail(conferences[0])

            all_confs.extend(conferences)
            print(green(f"  Page {pg}: HTTP 200 — {len(conferences)} conferences  (running total: {len(all_confs)})"))

        context.close()
        browser.close()

    csv_path = base_path.with_name(base_path.name + "_test2.csv")
    _write_csv(all_confs, csv_path)

    print()
    if all_confs:
        print(red(f"  ✗  EXPOSED — {len(all_confs)} conferences pulled via browser session."))
        print(f"     The API is reachable by any headless browser that loads the page first.")
        print(f"     CSV: {csv_path}")
    else:
        print(green(f"  ✓  No data extracted via headless browser session."))


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Test API exposure on newdev.emedevents.com")
    parser.add_argument("--keyword", default="Cardiology", help="Search keyword (default: Cardiology)")
    parser.add_argument("--pages",   type=int, default=10,  help="Pages to pull per test (default: 10)")
    args = parser.parse_args()

    logs_dir = Path(__file__).parent.parent.parent / "logs"
    logs_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_path = logs_dir / f"exposed_api_{args.keyword.lower()}_{timestamp}"

    print(f"\nAPI Exposure Test — {API_URL}")
    print(f"Keyword : {args.keyword}  |  Pages per test: {args.pages}")
    print(f"Logs    : {logs_dir}")

    run_test1(args.keyword, args.pages, base_path)
    run_test2(args.keyword, args.pages, base_path)

    print(f"\n{'═'*60}")
    print("Done.")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    main()
