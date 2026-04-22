"""
Pulls conference data from the exposed newdev.emedevents.com API.
Demonstrates that all conference data is accessible with no authentication.

Usage:
    python scripts/waf_check/pull_exposed_api.py
    python scripts/waf_check/pull_exposed_api.py --pages 20
    python scripts/waf_check/pull_exposed_api.py --keyword Cardiology --pages 5
"""
import argparse
import csv
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

# Add the waf_check directory to the path so common.py can be imported
sys.path.insert(0, str(Path(__file__).parent))
from common import green, red

API_URL  = "https://newdev.emedevents.com/Conference/conferenceList"
SITE_URL = "https://www.emedevents.com"

HEADERS = {
    "User-Agent"       : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Content-Type"     : "application/json",
    "Accept"           : "application/json, text/plain, */*",
    "Referer"          : f"{SITE_URL}/",
    "emedauthorization": "undefined",
    "trackinguid"      : "",
    "referrerurl"      : "",
}

PAGE_SIZE = 9


def fetch_page(keyword: str, pageno: int) -> tuple[list[dict], int]:
    """Returns (conferences, http_status_code)."""
    headers = {
        **HEADERS,
        "clickedurl": f"{SITE_URL}/Conferences/searchConference?keyword={keyword}",
    }
    payload = {"pageno": pageno, "limit": PAGE_SIZE, "request_type": "normallist"}
    resp = requests.post(API_URL, json=payload, headers=headers, timeout=15)
    return resp.json().get("conferences", []) if resp.status_code == 200 else [], resp.status_code


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keyword", default="Cardiology", help="Search keyword (default: Cardiology)")
    parser.add_argument("--pages",   type=int, default=10,  help="Number of pages to pull (default: 10)")
    args = parser.parse_args()

    logs_dir  = Path(__file__).parent.parent.parent / "logs"
    logs_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path  = logs_dir / f"exposed_api_{args.keyword.lower()}_{timestamp}.csv"

    print(f"\nPulling from exposed API: {API_URL}")
    print(f"Keyword : {args.keyword}")
    print(f"Pages   : {args.pages}  ({args.pages * PAGE_SIZE} conferences max)")
    print(f"Output  : {out_path}\n")

    total   = 0
    blocked = False

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["title", "organization_name", "startdate", "detailpage_url", "email"])

        for pageno in range(args.pages):
            try:
                conferences, status = fetch_page(args.keyword, pageno)
            except Exception as e:
                print(red(f"  Page {pageno + 1}: request failed — {e}"))
                blocked = True
                break

            if status in (403, 429, 503):
                print(red(f"  Page {pageno + 1}: HTTP {status} — API is blocking requests"))
                blocked = True
                break

            if not conferences:
                print(red(f"  Page {pageno + 1}: HTTP {status} — no conferences returned, stopping early"))
                break

            for c in conferences:
                writer.writerow([
                    c.get("title", ""),
                    c.get("organization_name", ""),
                    c.get("startdate", ""),
                    f"{SITE_URL}/{c.get('detailpage_url', '')}",
                    c.get("email", ""),
                ])
            total += len(conferences)
            print(green(f"  Page {pageno + 1}: HTTP {status} — {len(conferences)} conferences pulled  (running total: {total})"))
            time.sleep(0.2)

    print()
    if blocked:
        print(green(f"✓ API is protected — requests were blocked before any data was returned."))
    else:
        print(red(f"✗ API is EXPOSED — {total} conferences pulled with no authentication. Data written to: {out_path}"))


if __name__ == "__main__":
    main()
