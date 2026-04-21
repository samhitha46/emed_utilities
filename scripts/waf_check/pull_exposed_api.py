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
import time
from datetime import datetime
from pathlib import Path

import requests

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


def fetch_page(keyword: str, pageno: int) -> list[dict]:
    headers = {
        **HEADERS,
        "clickedurl": f"{SITE_URL}/Conferences/searchConference?keyword={keyword}",
    }
    payload = {"pageno": pageno, "limit": PAGE_SIZE, "request_type": "normallist"}
    resp = requests.post(API_URL, json=payload, headers=headers, timeout=15)
    resp.raise_for_status()
    return resp.json().get("conferences", [])


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

    total = 0
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["title", "organization_name", "startdate", "detailpage_url"])

        for pageno in range(args.pages):
            conferences = fetch_page(args.keyword, pageno)
            if not conferences:
                print(f"  Page {pageno + 1}: no results — stopping early")
                break

            for c in conferences:
                writer.writerow([
                    c.get("title", ""),
                    c.get("organization_name", ""),
                    c.get("startdate", ""),
                    f"{SITE_URL}/{c.get('detailpage_url', '')}",
                ])
            total += len(conferences)
            print(f"  Page {pageno + 1}: {len(conferences)} conferences pulled  (running total: {total})")
            time.sleep(0.2)

    print(f"\nDone. {total} conferences written to: {out_path}")


if __name__ == "__main__":
    main()
