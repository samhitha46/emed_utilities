"""
Reads a GA report CSV, enriches it with:
  - eMed URL    : emed_url fetched from tbl_conferences (used to query GA4)
  - Users       : Total users from GA4 for the date range in the CSV
  - Page Views  : Pageviews from GA4 for the date range in the CSV

Usage:
    # Fill eMed URL only (no GA4 query)
    python scripts/conferences/enrich_ga_csv.py --input "path/to/report.csv"

    # Fill eMed URL + GA4 metrics
    python scripts/conferences/enrich_ga_csv.py --input "path/to/report.csv" --ga4

    # Save to a new file
    python scripts/conferences/enrich_ga_csv.py --input "path/to/report.csv" --ga4 --output "path/to/enriched.csv"

The input CSV must have these columns:
    Conference ID, Conference Title, Organizer Name, Start Date, End Date, URL, Users, Page Views

Output appends an "eMed URL" column (the DB slug used for GA4 lookups).
The original URL column is preserved unchanged.
"""
import argparse
import csv
from pathlib import Path

from sqlalchemy import text

from emed_utilities.db.connection import get_session
from emed_utilities.logging_config import get_logger

log = get_logger(__name__)

COLUMNS = ["Conference ID", "Conference Title", "Organizer Name", "Start Date", "End Date", "URL", "Users", "Page Views", "eMed URL"]


def fetch_emed_urls(conference_ids: list[int]) -> dict[int, str]:
    if not conference_ids:
        return {}
    with get_session() as session:
        rows = session.execute(
            text("SELECT id, emed_url FROM tbl_conferences WHERE id IN :ids"),
            {"ids": tuple(conference_ids)},
        ).fetchall()
    return {row.id: (row.emed_url or "") for row in rows}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input",  required=True, help="Path to the input GA report CSV")
    parser.add_argument("--output", help="Output path (default: overwrites input)")
    parser.add_argument("--ga4",    action="store_true", help="Also fetch Users and Pageviews from GA4")
    args = parser.parse_args()

    input_path  = Path(args.input)
    output_path = Path(args.output) if args.output else input_path

    if not input_path.exists():
        print(f"File not found: {input_path}")
        return

    with open(input_path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        print("CSV is empty.")
        return

    # --- Step 1: Fill URL from DB ---
    conference_ids = []
    for row in rows:
        try:
            conference_ids.append(int(row["Conference ID"]))
        except (ValueError, KeyError):
            pass

    print(f"Found {len(conference_ids)} conference IDs — querying tbl_conferences...")
    url_map = fetch_emed_urls(conference_ids)
    print(f"Fetched emed_url for {len(url_map)} conferences.")

    for row in rows:
        try:
            conf_id = int(row["Conference ID"])
        except (ValueError, KeyError):
            continue
        row["eMed URL"] = url_map.get(conf_id, "")

    print(f"eMed URL column filled.")

    # --- Step 2: Fill Users + Pageviews from GA4 ---
    if args.ga4:
        from emed_utilities.analytics.ga4 import get_page_metrics

        # Use the date range from the first row of the CSV
        first_row  = rows[0]
        start_date = _reformat_date(first_row.get("Start Date", ""))
        end_date   = _reformat_date(first_row.get("End Date", ""))

        slugs = [row["eMed URL"] for row in rows if row.get("eMed URL")]
        print(f"Querying GA4 for {len(slugs)} page paths ({start_date} to {end_date})...")

        metrics = get_page_metrics(slugs, start_date, end_date)
        print(f"GA4 returned data for {len(metrics)} pages.")

        ga_filled = 0
        for row in rows:
            slug = row.get("eMed URL", "")
            if slug in metrics:
                row["Users"]      = metrics[slug].users
                row["Page Views"] = metrics[slug].pageviews
                ga_filled += 1
            else:
                row["Users"]      = 0
                row["Page Views"] = 0

        print(f"GA4 metrics filled for {ga_filled} conferences ({len(slugs) - ga_filled} had no traffic).")

    # --- Write output ---
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved to: {output_path}")
    log.info("enrich_complete", input=str(input_path), output=str(output_path), ga4=args.ga4)


def _reformat_date(date_str: str) -> str:
    """Convert DD/MM/YYYY to YYYY-MM-DD for GA4 API."""
    try:
        from datetime import datetime
        return datetime.strptime(date_str.strip(), "%m/%d/%Y").strftime("%Y-%m-%d")
    except ValueError:
        return date_str.strip()


if __name__ == "__main__":
    main()
