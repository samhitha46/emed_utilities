"""
Collect weekly platform-level metrics from GA4 and save to CSV.

Pulls totalUsers, newUsers, returningUsers, sessions, engagementRate,
avgSessionDuration, and pageviews — aggregated by week — for a configurable
look-back window (default: 52 weeks / 1 year).

Usage:
    # Default: 52 weeks, saved to scripts/analytics/output/weekly_platform.csv
    python scripts/analytics/collect_weekly_platform.py

    # Custom window and output path
    python scripts/analytics/collect_weekly_platform.py --weeks 26 --output path/to/out.csv
"""
import argparse
import csv
from dataclasses import asdict, fields
from pathlib import Path

from emed_utilities.analytics.ga4 import WeeklyPlatformMetrics, get_weekly_platform_metrics
from emed_utilities.logging_config import get_logger

log = get_logger(__name__)

COLUMNS = [f.name for f in fields(WeeklyPlatformMetrics)]
DEFAULT_OUTPUT = Path("scripts/analytics/output/weekly_platform.csv")


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect weekly platform metrics from GA4.")
    parser.add_argument(
        "--weeks", type=int, default=52,
        help="Number of weeks of history to fetch (default: 52)",
    )
    parser.add_argument(
        "--output",
        help=f"Output CSV path (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()

    output_path = Path(args.output) if args.output else DEFAULT_OUTPUT
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Fetching {args.weeks} weeks of platform metrics from GA4...")
    rows = get_weekly_platform_metrics(weeks=args.weeks)
    print(f"Received {len(rows)} weekly data points.")

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows([asdict(r) for r in rows])

    print(f"Saved {len(rows)} rows to: {output_path}")
    log.info("collect_weekly_complete", weeks=args.weeks, rows=len(rows), output=str(output_path))


if __name__ == "__main__":
    main()
