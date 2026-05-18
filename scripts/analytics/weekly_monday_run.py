"""
Monday master run: collect GA4 data → analyse → email the KPI report.

Steps (runs in sequence):
  1. Pull 52 weeks of weekly platform metrics from GA4 → overwrites weekly_platform.csv
  2. Run the KPI analysis → overwrites kpi_report.txt
  3. Email the report to all recipients

Usage:
    python scripts/analytics/weekly_monday_run.py             # full run + email
    python scripts/analytics/weekly_monday_run.py --dry-run   # collect + analyse, skip email
"""
import argparse
import csv
import sys
from dataclasses import asdict, fields
from datetime import date
from pathlib import Path

import requests

sys.stdout.reconfigure(encoding="utf-8")

# allow importing sibling script without making scripts/ a formal package
sys.path.insert(0, str(Path(__file__).parent))
from analyze_weekly_platform import build_report, load_weeks  # noqa: E402

from emed_utilities.analytics.ga4 import WeeklyPlatformMetrics, get_weekly_platform_metrics
from emed_utilities.config import get_settings
from emed_utilities.logging_config import get_logger

log = get_logger(__name__)

# ── config ────────────────────────────────────────────────────────────────────

WEEKS       = 52
CSV_PATH    = Path("scripts/analytics/output/weekly_platform.csv")
REPORT_PATH = Path("scripts/analytics/output/kpi_report.txt")

RECIPIENTS = [
    "rajesh@emedevents.com",
    # add more addresses here, one per line
]

COLUMNS = [f.name for f in fields(WeeklyPlatformMetrics)]


# ── steps ─────────────────────────────────────────────────────────────────────

def step_collect() -> list[dict]:
    print(f"[1/3] Collecting {WEEKS} weeks of platform metrics from GA4 ...")
    metrics = get_weekly_platform_metrics(weeks=WEEKS)
    print(f"      Received {len(metrics)} weekly data points.")

    CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows([asdict(r) for r in metrics])
    print(f"      Saved → {CSV_PATH}")

    return load_weeks(CSV_PATH)


def step_analyse(rows: list[dict]) -> str:
    print("[2/3] Building KPI report ...")
    report = build_report(rows)

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"      Saved → {REPORT_PATH}")
    return report


def step_email(report: str, dry_run: bool) -> None:
    settings = get_settings()

    if not settings.sendgrid_api_key:
        print("[3/3] SENDGRID_API_KEY not set — skipping email.")
        print("      Fill in SENDGRID_API_KEY and SENDGRID_FROM in .env to enable.")
        return

    week_label = date.today().strftime("%d %b %Y")
    subject    = f"Weekly Platform KPI Report — {week_label}"

    if dry_run:
        print("[3/3] DRY RUN — email not sent.")
        print(f"      Would send to : {RECIPIENTS}")
        print(f"      Subject       : {subject}")
        return

    payload = {
        "personalizations": [{"to": [{"email": r} for r in RECIPIENTS]}],
        "from": {"email": settings.sendgrid_from},
        "subject": subject,
        "content": [{"type": "text/plain", "value": report}],
    }

    print(f"[3/3] Sending email via SendGrid to {RECIPIENTS} ...")
    resp = requests.post(
        "https://api.sendgrid.com/v3/mail/send",
        json=payload,
        headers={"Authorization": f"Bearer {settings.sendgrid_api_key}"},
        timeout=15,
    )

    if resp.status_code == 202:
        print("      Email sent.")
        log.info("weekly_report_emailed", recipients=RECIPIENTS, subject=subject)
    else:
        print(f"      SendGrid error {resp.status_code}: {resp.text}")
        log.error("weekly_report_email_failed", status=resp.status_code, body=resp.text)


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Monday master run: collect GA4 data, build KPI report, email it."
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Collect and analyse but do not send the email",
    )
    args = parser.parse_args()

    print(f"\n{'='*50}")
    print(f"  Weekly KPI Run — {date.today():%A, %d %b %Y}")
    print(f"{'='*50}\n")

    rows   = step_collect()
    report = step_analyse(rows)
    step_email(report, dry_run=args.dry_run)

    print("\nDone.\n")


if __name__ == "__main__":
    main()
