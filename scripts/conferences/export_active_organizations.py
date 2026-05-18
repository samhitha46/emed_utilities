"""
Queries tbl_organizations for all active records (status = 1) and exports
id and name to a CSV file in the data folder.

Usage:
    python scripts/conferences/export_active_organizations.py
"""
import csv
from pathlib import Path

from sqlalchemy import text

from emed_utilities.db.connection import get_session
from emed_utilities.logging_config import get_logger

log = get_logger(__name__)

OUTPUT_PATH = Path(__file__).parent / "data" / "active_organizations.csv"


def fetch_active_organizations() -> list[dict]:
    with get_session() as session:
        rows = session.execute(
            text("SELECT id, name FROM tbl_organizations WHERE status = 1 ORDER BY name")
        ).fetchall()
    return [{"id": row.id, "name": row.name} for row in rows]


def main() -> None:
    print("Querying tbl_organizations for active records...")
    organizations = fetch_active_organizations()
    print(f"Found {len(organizations)} active organizations.")

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["id", "name"])
        writer.writeheader()
        writer.writerows(organizations)

    print(f"Saved to: {OUTPUT_PATH}")
    log.info("export_complete", output=str(OUTPUT_PATH), count=len(organizations))


if __name__ == "__main__":
    main()
