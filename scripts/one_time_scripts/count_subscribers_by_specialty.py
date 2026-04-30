"""
One-time script: count newsletter subscribers matching a specialty name.

Logic:
  1. Accept a specialty name as input (partial match, case-insensitive).
  2. Look up all matching IDs from tbl_master_specialities.
  3. Build a query against tbl_newsletter_subscribers using REGEXP to match
     comma-separated speciality_ids values.
  4. Print the count and the exact SQL so you can reuse it.

Usage:
    python scripts/one_time_scripts/count_subscribers_by_specialty.py
    python scripts/one_time_scripts/count_subscribers_by_specialty.py --name Cardiology
"""
import argparse
import sys
from pathlib import Path

from sqlalchemy import text

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from emed_utilities.db.connection import get_session


def count_subscribers_by_specialty(name: str) -> None:
    with get_session() as session:

        # ── Step 1: Find matching speciality IDs ──────────────────────────────
        rows = session.execute(
            text("SELECT id, name FROM tbl_master_specialities WHERE name LIKE :pattern"),
            {"pattern": f"%{name}%"},
        ).fetchall()

        if not rows:
            print(f"\nNo specialities found matching '{name}'")
            return

        ids = [row[0] for row in rows]
        print(f"\nFound {len(ids)} speciality match(es) for '{name}':")
        for row in rows:
            print(f"  id={row[0]}  name={row[1]}")

        # ── Step 2: Build REGEXP conditions ───────────────────────────────────
        # Matches id at start, middle, or end of a comma-separated string.
        conditions = " OR ".join(
            f"specialty_ids REGEXP '(^|,){id}(,|$)'" for id in ids
        )

        # ── Step 3: Build and print the SQL ───────────────────────────────────
        sql = (
            f"SELECT COUNT(*)\n"
            f"FROM   tbl_newsletter_subscribers\n"
            f"WHERE  {conditions};"
        )
        print(f"\nGenerated SQL:\n{'-' * 60}\n{sql}\n{'-' * 60}")

        # ── Step 4: Execute and show the count ────────────────────────────────
        count = session.execute(text(
            f"SELECT COUNT(*) FROM tbl_newsletter_subscribers WHERE {conditions}"
        )).scalar()

        print(f"\nTotal newsletter subscribers matching '{name}': {count}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Count newsletter subscribers by specialty name"
    )
    parser.add_argument(
        "--name",
        default="",
        help="Specialty name to search (partial match). Prompted if not provided.",
    )
    args = parser.parse_args()

    name = args.name.strip() or input("Enter specialty name to search: ").strip()
    if not name:
        print("No name provided. Exiting.")
        sys.exit(1)

    count_subscribers_by_specialty(name)


if __name__ == "__main__":
    main()
