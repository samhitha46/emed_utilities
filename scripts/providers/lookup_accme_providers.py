"""
Enriches accme_providers.csv with eMedEvents organisation data.

For each provider name in the CSV, queries tbl_organizations (exact match on
name) and appends three columns to the output CSV:

    C — eMed Provider ID
    D — eMed Provider Name
    E — eMed Provider Status

Rows with no match get empty strings in those columns.
Rows with multiple matches (name collision) get the first result and a warning.

Usage:
    python scripts/providers/lookup_accme_providers.py
    python scripts/providers/lookup_accme_providers.py --output my_output.csv
"""
import csv
import sys
from pathlib import Path

from sqlalchemy import text

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from emed_utilities.db.connection import get_session

SCRIPT_DIR = Path(__file__).parent
INPUT_CSV  = SCRIPT_DIR / "accme_providers.csv"


def load_providers(csv_path: Path) -> list[dict]:
    with open(csv_path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def lookup_organizations(session, names: list[str]) -> dict[str, list[dict]]:
    """Return {name: [row, ...]} for all names in one query."""
    if not names:
        return {}

    placeholders = ", ".join(f":n_{i}" for i in range(len(names)))
    params       = {f"n_{i}": name for i, name in enumerate(names)}

    rows = session.execute(
        text(f"""
            SELECT id, name, status
            FROM   tbl_organizations
            WHERE  CONVERT(name USING utf8mb4) COLLATE utf8mb4_unicode_ci
                   IN ({placeholders})
        """),
        params,
    ).mappings().all()

    result: dict[str, list[dict]] = {}
    for row in rows:
        result.setdefault(row["name"], []).append(dict(row))
    return result


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Enrich ACCME provider CSV with eMed org data")
    parser.add_argument(
        "--output",
        default=None,
        help="Output CSV path (default: accme_providers_enriched_<timestamp>.csv next to input)",
    )
    args = parser.parse_args()

    output_csv = Path(args.output) if args.output else SCRIPT_DIR / "accme_providers_enriched.csv"

    print(f"Input  : {INPUT_CSV}")
    print(f"Output : {output_csv}")

    providers = load_providers(INPUT_CSV)
    print(f"Providers loaded : {len(providers)}")

    names = [p["name"] for p in providers]

    print("Querying tbl_organizations ...")
    with get_session() as session:
        org_map = lookup_organizations(session, names)

    matched   = sum(1 for n in names if n in org_map)
    unmatched = len(names) - matched
    print(f"  Matched   : {matched}")
    print(f"  Unmatched : {unmatched}")

    # Warn on name collisions
    for name, rows in org_map.items():
        if len(rows) > 1:
            ids = [r["id"] for r in rows]
            print(f"  [warn] '{name}' matched {len(rows)} rows — ids: {ids}")

    # Write enriched CSV
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        fieldnames = list(providers[0].keys()) + [
            "eMed Provider ID",
            "eMed Provider Name",
            "eMed Provider Status",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for provider in providers:
            matches = org_map.get(provider["name"], [])
            writer.writerow({
                **provider,
                "eMed Provider ID"    : ",".join(str(r["id"])     for r in matches),
                "eMed Provider Name"  : ",".join(str(r["name"])   for r in matches),
                "eMed Provider Status": ",".join(str(r["status"]) for r in matches),
            })

    print(f"\nDone. Output written to:\n  {output_csv}")


if __name__ == "__main__":
    main()
