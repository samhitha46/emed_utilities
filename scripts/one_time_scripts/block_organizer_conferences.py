"""
One-time script: set status = 2 on conferences whose organizers are blocked.

Input  : blocked_organizer_conferences.csv  (same directory as this script)
         Required column: conference_id  (first column)

Action : UPDATE tbl_conferences
         SET    status        = 2,
                modified_by   = 64529,
                modified_date = <today>
         WHERE  id = <conference_id>
           AND  status != 2          -- skip rows already blocked

Safety features
---------------
  1. Dry-run by default  — pass --execute to write to the DB.
  2. Pre-flight SELECT   — fetches current status for every ID before touching anything.
                           Rows not found in DB or already status=2 are reported and skipped.
  3. Explicit confirmation prompt in --execute mode.
  4. Single transaction  — all UPDATEs committed together; any error rolls back everything.
  5. Audit log           — CSV written next to this script recording before/after state.

Usage
-----
  # Preview what WOULD be updated (no DB writes):
  python scripts/one_time_scripts/block_organizer_conferences.py

  # Actually execute (will prompt for confirmation):
  python scripts/one_time_scripts/block_organizer_conferences.py --execute
"""
import argparse
import csv
import sys
from datetime import date, datetime
from pathlib import Path

from sqlalchemy import text

# Allow running from any working directory
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from emed_utilities.db.connection import get_session

SCRIPT_DIR   = Path(__file__).parent
INPUT_CSV    = SCRIPT_DIR / "blocked_organizer_conferences.csv"
MODIFIED_BY  = 64529
NEW_STATUS   = 2
TODAY        = date.today()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_ids(csv_path: Path) -> list[tuple[int, str]]:
    """Return [(conference_id, title), ...] from the input CSV."""
    rows = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for lineno, row in enumerate(reader, start=2):   # line 1 = header
            raw = row.get("conference_id", "").strip()
            if not raw:
                print(f"  [warn] line {lineno}: empty conference_id — skipped")
                continue
            try:
                rows.append((int(raw), row.get("title", "").strip()))
            except ValueError:
                print(f"  [warn] line {lineno}: non-integer conference_id '{raw}' — skipped")
    return rows


def _preflight(session, ids: list[int]) -> tuple[list[dict], list[int], list[int]]:
    """
    SELECT current state for all IDs in one query.

    Returns:
        to_update   — list of dicts with current DB state, ready to be updated
        already_blocked — IDs already at status=2 (will be skipped)
        not_found   — IDs that do not exist in tbl_conferences
    """
    if not ids:
        return [], [], []

    placeholders = ", ".join(f":id_{i}" for i in range(len(ids)))
    params       = {f"id_{i}": v for i, v in enumerate(ids)}

    rows = session.execute(
        text(f"""
            SELECT id, title, status, modified_by, modified_date
            FROM   tbl_conferences
            WHERE  id IN ({placeholders})
        """),
        params,
    ).mappings().all()

    found_ids    = {r["id"] for r in rows}
    not_found    = [i for i in ids if i not in found_ids]
    already_blocked = [r["id"] for r in rows if r["status"] == NEW_STATUS]
    to_update    = [dict(r) for r in rows if r["status"] != NEW_STATUS]

    return to_update, already_blocked, not_found


def _write_audit_log(to_update: list[dict], dry_run: bool) -> Path:
    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    mode       = "dryrun" if dry_run else "executed"
    audit_path = SCRIPT_DIR / f"block_conferences_audit_{mode}_{timestamp}.csv"

    with open(audit_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "conference_id", "title",
            "status_before", "status_after",
            "modified_by_before", "modified_by_after",
            "modified_date_before", "modified_date_after",
            "action",
        ])
        action = "DRY_RUN" if dry_run else "UPDATED"
        for r in to_update:
            writer.writerow([
                r["id"], r.get("title", ""),
                r["status"], NEW_STATUS,
                r["modified_by"], MODIFIED_BY,
                r["modified_date"], TODAY,
                action,
            ])
    return audit_path


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Block conferences by organizer")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Write changes to the database. Without this flag the script runs in dry-run mode.",
    )
    args     = parser.parse_args()
    dry_run  = not args.execute

    print("=" * 65)
    print("Block Organizer Conferences")
    print(f"Mode        : {'*** DRY RUN — no DB writes ***' if dry_run else '*** EXECUTE — PRODUCTION DB ***'}")
    print(f"Input file  : {INPUT_CSV}")
    print(f"Modified by : {MODIFIED_BY}")
    print(f"Today       : {TODAY}")
    print("=" * 65)

    # ── Load CSV ──────────────────────────────────────────────────────────────
    if not INPUT_CSV.exists():
        print(f"\n[ERROR] Input file not found: {INPUT_CSV}")
        sys.exit(1)

    id_title_pairs = _load_ids(INPUT_CSV)
    if not id_title_pairs:
        print("\n[ERROR] No valid conference IDs found in the CSV.")
        sys.exit(1)

    all_ids = [cid for cid, _ in id_title_pairs]
    print(f"\nConference IDs read from CSV : {len(all_ids)}")

    # ── Pre-flight SELECT (read-only) ─────────────────────────────────────────
    print("\n[ Pre-flight ] Checking current state in tbl_conferences ...")
    with get_session() as session:
        to_update, already_blocked, not_found = _preflight(session, all_ids)

    print(f"  Will be updated   : {len(to_update)}")
    print(f"  Already status=2  : {len(already_blocked)}  (will be skipped)")
    print(f"  Not found in DB   : {len(not_found)}  (will be skipped)")

    if not_found:
        print(f"\n  [warn] IDs not found in tbl_conferences: {not_found}")

    if already_blocked:
        print(f"\n  [info] IDs already blocked (status=2): {already_blocked}")

    if not to_update:
        print("\nNothing to update — all rows are already blocked or not found. Exiting.")
        sys.exit(0)

    # ── Preview ───────────────────────────────────────────────────────────────
    print(f"\n{'─' * 65}")
    print(f"{'ID':<10} {'Current status':<16} {'Title (truncated)'}")
    print(f"{'─' * 65}")
    for r in to_update:
        title = (r.get("title") or "")[:45]
        print(f"  {r['id']:<8} {r['status']:<16} {title}")
    print(f"{'─' * 65}")

    # ── Audit log (always written, even in dry-run) ───────────────────────────
    audit_path = _write_audit_log(to_update, dry_run)
    print(f"\nAudit log written : {audit_path}")

    if dry_run:
        print("\nDry-run complete. No changes were made.")
        print("Re-run with --execute to apply updates to the production database.")
        sys.exit(0)

    # ── Confirmation prompt ───────────────────────────────────────────────────
    print(f"\n{'!' * 65}")
    print(f"  You are about to UPDATE {len(to_update)} rows in PRODUCTION.")
    print(f"  tbl_conferences  →  status=2, modified_by={MODIFIED_BY}, modified_date={TODAY}")
    print(f"{'!' * 65}")
    answer = input("\n  Type  YES  to proceed, anything else to abort: ").strip()
    if answer != "YES":
        print("Aborted. No changes were made.")
        sys.exit(0)

    # ── Execute UPDATEs in a single transaction ───────────────────────────────
    ids_to_update = [r["id"] for r in to_update]
    updated_count = 0
    failed_ids: list[int] = []

    print(f"\n[ Executing ] Updating {len(ids_to_update)} rows ...")
    with get_session() as session:
        for cid in ids_to_update:
            result = session.execute(
                text("""
                    UPDATE tbl_conferences
                    SET    status        = :status,
                           modified_by   = :modified_by,
                           modified_date = :modified_date
                    WHERE  id            = :id
                      AND  status        != :status
                """),
                {
                    "status"       : NEW_STATUS,
                    "modified_by"  : MODIFIED_BY,
                    "modified_date": TODAY,
                    "id"           : cid,
                },
            )
            if result.rowcount == 1:
                updated_count += 1
                print(f"  [OK] id={cid}")
            else:
                failed_ids.append(cid)
                print(f"  [!!] id={cid}  — rowcount={result.rowcount} (unexpected)")
        # session.commit() is called automatically by the context manager

    # ── Final report ─────────────────────────────────────────────────────────
    print(f"\n{'=' * 65}")
    print("RESULT")
    print(f"{'=' * 65}")
    print(f"  Successfully updated : {updated_count}")
    print(f"  Unexpected rowcount  : {len(failed_ids)}")
    if failed_ids:
        print(f"  Affected IDs        : {failed_ids}")
        print("  [warn] These IDs returned rowcount != 1. Verify manually.")
    print(f"  Audit log           : {audit_path}")
    print(f"{'=' * 65}")

    # Re-write the audit log now marked as executed
    _write_audit_log(to_update, dry_run=False)


if __name__ == "__main__":
    main()
