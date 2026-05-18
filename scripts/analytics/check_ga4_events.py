"""
Read-only GA4 event audit: checks which events from the eMedEvents
Analytics Framework are currently firing vs missing.

Queries the last 28 days of GA4 event data and cross-references against
the full required event list from the framework document.

Usage:
    python scripts/analytics/check_ga4_events.py
    python scripts/analytics/check_ga4_events.py --days 90
"""
import argparse
import sys
from datetime import date

sys.stdout.reconfigure(encoding="utf-8")

from google.analytics.data_v1beta import BetaAnalyticsDataClient
from google.analytics.data_v1beta.types import DateRange, Dimension, Metric, RunReportRequest
from google.oauth2 import service_account

from emed_utilities.config import get_settings

# ── Required events from the framework document ───────────────────────────────

REQUIRED_EVENTS = {
    # HCP — Acquisition & Registration
    "hcp_registration_start":    ("HCP", "Acquisition",   False),
    "hcp_registration_complete": ("HCP", "Acquisition",   True),   # conversion
    "hcp_login":                 ("HCP", "Acquisition",   False),
    "hcp_profile_complete":      ("HCP", "Acquisition",   False),
    # HCP — Discovery & Search
    "search_performed":          ("HCP", "Discovery",     False),
    "search_result_clicked":     ("HCP", "Discovery",     False),
    "listing_viewed":            ("HCP", "Discovery",     False),
    "listing_saved":             ("HCP", "Discovery",     False),
    "filter_applied":            ("HCP", "Discovery",     False),
    # HCP — Registration & Transaction
    "registration_initiated":    ("HCP", "Transaction",   False),
    "registration_step_completed":("HCP","Transaction",   False),
    "registration_completed":    ("HCP", "Transaction",   True),   # conversion — critical
    "registration_abandoned":    ("HCP", "Transaction",   False),
    "i_am_interested_clicked":   ("HCP", "Transaction",   True),   # conversion
    # Provider / Organizer
    "provider_signup_complete":  ("Provider", "Signup",   True),   # conversion
    "listing_creation_start":    ("Provider", "Listing",  False),
    "listing_step_completed":    ("Provider", "Listing",  False),
    "listing_submitted":         ("Provider", "Listing",  False),
    "listing_published":         ("Provider", "Listing",  True),   # conversion
    "listing_creation_abandoned":("Provider", "Listing",  False),
    "ticketing_agreement_signed":("Provider", "Commerce", True),   # conversion
    "provider_portal_login":     ("Provider", "Engagement",False),
}

CONVERSION_EVENTS = {k for k, (_, _, is_conv) in REQUIRED_EVENTS.items() if is_conv}


def _get_client() -> BetaAnalyticsDataClient:
    settings = get_settings()
    creds = service_account.Credentials.from_service_account_file(
        settings.ga4_credentials_file,
        scopes=["https://www.googleapis.com/auth/analytics.readonly"],
    )
    return BetaAnalyticsDataClient(credentials=creds)


def fetch_all_events(days: int) -> dict[str, int]:
    """Return {event_name: event_count} for all events in the last N days."""
    settings = get_settings()
    client   = _get_client()

    request = RunReportRequest(
        property=f"properties/{settings.ga4_property_id}",
        date_ranges=[DateRange(start_date=f"{days}daysAgo", end_date="yesterday")],
        dimensions=[Dimension(name="eventName")],
        metrics=[Metric(name="eventCount")],
        limit=500,
    )
    response = client.run_report(request)
    return {
        row.dimension_values[0].value: int(row.metric_values[0].value)
        for row in response.rows
    }


def build_report(live_events: dict[str, int], days: int) -> str:
    out = []
    SEP  = "=" * 70
    THIN = "-" * 70
    today = date.today()

    out += [
        SEP,
        "  GA4 EVENT AUDIT — eMedEvents Analytics Framework",
        f"  Property   : {get_settings().ga4_property_id}",
        f"  Period     : last {days} days  (up to {today.isoformat()})",
        f"  Live events found in GA4 : {len(live_events)}",
        SEP,
    ]

    # ── Section 1: Required events status ────────────────────────────
    out += ["", "REQUIRED EVENTS — STATUS", THIN]
    hdr = f"  {'Event Name':<34} {'Side':<10} {'Group':<12} {'Conv?':<6} {'Status':<10} {'28d Count':>10}"
    out.append(hdr)
    out.append("  " + "-" * 68)

    present   = {}
    missing   = {}
    conv_missing = []

    for event, (side, group, is_conv) in REQUIRED_EVENTS.items():
        count = live_events.get(event)
        conv_mark = "YES" if is_conv else "-"
        if count is not None:
            present[event] = count
            status = "FIRING"
            count_str = f"{count:,}"
        else:
            missing[event] = (side, group, is_conv)
            status = "MISSING"
            count_str = "-"
            if is_conv:
                conv_missing.append(event)

        out.append(
            f"  {event:<34} {side:<10} {group:<12} {conv_mark:<6} {status:<10} {count_str:>10}"
        )

    # ── Section 2: Summary counts ─────────────────────────────────────
    out += ["", "SUMMARY", THIN]
    out.append(f"  Required events total     : {len(REQUIRED_EVENTS)}")
    out.append(f"  Currently firing          : {len(present)}  ({len(present)/len(REQUIRED_EVENTS)*100:.0f}%)")
    out.append(f"  Missing                   : {len(missing)}  ({len(missing)/len(REQUIRED_EVENTS)*100:.0f}%)")
    out.append(f"  Conversion events missing : {len(conv_missing)}")

    # ── Section 3: Missing events grouped ────────────────────────────
    if missing:
        out += ["", "MISSING EVENTS — DETAIL", THIN]

        # group by side
        by_side: dict[str, list[str]] = {}
        for event, (side, group, is_conv) in missing.items():
            by_side.setdefault(side, []).append((event, group, is_conv))

        for side, items in by_side.items():
            out.append(f"\n  {side} events:")
            for event, group, is_conv in items:
                conv_tag = "  ← CONVERSION EVENT" if is_conv else ""
                out.append(f"    ✗  {event:<38} [{group}]{conv_tag}")

    # ── Section 4: Events firing but NOT in framework ─────────────────
    extra = {k: v for k, v in live_events.items() if k not in REQUIRED_EVENTS}
    # filter out GA4 auto-collected events to reduce noise
    ga4_auto = {
        "session_start", "first_visit", "page_view", "scroll", "click",
        "file_download", "video_start", "video_progress", "video_complete",
        "view_search_results", "user_engagement", "form_start", "form_submit",
    }
    custom_extra = {k: v for k, v in extra.items() if k not in ga4_auto}
    auto_present = {k: v for k, v in extra.items() if k in ga4_auto}

    out += ["", "AUTO-COLLECTED EVENTS (GA4 built-in — no action needed)", THIN]
    if auto_present:
        for event, count in sorted(auto_present.items(), key=lambda x: -x[1]):
            out.append(f"  ✓  {event:<38} {count:>10,}")
    else:
        out.append("  None detected.")

    out += ["", "CUSTOM EVENTS IN GA4 NOT IN FRAMEWORK (possible renames / legacy)", THIN]
    if custom_extra:
        for event, count in sorted(custom_extra.items(), key=lambda x: -x[1]):
            out.append(f"  ?  {event:<38} {count:>10,}")
        out.append(
            "\n  Review: if any of these are renamed versions of required events,\n"
            "  align the event name with the framework or update the framework."
        )
    else:
        out.append("  None detected.")

    # ── Section 5: Action plan ────────────────────────────────────────
    out += ["", "ACTION PLAN", THIN]

    out.append("\n  IMMEDIATE (GA4 Admin UI — no Engineering needed):")
    if conv_missing:
        out.append("  Once events start firing, mark these as conversions in")
        out.append("  Admin → Events → toggle 'Mark as conversion':")
        for e in conv_missing:
            out.append(f"    • {e}")
    else:
        out.append("  All conversion events are firing — mark them in GA4 Admin if")
        out.append("  not already done.")

    out.append("\n  ENGINEERING — implement and fire these events from the application:")
    hcp_missing   = [(e, g) for e, (s, g, _) in missing.items() if s == "HCP"]
    prov_missing  = [(e, g) for e, (s, g, _) in missing.items() if s == "Provider"]

    if hcp_missing:
        out.append("  HCP-side:")
        for e, g in hcp_missing:
            out.append(f"    • {e}  [{g}]")
    if prov_missing:
        out.append("  Provider-side:")
        for e, g in prov_missing:
            out.append(f"    • {e}  [{g}]")

    if not missing:
        out.append("  All required events are firing — no Engineering work outstanding.")

    out.append("\n  PIPELINE — these report sections are BLOCKED until events fire:")
    blocked = []
    if "registration_completed"   not in present: blocked.append("Revenue & Transactions")
    if "hcp_registration_complete" not in present: blocked.append("New HCP registrations")
    if "listing_viewed"           not in present: blocked.append("Funnel (listing view rate)")
    if "registration_initiated"   not in present: blocked.append("Funnel (registration initiation rate)")
    if "i_am_interested_clicked"  not in present: blocked.append("I Am Interested rate (free listings)")
    if "listing_published"        not in present: blocked.append("Supply — new listings published")
    if "search_performed"         not in present: blocked.append("Search-to-listing click rate")

    if blocked:
        for b in blocked:
            out.append(f"    ✗  {b}")
    else:
        out.append("  No blocked sections — all required events are firing.")

    out += ["", SEP, "  End of audit", SEP, ""]
    return "\n".join(out)


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit GA4 events against framework requirements.")
    parser.add_argument("--days", type=int, default=28, help="Look-back window in days (default: 28)")
    args = parser.parse_args()

    print(f"Querying GA4 for last {args.days} days of event data...")
    live_events = fetch_all_events(args.days)
    print(f"Found {len(live_events)} distinct event names in GA4.\n")

    report = build_report(live_events, args.days)
    print(report)


if __name__ == "__main__":
    main()
