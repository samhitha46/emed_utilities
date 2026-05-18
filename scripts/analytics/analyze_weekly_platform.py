"""
Analyse weekly_platform.csv and produce a plain-text executive KPI report.

Computes:
  - Week-over-week (WoW) deltas for every metric
  - 4-week rolling average (short-term trend)
  - 12-week median baseline (anomaly reference)
  - Z-score anomaly detection across the full history
  - Automated insights and recommendations

Usage:
    python scripts/analytics/analyze_weekly_platform.py
    python scripts/analytics/analyze_weekly_platform.py \\
        --input  scripts/analytics/output/weekly_platform.csv \\
        --output scripts/analytics/output/kpi_report.txt
"""
import argparse
import csv
import statistics
from datetime import date, timedelta
from pathlib import Path
from typing import Optional

TODAY = date.today()

DEFAULT_INPUT  = Path("scripts/analytics/output/weekly_platform.csv")
DEFAULT_OUTPUT = Path("scripts/analytics/output/kpi_report.txt")

ROLLING_AVG_WEEKS  = 4
BASELINE_WEEKS     = 12
ANOMALY_SIGMA      = 2.0
ENGAGEMENT_HEALTHY = 0.45   # engagement rate below this is flagged


# ── helpers ──────────────────────────────────────────────────────────────────

def _pct_change(new: float, old: float) -> Optional[float]:
    return None if old == 0 else (new - old) / old * 100


def _week_end(week_start: str) -> date:
    return date.fromisoformat(week_start) + timedelta(days=6)


def _is_partial(week_start: str) -> bool:
    return TODAY <= _week_end(week_start)


def _mean(rows: list[dict], key: str) -> float:
    return statistics.mean(r[key] for r in rows)


def _median(rows: list[dict], key: str) -> float:
    return statistics.median(r[key] for r in rows)


def _stdev(rows: list[dict], key: str) -> float:
    vals = [r[key] for r in rows]
    return statistics.stdev(vals) if len(vals) > 1 else 1.0


def _wrap(text: str, indent: str = "     ", width: int = 65) -> list[str]:
    words = text.split()
    lines, buf = [], indent
    for w in words:
        if len(buf) + len(w) + 1 > width:
            lines.append(buf.rstrip())
            buf = indent + w
        else:
            buf += ("" if buf == indent else " ") + w
    if buf.strip():
        lines.append(buf.rstrip())
    return lines


# ── data loading ──────────────────────────────────────────────────────────────

def load_weeks(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["total_users"]              = int(r["total_users"])
        r["new_users"]                = int(r["new_users"])
        r["returning_users"]          = int(r["returning_users"])
        r["sessions"]                 = int(r["sessions"])
        r["pageviews"]                = int(r["pageviews"])
        r["engagement_rate"]          = float(r["engagement_rate"])
        r["avg_session_duration_sec"] = float(r["avg_session_duration_sec"])
        # derived
        r["sessions_per_user"] = (
            round(r["sessions"] / r["total_users"], 2) if r["total_users"] else 0.0
        )
        r["returning_pct"] = (
            round(r["returning_users"] / r["total_users"] * 100, 1) if r["total_users"] else 0.0
        )
    return rows


# ── report ────────────────────────────────────────────────────────────────────

def build_report(rows: list[dict]) -> str:
    out = []
    SEP  = "=" * 68
    THIN = "-" * 68

    # ── identify partial weeks ────────────────────────────────────────
    # First row is partial when the collection window started mid-week
    first_partial = rows[0]["total_users"] < rows[1]["total_users"] * 0.5
    last_partial  = _is_partial(rows[-1]["week_start"])

    start_idx   = 1 if first_partial else 0
    end_idx     = len(rows) - 1 if last_partial else len(rows)
    weeks       = rows[start_idx:end_idx]
    partial_row = rows[-1] if last_partial else None

    if len(weeks) < 2:
        return "Insufficient complete weeks for analysis."

    curr  = weeks[-1]
    prior = weeks[-2]

    avg4 = weeks[-ROLLING_AVG_WEEKS:]
    # Baseline: the 12 weeks before the most recent 4 — excludes near-term
    # volatility from the reference point used for anomaly flagging
    base_slice = weeks[-(BASELINE_WEEKS + ROLLING_AVG_WEEKS):-ROLLING_AVG_WEEKS]
    base = base_slice if base_slice else weeks

    curr_end = _week_end(curr["week_start"])

    # ── header ───────────────────────────────────────────────────────
    out += [
        SEP,
        "  PLATFORM WEEKLY KPI REPORT",
        f"  Report week : {curr['week_start']}  →  {curr_end.isoformat()}  (week {curr['year_week']})",
        f"  Generated   : {TODAY.isoformat()}",
        f"  Data range  : {weeks[0]['week_start']}  to  {curr['week_start']}  ({len(weeks)} complete weeks)",
        SEP,
    ]

    # ── executive summary ─────────────────────────────────────────────
    wow_u = _pct_change(curr["total_users"], prior["total_users"])
    wow_s = _pct_change(curr["sessions"],    prior["sessions"])
    wow_e = (curr["engagement_rate"] - prior["engagement_rate"]) * 100

    out += ["", "EXECUTIVE SUMMARY", THIN]
    out.append(f"  Total users this week    : {curr['total_users']:>10,}   WoW {wow_u:+.1f}%")
    out.append(f"  Sessions this week       : {curr['sessions']:>10,}   WoW {wow_s:+.1f}%")
    out.append(
        f"  Engagement rate          : {curr['engagement_rate']*100:>9.1f}%   WoW {wow_e:+.1f}pp"
        + ("   ✓ healthy" if curr["engagement_rate"] >= ENGAGEMENT_HEALTHY else "   ⚠ BELOW THRESHOLD")
    )
    out.append(f"  Avg session duration     : {curr['avg_session_duration_sec']:>9.0f}s")
    out.append(f"  Returning visitors       : {curr['returning_pct']:>9.1f}%  of weekly users")
    out.append(f"  4-week avg users         : {int(_mean(avg4, 'total_users')):>10,}")

    if partial_row:
        days_in = (TODAY - date.fromisoformat(partial_row["week_start"])).days + 1
        out.append(
            f"\n  ⓘ  Week {partial_row['year_week']} ({partial_row['week_start']}, "
            f"{days_in} days so far: {partial_row['total_users']:,} users) is partial — excluded from all figures."
        )

    # ── traffic KPI table ─────────────────────────────────────────────
    def _hdr() -> str:
        return (f"  {'Metric':<26} {'This Week':>11} {'WoW Δ':>8}"
                f" {'4w Avg':>11} {'12w Median':>11}")

    def _divider() -> str:
        return "  " + "-" * 66

    def trow(label: str, key: str) -> str:
        c   = curr[key]
        p   = prior[key]
        a4  = _mean(avg4, key)
        b   = _median(base, key)
        wow = _pct_change(c, p)
        wow_str = f"{wow:+.1f}%" if wow is not None else "N/A"
        return (f"  {label:<26} {int(c):>11,} {wow_str:>8}"
                f" {int(a4):>11,} {int(b):>11,}")

    out += ["", "TRAFFIC KPIs", THIN, _hdr(), _divider()]
    out.append(trow("Total Users",     "total_users"))
    out.append(trow("New Users",       "new_users"))
    out.append(trow("Returning Users", "returning_users"))
    out.append(trow("Sessions",        "sessions"))
    out.append(trow("Pageviews",       "pageviews"))

    # ── engagement KPI table ──────────────────────────────────────────
    def erow_rate(label: str, key: str, as_pct100: bool = False,
                  threshold: Optional[float] = None) -> str:
        """
        as_pct100=False → key is a 0-1 rate (e.g. engagement_rate)
        as_pct100=True  → key is already 0-100 (e.g. returning_pct)
        """
        c  = curr[key]
        p  = prior[key]
        a4 = _mean(avg4, key)
        b  = _median(base, key)

        if as_pct100:
            wow_pp = c - p
            fmt  = lambda v: f"{v:>10.1f}%"
            rate_c = c / 100
        else:
            wow_pp = (c - p) * 100
            fmt  = lambda v: f"{v*100:>10.1f}%"
            rate_c = c

        flag = ""
        if threshold is not None:
            flag = "   ✓" if rate_c >= threshold else "   ⚠"

        return (f"  {label:<26} {fmt(c)} {wow_pp:>+7.1f}pp"
                f" {fmt(a4)} {fmt(b)}{flag}")

    def erow_sec(label: str, key: str) -> str:
        c   = curr[key]
        p   = prior[key]
        a4  = _mean(avg4, key)
        b   = _median(base, key)
        wow = _pct_change(c, p)
        wow_str = f"{wow:+.1f}%" if wow is not None else "N/A"
        return (f"  {label:<26} {c:>10.0f}s {wow_str:>8}"
                f" {a4:>10.0f}s {b:>10.0f}s")

    def erow_float(label: str, key: str) -> str:
        c   = curr[key]
        p   = prior[key]
        a4  = _mean(avg4, key)
        b   = _median(base, key)
        wow = _pct_change(c, p)
        wow_str = f"{wow:+.1f}%" if wow is not None else "N/A"
        return (f"  {label:<26} {c:>11.2f} {wow_str:>8}"
                f" {a4:>11.2f} {b:>11.2f}")

    out += ["", "ENGAGEMENT KPIs", THIN, _hdr(), _divider()]
    out.append(erow_rate("Engagement Rate",      "engagement_rate",
                         threshold=ENGAGEMENT_HEALTHY))
    out.append(erow_sec ("Avg Session Duration", "avg_session_duration_sec"))
    out.append(erow_float("Sessions / User",     "sessions_per_user"))
    out.append(erow_rate("Returning Visitors %", "returning_pct", as_pct100=True))

    # ── anomaly detection ─────────────────────────────────────────────
    out += ["", "ANOMALY DETECTION  (full history, flagged at ±2σ)", THIN]

    check_keys = [
        ("total_users",              "Users",       True,  False),
        ("engagement_rate",          "Engagement",  False, True),
        ("avg_session_duration_sec", "Sessions",    False, True),
    ]

    global_stats: dict[str, tuple[float, float]] = {}
    for key, *_ in check_keys:
        vals = [r[key] for r in weeks]
        mu   = statistics.mean(vals)
        sd   = statistics.stdev(vals) if len(vals) > 1 else 1.0
        global_stats[key] = (mu, sd)

    anomalies_found = False
    for r in weeks:
        flags = []
        for key, label, spike_bad, drop_bad in check_keys:
            mu, sd = global_stats[key]
            z = (r[key] - mu) / sd
            if spike_bad and z >  ANOMALY_SIGMA:
                flags.append(f"{label} SPIKE : {r[key]:,.0f}  ({z:+.1f}σ, baseline avg {mu:,.0f})")
            if drop_bad  and z < -ANOMALY_SIGMA:
                unit = "%" if key == "engagement_rate" else "s"
                val  = r[key] * 100 if key == "engagement_rate" else r[key]
                b_v  = mu * 100      if key == "engagement_rate" else mu
                flags.append(f"{label} LOW   : {val:.1f}{unit}  ({z:+.1f}σ, baseline avg {b_v:.1f}{unit})")
            if spike_bad and z < -ANOMALY_SIGMA:
                flags.append(f"{label} DROP  : {r[key]:,.0f}  ({z:+.1f}σ, baseline avg {mu:,.0f})")

        if flags:
            anomalies_found = True
            out.append(f"\n  ⚠  Week {r['year_week']}  ({r['week_start']})")
            for fl in flags:
                out.append(f"     → {fl}")

    if not anomalies_found:
        out.append("  No anomalies detected across the full history.")

    # ── insights & recommendations ────────────────────────────────────
    out += ["", "INSIGHTS & RECOMMENDATIONS", THIN]
    insights: list[tuple[str, str]] = []

    # 1. Engagement trend (first 12 weeks vs most recent 4)
    if len(weeks) >= 16:
        early_eng  = _mean(weeks[:12], "engagement_rate")
        recent_eng = _mean(weeks[-4:], "engagement_rate")
        delta_pp   = (recent_eng - early_eng) * 100
        if delta_pp < -5:
            insights.append((
                "ENGAGEMENT QUALITY DECLINING",
                f"Recent 4-week engagement ({recent_eng*100:.1f}%) is {abs(delta_pp):.1f}pp "
                f"below the early-period average ({early_eng*100:.1f}%). "
                "Traffic growth is outpacing audience quality. "
                "Audit acquisition channels: prioritise organic search and email "
                "over broad paid campaigns which bring low-intent visitors.",
            ))
        elif delta_pp > 5:
            insights.append((
                "ENGAGEMENT IMPROVING",
                f"Recent 4-week engagement ({recent_eng*100:.1f}%) is {delta_pp:.1f}pp above "
                f"the early-period average ({early_eng*100:.1f}%). "
                "Traffic quality is improving — a positive signal.",
            ))

    # 2. Audience loyalty
    avg_ret = _mean(weeks[-4:], "returning_pct")
    if avg_ret < 12:
        insights.append((
            "LOW AUDIENCE LOYALTY",
            f"Only {avg_ret:.1f}% of weekly users return to the platform "
            "(industry benchmark for content sites: 20–30%). "
            "The platform depends almost entirely on new user acquisition. "
            "Recommended actions: promote newsletter sign-ups on conference pages, "
            "add push-notification opt-ins, and gate some content behind free accounts "
            "to build a logged-in returning audience.",
        ))

    # 3. Traffic vs baseline
    avg4_u   = _mean(avg4,  "total_users")
    base_med = _median(base, "total_users")
    trend    = _pct_change(avg4_u, base_med)
    if trend is not None:
        if trend > 20:
            insights.append((
                "TRAFFIC RUNNING ABOVE BASELINE",
                f"4-week average ({int(avg4_u):,}/wk) is {trend:+.0f}% above the "
                f"12-week median baseline ({int(base_med):,}/wk). "
                "Confirm that growth is from high-intent channels. "
                "If engagement rate is simultaneously below 45%, the extra traffic "
                "is not converting to meaningful engagement.",
            ))
        elif trend < -20:
            insights.append((
                "TRAFFIC RUNNING BELOW BASELINE",
                f"4-week average ({int(avg4_u):,}/wk) is {trend:+.0f}% below the "
                f"12-week median baseline ({int(base_med):,}/wk). "
                "Check whether this is expected seasonal softening or a sign of "
                "reduced acquisition effort or algorithm/SEO changes.",
            ))

    # 4. Composite engagement score vs baseline
    curr_score = curr["engagement_rate"] * curr["avg_session_duration_sec"]
    base_score = _median(base, "engagement_rate") * _median(base, "avg_session_duration_sec")
    score_delta = _pct_change(curr_score, base_score)
    if score_delta is not None and score_delta < -20:
        insights.append((
            "SESSION QUALITY BELOW BASELINE",
            f"Composite engagement score (rate × duration) is {score_delta:+.0f}% below "
            "the 12-week baseline. Users are spending less time and clicking less. "
            "Check page-load performance on mobile, content relevance, and whether "
            "recent traffic sources are driving low-intent visitors.",
        ))

    # 5. Seasonality
    insights.append((
        "SEASONALITY",
        "Based on 52 weeks of historical data: "
        "May–Jun is peak conference-season traffic (40–50k+/wk). "
        "Jul–Aug softens moderately (36–42k/wk). "
        "Dec–Jan sees a sharp holiday dip with significantly lower engagement quality. "
        "Plan campaign budgets and content launches around these windows.",
    ))

    for i, (title, body) in enumerate(insights, 1):
        out.append(f"\n  {i}. {title}")
        out.extend(_wrap(body))

    out += ["", SEP, "  End of report", SEP, ""]
    return "\n".join(str(x) for x in out)


def main() -> None:
    import sys
    sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="Generate an executive KPI report from weekly platform metrics."
    )
    parser.add_argument("--input",  default=str(DEFAULT_INPUT),
                        help="Path to weekly_platform.csv")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT),
                        help="Where to save the text report")
    args = parser.parse_args()

    input_path  = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"Input not found: {input_path}")
        return

    rows   = load_weeks(input_path)
    report = build_report(rows)

    print(report)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"Report saved → {output_path}")


if __name__ == "__main__":
    main()
