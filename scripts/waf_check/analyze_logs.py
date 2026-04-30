"""
analyze_logs.py — Query S3 WAF logs to find which rule terminated F-01 test requests.

The WAF ships logs via Kinesis Firehose → S3 bucket (emed-elb-logs, us-west-2).
Each object is a gzip file of newline-delimited JSON records.

This script:
  1. Detects your current external IP via api.ipify.org.
  2. Lists recent log objects in the bucket.
  3. Downloads and scans each object for records matching your IP + /medical-conferences URI.
  4. Prints per-request detail: terminating rule, Bot Control labels, User-Agent.
  5. Gives an F-01 verdict: did Bot Control catch the spoofed UAs, or were they ALLOWED?

Usage:
    python scripts/waf_check/analyze_logs.py
    python scripts/waf_check/analyze_logs.py --hours 2 --prefix AWSLogs/
    python scripts/waf_check/analyze_logs.py --ip 1.2.3.4   # override IP detection
"""
import argparse
import gzip
import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3
import requests as req_lib

sys.path.insert(0, str(Path(__file__).parent))
from common import green, red, yellow

BUCKET      = "emed-elb-logs"
REGION      = "us-west-2"
TARGET_URI  = "/medical-conferences"


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_my_ip() -> str:
    try:
        ip = req_lib.get("https://api.ipify.org", timeout=5).text.strip()
        print(f"  Detected external IP : {ip}")
        return ip
    except Exception as e:
        print(yellow(f"  Could not detect external IP: {e}"))
        return ""


def list_recent_objects(s3, prefix: str, hours: int) -> list[dict]:
    """Return S3 object summaries modified within the last `hours` hours."""
    cutoff = datetime.now(tz=timezone.utc).timestamp() - hours * 3600
    paginator = s3.get_paginator("list_objects_v2")
    objects   = []
    for page in paginator.paginate(Bucket=BUCKET, Prefix=prefix):
        for obj in page.get("Contents", []):
            if obj["LastModified"].timestamp() >= cutoff:
                objects.append(obj)
    objects.sort(key=lambda o: o["LastModified"])
    return objects


def stream_records(s3, key: str):
    """Yield parsed JSON records from a gzip WAF log object."""
    body = s3.get_object(Bucket=BUCKET, Key=key)["Body"].read()
    with gzip.open(io.BytesIO(body)) as gz:
        for raw_line in gz:
            line = raw_line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def extract_terminating_rule(record: dict) -> str:
    return record.get("terminatingRuleId", "—")


def extract_bot_labels(record: dict) -> list[str]:
    labels = record.get("labels", [])
    return [lbl["name"] for lbl in labels if "botcontrol" in lbl.get("name", "").lower()]


def extract_sub_rule(record: dict) -> str:
    """Walk ruleGroupList to find the Bot Control group and its matching rule."""
    for group in record.get("ruleGroupList", []):
        group_id = group.get("ruleGroupId", "")
        if "BotControl" not in group_id and "botcontrol" not in group_id.lower():
            continue
        for rule in group.get("nonTerminatingMatchingRules", []) + [
            group.get("terminatingRule") or {}
        ]:
            rid = rule.get("ruleId", "")
            if rid:
                return f"{group_id} / {rid}"
    return "—"


def extract_user_agent(record: dict) -> str:
    for header in record.get("httpRequest", {}).get("headers", []):
        if header.get("name", "").lower() == "user-agent":
            return header.get("value", "")
    return "—"


def format_ts(ms: int) -> str:
    try:
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%H:%M:%S UTC")
    except Exception:
        return str(ms)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Scan S3 WAF logs for F-01 test requests")
    parser.add_argument("--hours",  type=float, default=1.0,    help="How many hours back to scan (default: 1)")
    parser.add_argument("--prefix", default="",                  help="S3 key prefix to narrow the search")
    parser.add_argument("--ip",     default="",                  help="Override external IP detection")
    args = parser.parse_args()

    print("=" * 65)
    print("WAF Log Analyzer — F-01 User-Agent Spoofing Investigation")
    print("=" * 65)
    print(f"Bucket  : {BUCKET}  ({REGION})")
    print(f"Window  : last {args.hours}h")
    print(f"URI     : {TARGET_URI}")
    print()

    my_ip = args.ip.strip() or get_my_ip()
    if not my_ip:
        print(red("  No IP to filter on. Pass --ip <your-ip> manually."))
        sys.exit(1)

    s3 = boto3.client("s3", region_name=REGION)

    print(f"\n  Listing objects in s3://{BUCKET}/{args.prefix} ...")
    objects = list_recent_objects(s3, args.prefix, args.hours)
    print(f"  Found {len(objects)} object(s) in the last {args.hours}h")

    if not objects:
        print(yellow("\n  No log objects found in the time window. Try --hours 3 or check the prefix."))
        sys.exit(0)

    matching_records: list[dict] = []

    for obj in objects:
        key = obj["Key"]
        print(f"  Scanning {key} ...", end="\r")
        try:
            for record in stream_records(s3, key):
                ip_in_log  = record.get("httpRequest", {}).get("clientIp", "")
                uri_in_log = record.get("httpRequest", {}).get("uri", "")
                if ip_in_log == my_ip and TARGET_URI in uri_in_log:
                    matching_records.append(record)
        except Exception as e:
            print(yellow(f"\n  [skip] {key}: {e}"))

    print(" " * 80, end="\r")   # clear the \r line

    print(f"\n  Matched {len(matching_records)} record(s) for IP={my_ip} URI~={TARGET_URI}\n")

    if not matching_records:
        print(yellow("  No matching records found."))
        print(yellow("  Either the test ran outside the scan window, or the IP changed."))
        print(yellow("  Try --hours 3 or --ip <ip-at-test-time>"))
        sys.exit(0)

    # ── Per-request table ─────────────────────────────────────────────────────
    print(f"  {'Time':<12} {'Action':<8} {'Terminating Rule':<35} {'User-Agent (truncated)'}")
    print(f"  {'-' * 95}")

    allowed_count = 0
    blocked_count = 0

    for rec in matching_records:
        ts       = format_ts(rec.get("timestamp", 0))
        action   = rec.get("action", "—")
        term_rule = extract_terminating_rule(rec)
        ua        = extract_user_agent(rec)[:50]
        sub_rule  = extract_sub_rule(rec)
        bot_labels = extract_bot_labels(rec)

        if action == "ALLOW":
            allowed_count += 1
            action_str = red("ALLOW")
        elif action in ("BLOCK", "CAPTCHA", "CHALLENGE"):
            blocked_count += 1
            action_str = green(action)
        else:
            action_str = yellow(action)

        print(f"  {ts:<12} {action_str:<8} {term_rule:<35} {ua}")
        if sub_rule != "—":
            print(f"  {'':12} {'':8} Sub-rule : {sub_rule}")
        if bot_labels:
            print(f"  {'':12} {'':8} Bot labels: {', '.join(bot_labels)}")
        print()

    # ── F-01 Verdict ──────────────────────────────────────────────────────────
    print("=" * 65)
    print("F-01 VERDICT")
    print("=" * 65)
    total = allowed_count + blocked_count

    if allowed_count > 0 and blocked_count == 0:
        print(red(f"  EXPLOITABLE — all {allowed_count}/{total} spoofed-UA requests were ALLOWED"))
        print(red("  The Allow_Trusted_Bots rule matched on User-Agent string alone."))
        print(red("  No Bot Control label or IP-range check stopped the requests."))
    elif allowed_count == 0 and blocked_count > 0:
        print(green(f"  PROTECTED — all {blocked_count}/{total} spoofed-UA requests were BLOCKED"))
        print(green("  Bot Control or another rule caught the spoof."))
    elif allowed_count > 0:
        print(yellow(f"  MIXED — {allowed_count} ALLOWED, {blocked_count} BLOCKED out of {total} requests"))
        print(yellow("  Some spoofed UAs slipped through. Review the per-request table above."))
    else:
        print(yellow(f"  {total} record(s) found but none were ALLOW or BLOCK — check action values above."))

    print("=" * 65)


if __name__ == "__main__":
    main()
