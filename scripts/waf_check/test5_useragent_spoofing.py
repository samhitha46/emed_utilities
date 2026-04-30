"""
F-01 Proof Test: Can a bad actor bypass the WAF by spoofing a trusted bot User-Agent?

The WAF has a rule (Allow_Trusted_Bots) that permits known good crawlers like
Googlebot and UptimeRobot. If that rule matches on User-Agent alone — without
verifying the request looks like a real browser — any attacker who sets
User-Agent: googlebot gets a free pass.

Two escalating tests are run in sequence:

  Test A — Bare UA only
      Sends ONLY the User-Agent with no other headers.
      A real browser always sends Accept, Accept-Language, Accept-Encoding etc.
      This is the laziest possible spoof — if this passes, the WAF is very weak.

  Test B — Sophisticated full-header spoof
      Sends the full Googlebot User-Agent string alongside realistic browser
      headers (Accept, Accept-Language, Accept-Encoding, Connection).
      This is a more convincing impersonation that a competent attacker would use.
      If Test A is blocked but Test B passes, the WAF checks headers but not IP.

Result interpretation:
  HTTP 200  →  WAF is matching on User-Agent string alone — EXPLOITABLE
  Non-200   →  WAF requires more than just the matching string — rule is tighter

Usage:
    python scripts/waf_check/test5_useragent_spoofing.py
    python scripts/waf_check/test5_useragent_spoofing.py --no-wait
"""
import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from common import BASE_URL, green, red, yellow

TARGET_URL = f"{BASE_URL}/medical-conferences"

SPOOF_AGENTS = [
    ("Minimal Googlebot spoof",    "googlebot"),
    ("Minimal Bingbot spoof",      "bingbot"),
    ("Minimal GPTBot spoof",       "gptbot"),
    ("Minimal UptimeRobot spoof",  "uptimerobot"),
    ("Minimal Facebookbot spoof",  "facebookexternalhit"),
    ("Minimal Twitterbot spoof",   "twitterbot"),
]


def main() -> None:
    parser = argparse.ArgumentParser(description="F-01 User-Agent spoofing proof test")
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Skip the 120-second rate-limit cooldown (use if you know the window is clear)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("F-01 Proof Test — User-Agent Spoofing")
    print("Can a bare spoofed UA bypass the WAF's trusted-bot rule?")
    print("=" * 60)
    print(f"Target  : {TARGET_URL}")
    print(f"Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    if not args.no_wait:
        print(yellow("Waiting 120 seconds to clear any active rate-limit window..."))
        print(yellow("(Skip with --no-wait if the window is already clear)"))
        for remaining in range(120, 0, -10):
            print(yellow(f"  {remaining}s remaining..."))
            time.sleep(10)
        print()

    print(f"  {'Agent label':<30} {'UA sent':<25} {'HTTP':<6} {'Result'}")
    print(f"  {'-' * 75}")

    exploitable_count = 0

    for label, ua in SPOOF_AGENTS:
        try:
            # Deliberately send ONLY the User-Agent — no Accept, Accept-Language,
            # Accept-Encoding, or any other header a real browser would include.
            resp = requests.get(
                TARGET_URL,
                headers={"User-Agent": ua},
                timeout=10,
            )

            if resp.status_code == 200:
                exploitable_count += 1
                result = red("ALLOWED — F-01 EXPLOITABLE")
            elif resp.status_code in (403, 429, 503):
                result = green(f"Blocked ({resp.status_code})")
            else:
                result = yellow(f"Unexpected ({resp.status_code})")

            ua_display = ua if len(ua) <= 22 else ua[:22] + "..."
            row = f"  {label:<30} {ua_display:<25} {resp.status_code:<6} {result}"
            print(row)

        except Exception as e:
            print(red(f"  {label:<30} {'ERROR':<25} {'---':<6} {e}"))

        time.sleep(5)

    print(f"\n{'=' * 60}")
    if exploitable_count:
        print(red(f"  Test A: F-01 CONFIRMED — {exploitable_count}/{len(SPOOF_AGENTS)} bare spoofed UAs allowed"))
        print(red("  The WAF's trusted-bot rule matches on User-Agent string alone."))
        print(red("  A bad actor can bypass WAF simply by setting User-Agent: googlebot"))
    else:
        print(green(f"  Test A: all {len(SPOOF_AGENTS)} bare spoofed UAs were blocked"))
        print(green("  The WAF requires more than just a matching User-Agent string."))
    print(f"{'=' * 60}")

    # ── Test B: Sophisticated full-header spoof ───────────────────────────────
    print()
    print("=" * 60)
    print("Test B — Sophisticated full-header Googlebot spoof")
    print("Sends the full UA string + realistic browser headers")
    print("=" * 60)
    time.sleep(5)

    sophisticated_headers = {
        "User-Agent"     : "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Accept"         : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection"     : "keep-alive",
    }

    print("  Headers sent:")
    for k, v in sophisticated_headers.items():
        print(f"    {k}: {v}")
    print()

    try:
        resp = requests.get(TARGET_URL, headers=sophisticated_headers, timeout=10)
        print(f"  Status: {resp.status_code}")

        if resp.status_code == 200:
            print(red("  ALLOWED — sophisticated spoof bypassed the WAF"))
            print(red("  WAF does not verify Googlebot identity beyond UA string and headers."))
            print(red("  A competent attacker can impersonate Googlebot to scrape freely."))
        elif resp.status_code in (403, 429, 503):
            print(green(f"  Blocked ({resp.status_code}) — WAF detected spoof despite full headers"))  # noqa: E501
            if exploitable_count == 0:
                print(green(
                    "  Both tests blocked — WAF appears to verify bot identity "
                    "beyond UA/headers (e.g. IP range)."
                ))
        else:
            print(yellow(f"  Unexpected status {resp.status_code}"))
    except Exception as e:
        print(red(f"  Request failed: {e}"))

    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
