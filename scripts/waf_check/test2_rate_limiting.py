"""
WAF Check — Test 2: Rate Limiting
===================================
WHAT WE ARE TESTING
-------------------
Test 1 checks *who* is asking. Test 2 checks *how many times* they ask.

A real human visitor loads a page once or twice. A scraper hammers the
same URL hundreds or thousands of times in rapid succession. Rate limiting
is the WAF layer that detects and blocks this pattern regardless of how
legitimate the User-Agent looks.

We send requests in concurrent batches using a real browser User-Agent
(the same one that passed Test 1 undetected) and watch for the WAF to
return HTTP 429 (Too Many Requests), 403 (Forbidden), or 503.

WHY IT MATTERS
--------------
Without rate limiting, an attacker who knows to change their User-Agent
can scrape the entire site without any further obstacles. Rate limiting
acts as a volume cap — even a legitimate-looking client gets blocked
once it exceeds a threshold.

The test reports *at which request number* a block was triggered, so the
tech team can see exactly where the threshold sits (or confirm that none
exists).

Usage:
    python scripts/waf_check/test2_rate_limiting.py
    python scripts/waf_check/test2_rate_limiting.py --total 200 --concurrency 50
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from common import BASE_URL, BROWSER_HEADERS, CheckResult, Report, is_blocked, green

URL = f"{BASE_URL}/medical-conferences"


def run(report: Report, total: int = 100, concurrency: int = 20) -> None:
    print(f"  Target      : {URL}")
    print(f"  User-Agent  : real Chrome browser (same as Test 1 bypass)")
    print(f"  Plan        : {total} total requests, {concurrency} at a time\n")
    print(f"  {'Batch':<8} {'Sent so far':<14} {'Status codes seen'}")
    print(f"  {'-' * 55}")

    results:    dict[int, int] = {}
    blocked_at: int | None     = None
    sent = 0

    def _fetch(n: int) -> tuple[int, int]:
        try:
            r = requests.get(URL, headers=BROWSER_HEADERS, timeout=10)
            return n, r.status_code
        except Exception:
            return n, 0

    batch_num = 0
    while sent < total and blocked_at is None:
        batch_size = min(concurrency, total - sent)
        batch_num += 1

        with ThreadPoolExecutor(max_workers=batch_size) as ex:
            futures = {ex.submit(_fetch, sent + i): sent + i for i in range(batch_size)}
            for future in as_completed(futures):
                _, status = future.result()
                results[status] = results.get(status, 0) + 1
                if status in (403, 429, 503):
                    blocked_at = sent + 1

        sent += batch_size
        status_summary = "  ".join(f"HTTP {k}: {v}" for k, v in sorted(results.items()))
        row = f"  {batch_num:<8} {sent:<14} {status_summary}"
        print(green(row))

        if blocked_at:
            break

    if blocked_at:
        detail = (
            f"WAF rate-limit triggered around request #{blocked_at} of {total} "
            f"({concurrency} concurrent). Threshold is somewhere below {blocked_at} requests."
        )
    else:
        detail = (
            f"Sent all {sent} requests ({concurrency} concurrent) with no block. "
            f"Status codes: {dict(results)}. "
            f"Rate limiting is either not configured or threshold exceeds {total} requests."
        )

    report.add(CheckResult(
        name=f"Rate limiting ({total} requests, {concurrency} concurrent)",
        passed=blocked_at is not None,
        status_code=max(results, key=results.get) if results else 0,
        detail=detail,
    ))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--total",       type=int, default=100, help="Total requests to send (default: 100)")
    parser.add_argument("--concurrency", type=int, default=20,  help="Concurrent requests per batch (default: 20)")
    args = parser.parse_args()

    print("=" * 60)
    print("Test 2 — Rate Limiting")
    print("If a client looks like a real browser but sends hundreds")
    print("of requests in seconds, does the WAF step in?")
    print("=" * 60 + "\n")

    report = Report()
    run(report, total=args.total, concurrency=args.concurrency)
    report.summary()
    report.write_log("test2_rate_limiting")


if __name__ == "__main__":
    main()
