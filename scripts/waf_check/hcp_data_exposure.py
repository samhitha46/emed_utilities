"""
Probes emedevents.com for exposed HCP (Healthcare Professional) data.

Starts with the Speaker Bureau (/healthcare-speakers) — a paginated public
listing — and uses the same Next.js /_next/data/ technique proven in check_waf.py
to pull structured JSON records without authentication.

Usage:
    # Probe Speaker Bureau only (default 10 pages)
    python scripts/waf_check/hcp_data_exposure.py

    # Increase page depth
    python scripts/waf_check/hcp_data_exposure.py --max-pages 50
"""
import argparse
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import requests
from bs4 import BeautifulSoup

BASE_URL = "https://www.emedevents.com"

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

# Fields that would indicate PII / sensitive data is exposed
SENSITIVE_MARKERS = {"email", "phone", "mobile", "contact", "address", "dob", "npi", "license", "fax"}


@dataclass
class Finding:
    label: str
    value: str
    is_sensitive: bool = False


@dataclass
class ProbeResult:
    name: str
    exposed: bool
    findings: list[Finding] = field(default_factory=list)
    records_sample: list[dict] = field(default_factory=list)


def _is_blocked(response: requests.Response) -> bool:
    if response.status_code in (403, 429, 503):
        return True
    body = response.text.lower()
    return any(k in body for k in ["access denied", "blocked", "captcha", "cloudflare", "ray id"])


def _find_list_in_props(props: dict) -> tuple[list, str]:
    """Walk up to two levels into a pageProps dict to find the primary record list."""
    for k, v in props.items():
        if isinstance(v, list) and len(v) > 0 and isinstance(v[0], dict):
            return v, k
    for k, v in props.items():
        if isinstance(v, dict):
            for k2, v2 in v.items():
                if isinstance(v2, list) and len(v2) > 0 and isinstance(v2[0], dict):
                    return v2, f"{k}.{k2}"
    return [], ""


def _find_count_in_props(props: dict) -> int | None:
    """Look for an integer total-count scalar anywhere in pageProps."""
    for k, v in props.items():
        if isinstance(v, int) and "count" in k.lower():
            return v
        if isinstance(v, dict):
            for k2, v2 in v.items():
                if isinstance(v2, int) and "count" in k2.lower():
                    return v2
    return None


def _sensitive_fields(record: dict) -> list[str]:
    return [f for f in record if any(m in f.lower() for m in SENSITIVE_MARKERS)]


def _extract_build_id(session: requests.Session, url: str) -> tuple[str, str, dict]:
    """Fetch a page and return (build_id, next_page_path, page_props)."""
    resp = session.get(url, headers=BROWSER_HEADERS, timeout=15)
    if _is_blocked(resp):
        return "", "", {}
    soup = BeautifulSoup(resp.text, "html.parser")
    tag  = soup.find("script", {"id": "__NEXT_DATA__"})
    if not tag:
        return "", "", {}
    data = json.loads(tag.string)
    props = data.get("props", {}).get("pageProps", {})
    return data.get("buildId", ""), data.get("page", ""), props


def probe_speaker_bureau(session: requests.Session, max_pages: int) -> ProbeResult:
    """Probe /healthcare-speakers via the Next.js JSON endpoint."""
    result = ProbeResult(name="Speaker Bureau (/healthcare-speakers)", exposed=False)
    page_url = f"{BASE_URL}/healthcare-speakers"

    print(f"  Fetching {page_url}...")
    build_id, page_path, inline_props = _extract_build_id(session, page_url)

    if not build_id:
        print("  Could not extract build ID — page may be blocked or not Next.js")
        result.findings.append(Finding("build_id", "not found"))
        return result

    print(f"  Build ID : {build_id}")
    print(f"  Page     : {page_path}")
    result.findings.append(Finding("build_id", build_id))
    result.findings.append(Finding("next_page_path", page_path))

    # Show what is already pre-rendered in the HTML
    inline_list, inline_key = _find_list_in_props(inline_props)
    if inline_list:
        print(f"  Pre-rendered HTML already contains '{inline_key}': {len(inline_list)} records")
        result.findings.append(Finding(
            "pre_rendered_records",
            f"'{inline_key}' — {len(inline_list)} records already in HTML source",
        ))

    # Probe the /_next/data/ JSON endpoint
    json_url = f"{BASE_URL}/_next/data/{build_id}/healthcare-speakers.json"
    print(f"\n  Probing JSON endpoint: {json_url}")
    json_resp = session.get(json_url, headers=BROWSER_HEADERS, timeout=15)
    print(f"  Response: HTTP {json_resp.status_code} — {len(json_resp.content) / 1024:.1f} KB")

    if _is_blocked(json_resp):
        print("  WAF blocked the /_next/data/ endpoint")
        result.findings.append(Finding("json_endpoint", "BLOCKED by WAF", is_sensitive=False))
        return result

    if json_resp.status_code != 200:
        result.findings.append(Finding("json_endpoint", f"HTTP {json_resp.status_code}"))
        return result

    try:
        page_props = json_resp.json().get("pageProps", {})
    except Exception:
        result.findings.append(Finding("json_endpoint", "non-JSON response"))
        return result

    result.exposed = True
    result.findings.append(Finding(
        "json_endpoint",
        f"HTTP 200, {len(json_resp.content)/1024:.1f} KB, no auth required — {json_url}",
        is_sensitive=True,
    ))

    # Locate the speaker list and analyse fields
    speaker_list, speaker_key = _find_list_in_props(page_props)
    total_count = _find_count_in_props(page_props)

    if not speaker_list:
        print("  No speaker list found in page-1 response — data may be fetched client-side")
        result.findings.append(Finding("speaker_list", "not found in /_next/data/ response"))
        return result

    record_fields  = list(speaker_list[0].keys())
    sensitive      = _sensitive_fields(speaker_list[0])
    result.records_sample = speaker_list[:3]

    result.findings.append(Finding(
        "speaker_list_key", speaker_key,
    ))
    result.findings.append(Finding(
        "records_per_page", str(len(speaker_list)),
    ))
    result.findings.append(Finding(
        "record_fields", str(record_fields),
    ))
    if total_count is not None:
        result.findings.append(Finding("total_count_from_api", str(total_count)))
    if sensitive:
        result.findings.append(Finding(
            "sensitive_fields_in_record", str(sensitive), is_sensitive=True,
        ))

    # Paginate to confirm bulk access
    total_scraped  = len(speaker_list)
    pages_fetched  = 1
    blocked_on_page: int | None = None

    print(f"\n  Paginating up to {max_pages} pages...")
    print(f"  {'Page':<6} {'HTTP':<6} {'Records':<10} {'KB':<8} {'Cumulative'}")
    print(f"  {'-'*45}")
    print(f"  {'1':<6} {'200':<6} {len(speaker_list):<10} {len(json_resp.content)/1024:<8.1f} {total_scraped}")

    for page_num in range(2, max_pages + 1):
        paged_resp = session.get(
            json_url,
            params={"page": page_num},
            headers=BROWSER_HEADERS,
            timeout=15,
        )
        if _is_blocked(paged_resp):
            blocked_on_page = page_num
            print(f"  {page_num:<6} {'BLOCKED':<6}")
            break
        try:
            paged_props = paged_resp.json().get("pageProps", {})
            paged_list, _ = _find_list_in_props(paged_props)
            total_scraped += len(paged_list)
            pages_fetched += 1
            print(f"  {page_num:<6} {paged_resp.status_code:<6} {len(paged_list):<10} {len(paged_resp.content)/1024:<8.1f} {total_scraped}")
            if not paged_list:
                print("  (empty page — reached end of listing)")
                break
        except Exception:
            print(f"  {page_num:<6} parse error")
            break
        time.sleep(0.3)

    result.findings.append(Finding(
        "pagination",
        f"{total_scraped} records scraped across {pages_fetched} pages"
        + (f" — WAF blocked at page {blocked_on_page}" if blocked_on_page else " — no block detected"),
        is_sensitive=blocked_on_page is None,
    ))

    return result


def _print_summary(results: list[ProbeResult]) -> None:
    print("\n" + "=" * 60)
    print("HCP DATA EXPOSURE — SUMMARY")
    print("=" * 60)

    for result in results:
        status = "EXPOSED" if result.exposed else "NOT EXPOSED / BLOCKED"
        print(f"\n  [{status}] {result.name}")
        for f in result.findings:
            marker = "[!!]" if f.is_sensitive else "[i] "
            print(f"    {marker} {f.label}: {f.value}")

        if result.records_sample:
            print(f"\n  Sample record (first result):")
            sample = result.records_sample[0]
            for k, v in sample.items():
                is_pii = any(m in k.lower() for m in SENSITIVE_MARKERS)
                tag    = " ← PII?" if is_pii else ""
                display = str(v)[:100] if v is not None else "null"
                print(f"      {k:<30}: {display}{tag}")

    print("\n" + "=" * 60)


def _write_report(results: list[ProbeResult]) -> None:
    logs_dir = Path(__file__).parent.parent.parent / "logs"
    logs_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path  = logs_dir / f"hcp_exposure_{timestamp}.log"

    with open(log_path, "w", encoding="utf-8") as f:
        f.write(f"HCP Data Exposure Report — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Target: {BASE_URL}\n\n")
        for result in results:
            status = "EXPOSED" if result.exposed else "NOT EXPOSED"
            f.write(f"[{status}] {result.name}\n")
            for finding in result.findings:
                f.write(f"  {'[SENSITIVE]' if finding.is_sensitive else '[info]    '} {finding.label}: {finding.value}\n")
            if result.records_sample:
                f.write(f"\n  Sample record:\n")
                for k, v in result.records_sample[0].items():
                    f.write(f"    {k}: {v}\n")
            f.write("\n")

    print(f"\nReport saved to: {log_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Probe emedevents.com for exposed HCP data")
    parser.add_argument("--max-pages", type=int, default=10, help="Max pages to paginate per probe (default: 10)")
    args = parser.parse_args()

    print(f"\nHCP Data Exposure Check — {BASE_URL}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    session = requests.Session()
    results: list[ProbeResult] = []

    print("[ Probe 1 ] Speaker Bureau")
    results.append(probe_speaker_bureau(session, max_pages=args.max_pages))

    _print_summary(results)
    _write_report(results)


if __name__ == "__main__":
    main()
