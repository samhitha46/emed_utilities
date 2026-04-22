"""
Probes emedevents.com for exposed HCP (Healthcare Professional) data.

Works through three surfaces in sequence:

  Probe 1 — Speaker Bureau listing (/healthcare-speakers)
            Uses the Next.js /_next/data/ technique to pull structured JSON
            records without authentication and paginate through the full list.

  Probe 2 — Individual speaker profile pages (/healthcare-speakers/<slug>)
            Fetches the profile page for the first speaker found in Probe 1
            and inspects what fields are exposed (bio, contact, email, etc.).

  Probe 3 — newdev.emedevents.com Speaker API
            Directly calls /Speaker/speakerList, /Speaker/searchSpeaker, and
            /Speaker/getSpeakerDetail with realistic POST bodies to determine
            whether email, phone, NPI, or any contact data is returned.

Usage:
    python scripts/waf_check/hcp_data_exposure.py
    python scripts/waf_check/hcp_data_exposure.py --max-pages 50
"""
import argparse
import csv
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parent))
from common import BASE_URL, BROWSER_HEADERS, green, red, yellow, is_blocked

# Fields that would indicate PII / sensitive data is exposed
SENSITIVE_MARKERS = {"email", "phone", "mobile", "contact", "address", "dob", "npi", "license", "fax"}


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class Finding:
    label: str
    value: str
    is_sensitive: bool = False


@dataclass
class ProbeResult:
    name: str
    exposed: bool
    # "exposed" = PII/data returned with no auth
    # "public_no_pii" = page is publicly accessible but no sensitive fields found
    # "protected" = blocked or data not returned
    status: str = "protected"
    findings: list[Finding] = field(default_factory=list)
    records_sample: list[dict] = field(default_factory=list)


# ── Shared helpers ────────────────────────────────────────────────────────────

def _find_list_in_props(props: dict) -> tuple[list, str]:
    """Walk up to two levels into pageProps to find the primary record list."""
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


def _extract_next_data(session: requests.Session, url: str) -> tuple[str, str, dict]:
    """Fetch a page and return (build_id, page_path, page_props)."""
    resp = session.get(url, headers=BROWSER_HEADERS, timeout=15)
    if is_blocked(resp):
        return "", "", {}
    soup = BeautifulSoup(resp.text, "html.parser")
    tag  = soup.find("script", {"id": "__NEXT_DATA__"})
    if not tag:
        return "", "", {}
    data  = json.loads(tag.string)
    props = data.get("props", {}).get("pageProps", {})
    return data.get("buildId", ""), data.get("page", ""), props


def _describe_record(record: dict) -> None:
    """Print all fields of a record, flagging PII candidates."""
    for k, v in record.items():
        is_pii  = any(m in k.lower() for m in SENSITIVE_MARKERS)
        display = str(v)[:120] if v is not None else "null"
        tag     = red(" ← PII") if is_pii else ""
        print(f"      {k:<32}: {display}{tag}")


# ── Probe 1: Speaker Bureau listing ──────────────────────────────────────────

def probe_speaker_bureau(session: requests.Session, max_pages: int) -> tuple[ProbeResult, list[dict], str]:
    """
    Probe 1 — two-step approach:

    Step A: /_next/data/ JSON endpoint — reveals the trending speakers list
            embedded server-side (same 90 records regardless of page param).

    Step B: Playwright intercept — loads the page in a real browser, clicks
            through pages, and intercepts the actual backend API call that
            powers the paginated speaker listing. This is where the full
            HCP database is accessible.
    """
    result      = ProbeResult(name="Speaker Bureau (/healthcare-speakers)", exposed=False, status="protected")
    page_url    = f"{BASE_URL}/healthcare-speakers"
    all_records: list[dict] = []

    print(f"  Fetching {page_url}...")
    build_id, page_path, inline_props = _extract_next_data(session, page_url)

    if not build_id:
        print(red("  Could not extract build ID — page may be blocked or not Next.js"))
        result.findings.append(Finding("build_id", "not found"))
        return result, all_records, ""

    print(f"  Build ID : {build_id}")
    print(f"  Page     : {page_path}")
    result.findings.append(Finding("build_id", build_id))
    result.findings.append(Finding("page_path", page_path))

    # ── Step A: /_next/data/ (trending speakers embedded in HTML) ─────────────
    inline_list, inline_key = _find_list_in_props(inline_props)
    if inline_list:
        print(green(f"  Pre-rendered HTML contains '{inline_key}': {len(inline_list)} records (trending list)"))
        result.findings.append(Finding(
            "pre_rendered_records",
            f"'{inline_key}' — {len(inline_list)} trending speakers already in HTML source",
            is_sensitive=True,
        ))

    json_url = f"{BASE_URL}/_next/data/{build_id}/healthcare-speakers.json"
    print(f"\n  Step A — Probing /_next/data/ JSON endpoint: {json_url}")
    json_resp = session.get(json_url, headers=BROWSER_HEADERS, timeout=15)
    print(f"  Response: HTTP {json_resp.status_code} — {len(json_resp.content) / 1024:.1f} KB")

    if is_blocked(json_resp):
        print(red("  WAF blocked the /_next/data/ endpoint"))
        result.findings.append(Finding("json_endpoint", "BLOCKED by WAF"))
    elif json_resp.status_code == 200:
        try:
            page_props    = json_resp.json().get("pageProps", {})
            speaker_list, speaker_key = _find_list_in_props(page_props)
            if speaker_list:
                result.exposed = True
                result.status  = "exposed"
                record_fields  = list(speaker_list[0].keys())
                sensitive      = _sensitive_fields(speaker_list[0])
                result.records_sample = speaker_list[:3]
                all_records.extend(speaker_list)
                print(green(f"  Trending speakers exposed: {len(speaker_list)} records, fields: {record_fields}"))
                result.findings.append(Finding(
                    "trending_list_endpoint",
                    f"HTTP 200 — {len(json_resp.content)/1024:.1f} KB, {len(speaker_list)} records, no auth. "
                    f"NOTE: /_next/data/ returns the same trending 90 regardless of ?page= param.",
                    is_sensitive=True,
                ))
                result.findings.append(Finding("record_fields", str(record_fields)))
                if sensitive:
                    result.findings.append(Finding("sensitive_fields", str(sensitive), is_sensitive=True))
        except Exception:
            pass

    # ── Step B: Playwright — intercept the real paginated API ─────────────────
    print(f"\n  Step B — Launching headless browser to intercept the real pagination API...")
    try:
        from playwright.sync_api import sync_playwright

        intercepted_endpoints: list[dict] = []

        def on_response(response):
            url = response.url
            if any(url.endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".svg", ".ico", ".woff2"]):
                return
            if any(k in url.lower() for k in ["speaker", "hcp", "search", "list", "json", "_next/data"]):
                try:
                    ct = response.headers.get("content-type", "")
                    if "json" in ct:
                        body = response.json()
                        records, key = _find_list_in_props(body) if isinstance(body, dict) else (body if isinstance(body, list) else [], "root")
                        if records and isinstance(records[0], dict) and len(records) > 1:
                            intercepted_endpoints.append({
                                "url":     url,
                                "count":   len(records),
                                "key":     key,
                                "fields":  list(records[0].keys()),
                                "records": records,
                            })
                except Exception:
                    pass

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(user_agent=BROWSER_HEADERS["User-Agent"], locale="en-US")
            page    = context.new_page()
            page.on("response", on_response)

            print(f"  Loading {page_url}...")
            page.goto(page_url, wait_until="networkidle", timeout=30000)
            page.wait_for_timeout(2000)

            # Click page 2 to trigger the real paginated API call
            print("  Clicking page 2 to trigger pagination API...")
            try:
                page.click("a[aria-label='2'], .pagination a:text('2'), li:nth-child(3) a", timeout=5000)
                page.wait_for_load_state("networkidle", timeout=15000)
                page.wait_for_timeout(2000)
            except Exception:
                # Fallback: navigate directly to page 2
                page.goto(f"{page_url}?page=2", wait_until="networkidle", timeout=20000)

            context.close()
            browser.close()

        if intercepted_endpoints:
            # Deduplicate by base URL
            seen = set()
            for ep in intercepted_endpoints:
                base = ep["url"].split("?")[0]
                if base in seen:
                    continue
                seen.add(base)
                result.exposed = True
                result.status  = "exposed"
                print(green(f"\n  *** REAL SPEAKER API FOUND ***"))
                print(green(f"  URL    : {ep['url']}"))
                print(green(f"  Records: {ep['count']} per page"))
                print(green(f"  Fields : {ep['fields']}"))
                sensitive = _sensitive_fields(ep["records"][0])
                if sensitive:
                    print(red(f"  [!!] SENSITIVE FIELDS: {sensitive}"))
                    for sf in sensitive:
                        print(red(f"       '{sf}': {str(ep['records'][0].get(sf, ''))[:100]}"))
                    result.findings.append(Finding(
                        "real_pagination_api_sensitive", str(sensitive), is_sensitive=True,
                    ))
                result.findings.append(Finding(
                    "real_pagination_api",
                    f"{ep['url']} — {ep['count']} records/page, fields: {ep['fields']}",
                    is_sensitive=True,
                ))
                all_records.extend(ep["records"])

            # Now paginate the real API up to max_pages
            if intercepted_endpoints:
                real_ep = intercepted_endpoints[0]
                real_url = real_ep["url"].split("?")[0]
                print(f"\n  Paginating real API up to {max_pages} pages...")
                print(f"  {'Page':<6} {'HTTP':<6} {'Records':<10} {'KB':<8} {'Cumulative'}")
                print(f"  {'-' * 45}")
                print(green(f"  {'1':<6} {'200':<6} {real_ep['count']:<10} {'?':<8} {len(all_records)}"))

                blocked_on_page = None
                for page_num in range(2, max_pages + 1):
                    paged_resp = session.post(
                        real_url,
                        json={"pageno": page_num - 1, "limit": 12, "request_type": "normallist"},
                        headers={**BROWSER_HEADERS, "Content-Type": "application/json", "Accept": "application/json"},
                        timeout=15,
                    )
                    if is_blocked(paged_resp):
                        blocked_on_page = page_num
                        print(red(f"  {page_num:<6} BLOCKED — WAF triggered"))
                        break
                    try:
                        body = paged_resp.json()
                        paged_list, _ = _find_list_in_props(body) if isinstance(body, dict) else (body, "root")
                        if not paged_list:
                            print(yellow(f"  {page_num:<6} {paged_resp.status_code:<6} empty — end of listing"))
                            break
                        all_records.extend(paged_list)
                        kb  = len(paged_resp.content) / 1024
                        row = f"  {page_num:<6} {paged_resp.status_code:<6} {len(paged_list):<10} {kb:<8.1f} {len(all_records)}"
                        print(green(row))
                    except Exception:
                        print(red(f"  {page_num:<6} parse error"))
                        break
                    time.sleep(0.3)

                result.findings.append(Finding(
                    "pagination",
                    f"{len(all_records)} total records scraped across {min(page_num, max_pages)} pages"
                    + (f" — WAF blocked at page {blocked_on_page}" if blocked_on_page else " — no block"),
                    is_sensitive=blocked_on_page is None,
                ))
        else:
            print(yellow("  No speaker API intercepted via Playwright (may be same-origin XHR or WebSocket)"))
            result.findings.append(Finding(
                "real_pagination_api", "not intercepted — may require deeper browser interaction",
            ))

    except ImportError:
        print(yellow("  Playwright not installed — skipping Step B"))
        print("  Run: pip install playwright && playwright install chromium")

    return result, all_records, build_id


# ── Probe 2: Individual speaker profile page ──────────────────────────────────

def probe_speaker_profile(session: requests.Session, sample_records: list[dict], build_id: str) -> ProbeResult:
    """
    Fetch individual speaker profile pages and inspect what fields are exposed
    beyond the listing (bio, contact details, email, phone etc.).

    Profile URL pattern: /speaker-profile/<user_url>
    e.g. https://www.emedevents.com/speaker-profile/frank-j-domino
    """
    result = ProbeResult(
        name="Individual speaker profile page (/speaker-profile/<slug>)",
        exposed=False,
        status="protected",
    )

    # user_url is the slug used in the profile URL
    slug = ""
    for record in sample_records:
        val = record.get("user_url", "").strip("/")
        if val:
            slug = val
            break

    if not slug:
        print(yellow("  Could not find 'user_url' in listing records — skipping"))
        result.findings.append(Finding("profile_url", "user_url field missing from listing records"))
        return result

    profile_url = f"{BASE_URL}/speaker-profile/{slug}"
    print(f"  Fetching profile page: {profile_url}")

    build_id_profile, page_path, inline_props = _extract_next_data(session, profile_url)
    used_build_id = build_id_profile or build_id

    if not used_build_id:
        print(red("  Could not extract build ID from profile page"))
        result.findings.append(Finding("profile_page", "blocked or not Next.js"))
        return result

    print(f"  Build ID : {used_build_id}")
    result.findings.append(Finding("profile_url", profile_url))
    result.findings.append(Finding(
        "page_access",
        "publicly accessible without authentication — page loads for any anonymous user",
    ))

    # Check what's pre-rendered in the HTML
    pii_found = False
    if inline_props:
        print(f"\n  Pre-rendered pageProps keys: {list(inline_props.keys())}")

        # Inspect the 'data' key — this is the full speaker profile object
        data_obj = inline_props.get("data")
        if data_obj and isinstance(data_obj, dict):
            print(f"\n  ── 'data' key (full speaker profile record) ────────────────")
            for k, v in data_obj.items():
                is_pii  = any(m in k.lower() for m in SENSITIVE_MARKERS)
                display = str(v)[:120] if v is not None else "null"
                tag     = red(" ← PII") if is_pii else ""
                print(f"    {k:<35}: {display}{tag}")
            pii_keys = [k for k in data_obj if any(m in k.lower() for m in SENSITIVE_MARKERS)]
            if pii_keys:
                pii_found = True
                print(red(f"\n  [!!] PII FIELDS in profile data: {pii_keys}"))
                result.findings.append(Finding(
                    "pii_in_profile_data",
                    str({k: str(data_obj[k])[:80] for k in pii_keys}),
                    is_sensitive=True,
                ))
            else:
                print(yellow("  No email/phone/NPI fields in profile data — fields are intentionally public"))
            result.findings.append(Finding("profile_data_fields", str(list(data_obj.keys()))))
        elif data_obj is None:
            print(yellow("  'data' key is null — profile data may be loaded via a separate API call"))
            result.findings.append(Finding("profile_data", "null in pre-rendered HTML — loaded client-side"))

        top_sensitive = _sensitive_fields(inline_props)
        if top_sensitive:
            pii_found = True
            for sf in top_sensitive:
                print(red(f"  [!!] PII field in HTML source — '{sf}': {str(inline_props.get(sf, ''))[:80]}"))
            result.findings.append(Finding("pii_in_html", str(top_sensitive), is_sensitive=True))

    # Probe the /_next/data/ JSON endpoint for the profile
    json_url = f"{BASE_URL}/_next/data/{used_build_id}/speaker-profile/{slug}.json"
    print(f"\n  Probing profile JSON endpoint: {json_url}")
    json_resp = session.get(json_url, headers=BROWSER_HEADERS, timeout=15)
    print(f"  Response: HTTP {json_resp.status_code} — {len(json_resp.content) / 1024:.1f} KB")

    if is_blocked(json_resp):
        print(red("  WAF blocked the profile JSON endpoint"))
        result.findings.append(Finding("profile_json_endpoint", "BLOCKED by WAF"))
    elif json_resp.status_code == 200:
        result.findings.append(Finding(
            "profile_json_endpoint",
            f"HTTP 200 — {len(json_resp.content)/1024:.1f} KB with no auth",
            is_sensitive=True,
        ))
        try:
            page_props = json_resp.json().get("pageProps", {})
            def _flatten(obj: dict, prefix: str = "") -> dict:
                flat = {}
                for k, v in obj.items():
                    full_key = f"{prefix}.{k}" if prefix else k
                    if isinstance(v, dict):
                        flat.update(_flatten(v, full_key))
                    elif not isinstance(v, list):
                        flat[full_key] = v
                return flat
            flat_props = _flatten(page_props)
            sensitive  = {k: v for k, v in flat_props.items() if any(m in k.lower() for m in SENSITIVE_MARKERS)}
            if sensitive:
                pii_found = True
                print(red(f"\n  [!!] SENSITIVE FIELDS FOUND ({len(sensitive)}):"))
                for k, v in sensitive.items():
                    print(red(f"       {k:<35}: {str(v)[:100]}"))
                result.findings.append(Finding("sensitive_fields", str(list(sensitive.keys())), is_sensitive=True))
                result.records_sample = [{"field": k, "value": str(v)[:200]} for k, v in sensitive.items()]
        except Exception:
            pass
    else:
        result.findings.append(Finding("profile_json_endpoint", f"HTTP {json_resp.status_code}"))

    # Set final status based on whether PII was found
    if pii_found:
        result.exposed = True
        result.status  = "exposed"
    else:
        result.status = "public_no_pii"
        result.findings.append(Finding(
            "conclusion",
            "page is publicly accessible but exposes only intentionally public fields "
            "(name, specialty, location, bio, conference history) — no email, phone, or NPI",
        ))

    return result


# ── Probe 3: Speaker search endpoint ─────────────────────────────────────────

_NEWDEV = "https://newdev.emedevents.com"

# Headers that mirror what the browser sends to the newdev backend
_NEWDEV_HEADERS = {
    **BROWSER_HEADERS,
    "Content-Type"     : "application/json",
    "Accept"           : "application/json, text/plain, */*",
    "Referer"          : f"{BASE_URL}/",
    "emedauthorization": "undefined",
    "trackinguid"      : "",
    "referrerurl"      : "",
    "clickedurl"       : f"{BASE_URL}/healthcare-speakers",
}


def _print_raw_body(resp: requests.Response, label: str) -> None:
    """Print the full response body (JSON pretty-printed or raw text, capped at 4 KB)."""
    try:
        body = resp.json()
        text = json.dumps(body, indent=2)
    except Exception:
        text = resp.text
    cap = 4000
    if len(text) > cap:
        text = text[:cap] + f"\n  ... [{len(text) - cap} more chars truncated]"
    print(f"  ── {label} response body ──")
    for line in text.splitlines():
        print(f"    {line}")


def _analyse_response(
    resp: requests.Response,
    endpoint_label: str,
    result: ProbeResult,
) -> list[dict]:
    """Parse the response, flag PII, return any records found."""
    records_found: list[dict] = []
    try:
        body = resp.json()
    except Exception:
        print(yellow(f"  Non-JSON response from {endpoint_label}"))
        return records_found

    if isinstance(body, list):
        candidate = body
        key = "root"
    elif isinstance(body, dict):
        candidate, key = _find_list_in_props(body)
    else:
        candidate, key = [], ""

    if candidate and isinstance(candidate[0], dict):
        records_found = candidate
        fields    = list(candidate[0].keys())
        sensitive = _sensitive_fields(candidate[0])
        print(green(f"  Records found   : {len(candidate)}  (key: '{key}')"))
        print(f"  Fields          : {fields}")
        result.exposed = True
        result.status  = "exposed"
        result.findings.append(Finding(
            "search_endpoint",
            f"{endpoint_label} — HTTP 200, {len(candidate)} records, fields: {fields}",
            is_sensitive=True,
        ))
        if sensitive:
            print(red(f"  [!!] SENSITIVE FIELDS: {sensitive}"))
            for sf in sensitive:
                print(red(f"       '{sf}': {str(candidate[0].get(sf, ''))[:120]}"))
            result.findings.append(Finding(
                "sensitive_fields_in_search", str(sensitive), is_sensitive=True,
            ))
        else:
            print(yellow("  No email/phone/contact fields in this response"))
            result.findings.append(Finding("sensitive_fields_in_search", f"none in {endpoint_label}"))
    else:
        # No list found — print the raw body so we can see what came back
        _print_raw_body(resp, endpoint_label)

    return records_found


def probe_speaker_search(
    session: requests.Session,
    build_id: str,
    sample_records: list[dict] | None = None,
) -> ProbeResult:
    """
    Directly call the newdev.emedevents.com Speaker API endpoints with realistic
    POST bodies (same pattern as the conference API) and inspect raw responses
    for email, phone, NPI, or any contact data beyond the public profile fields.

    Three targets:
      1. /Speaker/speakerList   — paginated speaker directory
      2. /Speaker/searchSpeaker — keyword search (e.g. by name or specialty)
      3. /Speaker/getSpeakerDetail — single-speaker lookup by user_url / id
    """
    result = ProbeResult(name="Speaker search / newdev.emedevents.com API", exposed=False)

    # Pull a real user_url slug from Probe 1 records if available
    slug = ""
    if sample_records:
        for rec in sample_records:
            val = rec.get("user_url", "").strip("/")
            if val:
                slug = val
                break
    if not slug:
        slug = "frank-j-domino"  # known-good slug from earlier runs

    # ── 1. speakerList — paginated list ──────────────────────────────────────
    url1 = f"{_NEWDEV}/Speaker/speakerList"
    bodies1 = [
        {"pageno": 0, "limit": 12, "request_type": "normallist"},
        {"pageno": 1, "limit": 12, "request_type": "normallist"},
        {"pageno": 0, "limit": 12},
    ]
    print(f"\n  ── Target 1: {url1}")
    found_any = False
    for body in bodies1:
        try:
            resp = session.post(url1, json=body, headers=_NEWDEV_HEADERS, timeout=15)
            row  = f"  POST  body={body}  →  HTTP {resp.status_code}  {len(resp.content)/1024:.1f} KB"
            print(green(row) if resp.status_code == 200 else red(row))
            if resp.status_code == 200:
                records = _analyse_response(resp, "speakerList", result)
                if records:
                    result.records_sample = records[:3]
                    found_any = True
                    break
        except Exception as e:
            print(red(f"  speakerList error: {e}"))
        time.sleep(0.3)

    if not found_any:
        print(yellow("  speakerList did not return parseable speaker records with any tested body"))

    # ── 2. searchSpeaker — keyword search ────────────────────────────────────
    url2 = f"{_NEWDEV}/Speaker/searchSpeaker"
    bodies2 = [
        {"keyword": "Cardiology", "pageno": 0, "limit": 12, "request_type": "normallist"},
        {"keyword": "Smith",      "pageno": 0, "limit": 12, "request_type": "normallist"},
        {"search":  "Cardiology", "pageno": 0, "limit": 12},
        {"keyword": "Cardiology"},
    ]
    print(f"\n  ── Target 2: {url2}")
    search_headers = {**_NEWDEV_HEADERS, "clickedurl": f"{BASE_URL}/healthcare-speakers"}
    for body in bodies2:
        try:
            resp = session.post(url2, json=body, headers=search_headers, timeout=15)
            row  = f"  POST  body={body}  →  HTTP {resp.status_code}  {len(resp.content)/1024:.1f} KB"
            print(green(row) if resp.status_code == 200 else red(row))
            if resp.status_code == 200:
                records = _analyse_response(resp, "searchSpeaker", result)
                if records and not result.records_sample:
                    result.records_sample = records[:3]
                    break
        except Exception as e:
            print(red(f"  searchSpeaker error: {e}"))
        time.sleep(0.3)

    # ── 3. getSpeakerDetail — single speaker lookup ───────────────────────────
    url3 = f"{_NEWDEV}/Speaker/getSpeakerDetail"
    detail_header = {**_NEWDEV_HEADERS, "clickedurl": f"{BASE_URL}/speaker-profile/{slug}"}
    bodies3 = [
        {"user_url": slug},
        {"slug": slug},
        {"speakerUrl": slug},
        {"user_url": slug, "request_type": "detail"},
    ]
    # Also try GET with query params
    get_params3 = [
        {"user_url": slug},
        {"slug": slug},
    ]
    print(f"\n  ── Target 3: {url3}  (slug: {slug})")
    for body in bodies3:
        try:
            resp = session.post(url3, json=body, headers=detail_header, timeout=15)
            row  = f"  POST  body={body}  →  HTTP {resp.status_code}  {len(resp.content)/1024:.1f} KB"
            print(green(row) if resp.status_code == 200 else red(row))
            if resp.status_code == 200:
                _analyse_response(resp, "getSpeakerDetail (POST)", result)
                break
        except Exception as e:
            print(red(f"  getSpeakerDetail POST error: {e}"))
        time.sleep(0.2)

    for params in get_params3:
        try:
            resp = session.get(url3, params=params, headers=detail_header, timeout=15)
            row  = f"  GET   params={params}  →  HTTP {resp.status_code}  {len(resp.content)/1024:.1f} KB"
            print(green(row) if resp.status_code == 200 else red(row))
            if resp.status_code == 200:
                _analyse_response(resp, "getSpeakerDetail (GET)", result)
                break
        except Exception as e:
            print(red(f"  getSpeakerDetail GET error: {e}"))
        time.sleep(0.2)

    if not result.exposed:
        print(yellow("\n  No speaker records returned by any newdev.emedevents.com endpoint"))
        result.findings.append(Finding(
            "search_endpoint",
            "no parseable speaker records returned — endpoints respond 200 but data is empty or requires different params",
        ))

    return result


# ── Summary + report ──────────────────────────────────────────────────────────

def _print_summary(results: list[ProbeResult]) -> None:
    print("\n" + "=" * 60)
    print("HCP DATA EXPOSURE — SUMMARY")
    print("=" * 60)

    for result in results:
        if result.status == "exposed":
            print(red(f"\n  [EXPOSED] {result.name}"))
        elif result.status == "public_no_pii":
            print(yellow(f"\n  [PUBLIC — no PII] {result.name}"))
        else:
            print(green(f"\n  [PROTECTED] {result.name}"))

        for f in result.findings:
            marker = red("[!!]") if f.is_sensitive else "[i] "
            print(f"    {marker} {f.label}: {f.value}")

        if result.records_sample:
            print(f"\n  Sample record (first result):")
            _describe_record(result.records_sample[0])

    print("\n" + "=" * 60)
    exposed_count   = sum(1 for r in results if r.status == "exposed")
    public_count    = sum(1 for r in results if r.status == "public_no_pii")
    protected_count = sum(1 for r in results if r.status == "protected")
    if exposed_count:
        print(red(f"  {exposed_count} EXPOSED  |  {public_count} PUBLIC (no PII)  |  {protected_count} PROTECTED"))
    elif public_count:
        print(yellow(f"  0 EXPOSED  |  {public_count} PUBLIC (no PII)  |  {protected_count} PROTECTED"))
        print(yellow("  Public pages expose only intentionally public profile fields — no contact data found"))
    else:
        print(green(f"  All {len(results)} probes protected — no HCP data exposed"))
    print("=" * 60)


def _write_outputs(results: list[ProbeResult], all_records: list[dict]) -> None:
    logs_dir  = Path(__file__).parent.parent.parent / "logs"
    logs_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Log file
    log_path = logs_dir / f"hcp_exposure_{timestamp}.log"
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(f"HCP Data Exposure Report — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Target: {BASE_URL}\n\n")
        for result in results:
            status_label = {"exposed": "EXPOSED", "public_no_pii": "PUBLIC — no PII", "protected": "PROTECTED"}.get(result.status, "PROTECTED")
            f.write(f"[{status_label}] {result.name}\n")
            for finding in result.findings:
                tag = "[SENSITIVE]" if finding.is_sensitive else "[info]     "
                f.write(f"  {tag} {finding.label}: {finding.value}\n")
            if result.records_sample:
                f.write("\n  Sample record:\n")
                for k, v in result.records_sample[0].items():
                    f.write(f"    {k}: {v}\n")
            f.write("\n")
    print(f"\nLog  saved to : {log_path}")

    # CSV — only if we have records with consistent keys
    if all_records:
        csv_path = logs_dir / f"hcp_exposure_{timestamp}.csv"
        fieldnames = list(all_records[0].keys())
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(all_records)
        print(f"CSV  saved to : {csv_path}  ({len(all_records)} records)")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Probe emedevents.com for exposed HCP data")
    parser.add_argument("--max-pages", type=int, default=10, help="Max pages to paginate in Probe 1 (default: 10)")
    args = parser.parse_args()

    print("=" * 60)
    print("HCP Data Exposure Check")
    print("Can HCP records be accessed without authentication?")
    print("=" * 60)
    print(f"\nTarget  : {BASE_URL}")
    print(f"Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    session  = requests.Session()
    results  = []

    print("[ Probe 1 ] Speaker Bureau — listing via Next.js JSON API")
    p1_result, all_records, build_id = probe_speaker_bureau(session, max_pages=args.max_pages)
    results.append(p1_result)

    print("\n[ Probe 2 ] Individual speaker profile page")
    if p1_result.records_sample:
        results.append(probe_speaker_profile(session, p1_result.records_sample, build_id))
    else:
        print(yellow("  Skipped — no sample records from Probe 1 to derive a profile URL"))

    print("\n[ Probe 3 ] Speaker search / newdev.emedevents.com API")
    results.append(probe_speaker_search(session, build_id, sample_records=all_records or p1_result.records_sample))

    _print_summary(results)
    _write_outputs(results, all_records)


if __name__ == "__main__":
    main()
