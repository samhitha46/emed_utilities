"""
WAF Check — Test 5: Next.js JSON API Exposure
===============================================
WHAT WE ARE TESTING
-------------------
The site is built with Next.js, a React framework that pre-renders pages
server-side. During this process, Next.js embeds a JSON block called
__NEXT_DATA__ in every HTML page. This block contains a build ID and
often the full data payload used to render the page.

More critically, Next.js also exposes a parallel JSON-only API at:

    /_next/data/<buildId>/<page-path>.json

This endpoint returns exactly the same data as the HTML page, but as
pure structured JSON — no browser needed, no HTML parsing required.
These endpoints are intended for internal client-side navigation but are
almost never protected by authentication or WAF rules.

We:
  1. Fetch the search page and extract the build ID from __NEXT_DATA__
  2. Hit the /_next/data/ JSON endpoint directly with no credentials
  3. Fully inspect everything returned: conference records, pagination
     state, filter options, session identifiers, and metadata
  4. Report in plain English exactly what a scraper gets for free

WHY IT MATTERS
--------------
This is the most efficient scraping vector on a Next.js site. One HTTP
request returns a clean JSON payload with every conference on the page,
the total conference count, and internal state that helps an attacker
understand the system (Redux store shape, org account flags, etc.).
No browser, no JavaScript execution, no HTML parsing — just a URL.

Usage:
    python scripts/waf_check/test5_nextjs_api_exposure.py
"""
import json

import requests
from bs4 import BeautifulSoup

from common import BASE_URL, BROWSER_HEADERS, CheckResult, Report, is_blocked

SEARCH_URL = f"{BASE_URL}/Conferences/searchConference"


def _describe_props(props: dict, indent: str = "  ", expand_keys: set | None = None) -> list[str]:
    lines = []
    for key, val in props.items():
        force_expand = expand_keys and key in expand_keys
        if isinstance(val, list):
            if len(val) == 0:
                lines.append(f"{indent}'{key}': [] (empty list)")
            elif isinstance(val[0], dict):
                lines.append(f"{indent}'{key}': list of {len(val)} objects — fields: {list(val[0].keys())}")
            else:
                lines.append(f"{indent}'{key}': list of {len(val)} scalars — sample: {val[:3]}")
        elif isinstance(val, dict):
            lines.append(f"{indent}'{key}': dict with {len(val)} keys — {list(val.keys())[:8]}")
            if force_expand or len(val) <= 10:
                for k2, v2 in val.items():
                    if isinstance(v2, (str, int, float, bool)) or v2 is None:
                        display = repr(v2) if not isinstance(v2, str) else repr(v2[:120])
                        lines.append(f"{indent}    '{k2}': {display}")
                    elif isinstance(v2, list):
                        if len(v2) == 0:
                            lines.append(f"{indent}    '{k2}': [] (empty list)")
                        elif isinstance(v2[0], dict):
                            lines.append(f"{indent}    '{k2}': list of {len(v2)} objects — fields: {list(v2[0].keys())}")
                        else:
                            lines.append(f"{indent}    '{k2}': list of {len(v2)} scalars — sample: {v2[:3]}")
                    elif isinstance(v2, dict):
                        lines.append(f"{indent}    '{k2}': dict with {len(v2)} keys — {list(v2.keys())[:8]}")
        elif isinstance(val, (str, int, float, bool)) or val is None:
            display = repr(val) if not isinstance(val, str) else repr(val[:120])
            lines.append(f"{indent}'{key}': {display}")
    return lines


def _print_exposure_summary(page_props: dict, json_url: str, response_kb: float) -> list[str]:
    findings: list[str] = []

    print("\n  ══════════════════════════════════════════════════════")
    print("  WHAT IS EXPOSED — plain English summary")
    print("  ══════════════════════════════════════════════════════")
    print(f"\n  Endpoint : {json_url}")
    print(f"  Auth     : none required")
    print(f"  Size     : {response_kb:.1f} KB")
    findings.append(f"Endpoint returns {response_kb:.1f} KB with no auth: {json_url}")

    # IP / UA leakage
    ip = page_props.get("ip")
    ua = page_props.get("uaString")
    if ip:
        print(f"\n  [!] Server echoes caller's real IP in the response: {ip}")
        print(f"      This confirms the backend logs and tracks all client IPs")
        findings.append(f"Caller IP leaked in response: {ip}")
    if ua:
        print(f"  [!] Server echoes caller's User-Agent: {ua[:70]}")
        findings.append("Caller User-Agent echoed in response")

    # Conference data
    list_resp = page_props.get("listRespData", {})
    if isinstance(list_resp, dict):
        conferences  = list_resp.get("conferences")
        conf_count   = list_resp.get("conferences_count")
        recommended  = list_resp.get("recommendedConferences")
        banners      = list_resp.get("banners")
        request_obj  = list_resp.get("request")
        aggregations = list_resp.get("aggregations")

        if isinstance(conferences, list):
            fields = list(conferences[0].keys()) if conferences and isinstance(conferences[0], dict) else []
            print(f"\n  [!] Conference records exposed: {len(conferences)} per page")
            print(f"      Fields per record: {fields}")
            findings.append(f"Conference list: {len(conferences)} records/page with fields: {fields}")

        if conf_count is not None:
            print(f"  [!] Total conferences in database exposed: {conf_count:,}")
            findings.append(f"Total conference count: {conf_count:,}")

        if isinstance(request_obj, dict):
            print(f"  [!] Internal search parameters exposed: {request_obj}")
            findings.append(f"Internal search params: {request_obj}")

        if isinstance(aggregations, dict):
            agg_keys = list(aggregations.keys())
            print(f"  [!] Filter/aggregation options exposed: {agg_keys}")
            findings.append(f"Aggregation options exposed: {agg_keys}")

        if isinstance(recommended, list) and recommended:
            print(f"  [i] Recommended conferences list: {len(recommended)} records")
            findings.append(f"Recommended conferences: {len(recommended)} records")

        if isinstance(banners, list) and banners:
            print(f"  [i] Banner/ad data: {len(banners)} entries")

    # Redux store / session state
    initial_state = page_props.get("initialState", {})
    if isinstance(initial_state, dict):
        auth = initial_state.get("authentication", {})
        user = initial_state.get("user", {})
        cart = initial_state.get("cart", {})
        print(f"\n  [i] Client-side Redux store structure is exposed:")
        print(f"      authentication : {list(auth.keys()) if isinstance(auth, dict) else auth}")
        print(f"      user           : {list(user.keys()) if isinstance(user, dict) else user}")
        print(f"      cart           : {list(cart.keys()) if isinstance(cart, dict) else cart}")
        print(f"      (This reveals session/auth field names — useful for impersonation attacks)")
        findings.append(f"Redux store exposed: auth={list(auth.keys()) if isinstance(auth, dict) else []}")

    token = page_props.get("token")
    uid   = page_props.get("uid")
    print(f"\n  [i] Session identifiers for this (unauthenticated) request:")
    print(f"      token : {token!r}  ← would contain auth token for a logged-in user")
    print(f"      uid   : {uid!r}  ← would contain user ID for a logged-in user")
    findings.append(f"token={token!r}, uid={uid!r} for unauthenticated call")

    org = page_props.get("orgAccount")
    if org is not None:
        print(f"  [i] orgAccount: {org!r} — server differentiates org vs individual accounts")
        findings.append(f"orgAccount flag: {org!r}")

    print("\n  ══════════════════════════════════════════════════════\n")
    return findings


def run(report: Report) -> None:
    session = requests.Session()

    print(f"  Target page : {SEARCH_URL}?keyword=Cardiology")
    print(f"  Auth        : none\n")

    print(f"  Step 1 — Fetching page to extract Next.js build ID...")
    resp = session.get(SEARCH_URL, params={"keyword": "Cardiology"}, headers=BROWSER_HEADERS, timeout=15)

    if is_blocked(resp):
        report.add(CheckResult(
            name="Next.js JSON API — initial page fetch",
            passed=True,
            status_code=resp.status_code,
            detail="WAF blocked the initial page request",
        ))
        return

    soup         = BeautifulSoup(resp.text, "html.parser")
    next_data_tag = soup.find("script", {"id": "__NEXT_DATA__"})

    if not next_data_tag:
        report.add(CheckResult(
            name="Next.js JSON API — build ID extraction",
            passed=False,
            status_code=200,
            detail="No __NEXT_DATA__ tag found — site may not be Next.js or tag is obfuscated",
        ))
        return

    next_data = json.loads(next_data_tag.string)
    build_id  = next_data.get("buildId", "")
    page_path = next_data.get("page", "")
    query     = next_data.get("query", {})

    print(f"  Build ID extracted : {build_id}")
    print(f"  Page path          : {page_path}")
    if query:
        print(f"  Query params       : {query}")

    # Show what's already embedded in the HTML (before hitting the JSON endpoint)
    inline_props = next_data.get("props", {}).get("pageProps", {})
    if inline_props:
        print(f"\n  Step 2 — Data already embedded in the HTML source ({len(inline_props)} keys):")
        for line in _describe_props(inline_props):
            print(line)
    else:
        print("\n  Step 2 — No data pre-rendered in HTML (loaded client-side after page load)")

    if not build_id:
        report.add(CheckResult(
            name="Next.js JSON API — build ID extraction",
            passed=False,
            status_code=200,
            detail="Could not extract build ID from __NEXT_DATA__",
        ))
        return

    # Hit the JSON endpoint directly
    json_url = f"{BASE_URL}/_next/data/{build_id}/Conferences/searchConference.json"
    print(f"\n  Step 3 — Probing JSON endpoint directly (no auth):")
    print(f"  {json_url}")

    json_resp = session.get(json_url, params={"keyword": "Cardiology"}, headers=BROWSER_HEADERS, timeout=15)
    print(f"  Response: HTTP {json_resp.status_code} — {len(json_resp.content) / 1024:.1f} KB")

    if is_blocked(json_resp):
        report.add(CheckResult(
            name="Next.js JSON API — /_next/data/ endpoint",
            passed=True,
            status_code=json_resp.status_code,
            detail=f"WAF blocked the /_next/data/ endpoint (HTTP {json_resp.status_code})",
        ))
        return

    if json_resp.status_code == 200:
        try:
            page_props  = json_resp.json().get("pageProps", {})
            response_kb = len(json_resp.content) / 1024

            print(f"\n  Full response structure ({len(page_props)} keys):")
            for line in _describe_props(page_props, expand_keys={"listRespData"}):
                print(line)

            findings = _print_exposure_summary(page_props, json_url, response_kb)
            detail   = "EXPOSED (no auth): " + " | ".join(findings)
        except Exception:
            detail = f"HTTP 200 but response is not valid JSON. Size: {len(json_resp.content) / 1024:.1f} KB"
    else:
        detail = f"/_next/data/ returned HTTP {json_resp.status_code}"

    report.add(CheckResult(
        name="Next.js JSON API — /_next/data/ endpoint",
        passed=False,
        status_code=json_resp.status_code,
        detail=detail,
    ))


def main() -> None:
    print("=" * 60)
    print("Test 5 — Next.js JSON API Exposure")
    print("Can an unauthenticated caller bypass the HTML layer and")
    print("pull structured JSON data directly from the framework's")
    print("internal API endpoint?")
    print("=" * 60 + "\n")

    report = Report()
    run(report)
    report.summary()
    report.write_log("test5_nextjs_api_exposure")


if __name__ == "__main__":
    main()
