# WAF Check — emedevents.com Security Assessment

Scripts for testing WAF protection and data exposure on emedevents.com.

All commands should be run from the **project root** (`emed_utilities/emed_utilities/`) with the virtual environment activated:

```bash
.venv\Scripts\activate
```

---

## Overview

The WAF check suite is split into five focused test scripts, each targeting a distinct attack
vector. They share a common library (`common.py`) and each saves its own timestamped log to
`logs/`. Run them individually or in sequence.

```
scripts/waf_check/
├── common.py                        Shared constants, dataclasses, helpers
├── test1_user_agent_detection.py    Can the WAF tell a scraper from a real browser?
├── test2_rate_limiting.py           Does the WAF block high-volume requests?
├── test3_pagination_scrape.py       Can a scraper walk through all listing pages?
├── test4_headless_browser_scrape.py Can a real browser scrape and discover the backend API?
├── test5_nextjs_api_exposure.py     Is the Next.js JSON API accessible without auth?
├── hcp_data_exposure.py             Is HCP / speaker data accessible without auth?
├── pull_exposed_api.py              Pull conference data from the exposed backend API
└── scrape_via_ui.py                 Scrape the site via a headless browser (UI path)
```

---

## Test 1 — User-Agent Detection

**Question:** Does the WAF block scraper tools? Does it correctly allow SEO crawlers?

The WAF's first line of defence is the `User-Agent` header. We test three groups:

| Group | Examples | WAF should... |
|---|---|---|
| Bad bots | python-requests, curl, scrapy, wget, Go, Java | Block all |
| Good crawlers | Googlebot, Bingbot, DuckDuckBot, Twitterbot | **Allow all** (SEO critical) |
| Headless browsers | HeadlessChrome, Selenium, PhantomJS | Block all |

> Blocking Googlebot would cause the site to disappear from search results.
> Both halves of this test are equally important.

```bash
python scripts/waf_check/test1_user_agent_detection.py
```

**Output:** One pass/fail result per group. Log saved to `logs/test1_user_agent_detection_<timestamp>.log`

---

## Test 2 — Rate Limiting

**Question:** If a client looks like a real browser but fires hundreds of requests per second,
does the WAF step in?

We send requests in concurrent batches using a genuine Chrome User-Agent — the same one that
passes Test 1. The test reports the exact request number at which the WAF triggered (or
confirms that no rate limit is configured).

```bash
# Default: 100 requests, 20 at a time
python scripts/waf_check/test2_rate_limiting.py

# Probe a higher threshold
python scripts/waf_check/test2_rate_limiting.py --total 500 --concurrency 50
```

| Argument | Default | Description |
|---|---|---|
| `--total` | 100 | Total requests to send |
| `--concurrency` | 20 | Requests sent simultaneously per batch |

**Output:** Pass/fail with the block threshold (or confirmation that no block was detected).
Log saved to `logs/test2_rate_limiting_<timestamp>.log`

---

## Test 3 — Pagination Scrape

**Question:** Can a scraper walk through the conference listings page by page without being stopped?

We paginate through both year-specific listing URLs:
- `/medical-conferences/medical-conferences-2025`
- `/medical-conferences/medical-conferences-2026`

We also optionally test while logged in as an authenticated user — the WAF should block
bot-like pagination regardless of whether the user has an account.

```bash
# Unauthenticated only (10 pages per year)
python scripts/waf_check/test3_pagination_scrape.py

# Include authenticated test (15 pages per year)
python scripts/waf_check/test3_pagination_scrape.py --email you@example.com --password yourpass
```

| Argument | Description |
|---|---|
| `--email` | emedevents.com account email (enables authenticated test) |
| `--password` | emedevents.com account password |

**Output:** One result per URL per auth state. Reports which page (if any) triggered a block,
and how many conference links were collected. Log saved to `logs/test3_pagination_scrape_<timestamp>.log`

---

## Test 4 — Headless Browser Scrape

**Question:** Can a real automated browser scrape the site, and can it discover the backend
API endpoints that power the pages?

This test launches a real Chromium browser (headless) and intercepts all network responses
while it loads the conference search page. It identifies which API endpoint actually delivers
the conference data — including if that endpoint is on a different domain (e.g. a staging
server like `newdev.emedevents.com`).

```bash
python scripts/waf_check/test4_headless_browser_scrape.py
```

**Requirements:**
```bash
pip install playwright
playwright install chromium
```

**Output:** Lists all backend API endpoints discovered, records per page, fields per record,
and total scraped across 6 pages. Flags any non-production domains. Log saved to
`logs/test4_headless_browser_scrape_<timestamp>.log`

---

## Test 5 — Next.js JSON API Exposure

**Question:** Can an unauthenticated caller skip the HTML page entirely and pull structured
JSON data directly from the framework's internal API?

Next.js embeds a build ID in every HTML page inside a `__NEXT_DATA__` script tag. Using that
build ID, a caller can construct a URL of the form:

```
https://www.emedevents.com/_next/data/<buildId>/Conferences/searchConference.json
```

This endpoint returns a clean JSON payload — no browser, no JavaScript, no HTML parsing.
We inspect everything returned: conference records, total count, filter options, session
identifiers, and internal Redux store structure.

```bash
python scripts/waf_check/test5_nextjs_api_exposure.py
```

**Output:** Full structured breakdown of every field exposed, plus a plain-English summary
of what an attacker gains from this single request. Log saved to
`logs/test5_nextjs_api_exposure_<timestamp>.log`

---

## HCP Data Exposure — `hcp_data_exposure.py`

**Question:** Is the Healthcare Professional (HCP) database accessible without authentication?

Starting with the Speaker Bureau (`/healthcare-speakers`), this script applies the same
Next.js JSON endpoint technique to HCP-facing pages, identifies what fields are returned
per speaker record, checks for PII (email, phone, NPI), and paginates to confirm bulk
access is possible.

```bash
# Default: probe up to 10 pages
python scripts/waf_check/hcp_data_exposure.py

# Go deeper
python scripts/waf_check/hcp_data_exposure.py --max-pages 50
```

| Argument | Default | Description |
|---|---|---|
| `--max-pages` | 10 | Maximum pages to paginate per probe |

**Output:** Per-record field list with PII flags, pagination table, and plain-English exposure
summary. Log saved to `logs/hcp_exposure_<timestamp>.log`

---

## Supporting Scripts

### `pull_exposed_api.py` — Pull from the exposed backend API directly

Pulls conference data from `newdev.emedevents.com/Conference/conferenceList` (the unprotected
backend API discovered in Test 4) and saves it as a CSV.

```bash
# Cardiology, 10 pages (~90 conferences)
python scripts/waf_check/pull_exposed_api.py

# Different keyword or more pages
python scripts/waf_check/pull_exposed_api.py --keyword Oncology --pages 25
python scripts/waf_check/pull_exposed_api.py --keyword "Family Medicine" --pages 257
```

| Argument | Default | Description |
|---|---|---|
| `--keyword` | `Cardiology` | Search keyword |
| `--pages` | `10` | Pages to pull (9 conferences per page) |

Output: `logs/exposed_api_<keyword>_<timestamp>.csv`

---

### `scrape_via_ui.py` — Scrape via headless browser (UI path)

Proves the site can be scraped through the rendered UI even if the direct API endpoint
is locked down.

```bash
python scripts/waf_check/scrape_via_ui.py
python scripts/waf_check/scrape_via_ui.py --keyword Oncology --pages 10
python scripts/waf_check/scrape_via_ui.py --headless false   # watch it in real time
```

| Argument | Default | Description |
|---|---|---|
| `--keyword` | `Cardiology` | Search keyword |
| `--pages` | `10` | Pages to paginate through |
| `--headless` | `true` | Set to `false` to watch the browser |

Output: `logs/ui_scrape_<keyword>_<timestamp>.csv` and `.log`

---

## Current Findings (as of 2026-04-21)

| Test | Check | Status |
|---|---|---|
| 1 | Bad bot user-agents blocked (python-requests etc.) | **PASS** |
| 1 | Good crawlers allowed (Googlebot, Bingbot etc.) | Pending re-run |
| 1 | Headless browser user-agents blocked | Pending re-run |
| 2 | Rate limiting (100 requests, 20 concurrent) | **FAIL** — no block detected |
| 3 | Pagination scrape — 2025 listings | **FAIL** — 10 pages freely accessible |
| 3 | Pagination scrape — 2026 listings | **FAIL** — 10 pages freely accessible |
| 4 | Headless browser scrape | **FAIL** — data freely scraped |
| 4 | Backend API domain | **FAIL** — `newdev.emedevents.com` serves data with no auth or rate limiting |
| 5 | Next.js `/_next/data/` endpoint | **FAIL** — 318 KB returned with no auth |

### Key exposures still open

| Exposure | Detail |
|---|---|
| Rate limiting | Not configured — unlimited requests accepted from any client |
| Next.js JSON API | `/_next/data/<buildId>/Conferences/searchConference.json` returns 9 conference records/page, 25,372 total count, no auth required |
| Backend API server | `newdev.emedevents.com/Conference/conferenceList` is publicly reachable and returns full conference records with no auth |
| Caller IP echoed | Server returns the requester's real IP in every JSON response |

### Recommended fixes (priority order)

1. **Protect `newdev.emedevents.com`** — add authentication and rate limiting to the backend API; it should not be freely callable from the public internet
2. **Configure WAF rate limiting** — recommended starting point: 60 requests/minute per IP
3. **Protect `/_next/data/` endpoints** — either require auth or restrict which paths are publicly accessible
4. **Expand bot signature list** — ensure curl, wget, scrapy, Go, Java, and empty User-Agents are all blocked, not just python-requests
5. **Verify SEO crawlers are not blocked** — run Test 1 after any WAF rule changes to confirm Googlebot and Bingbot still get through
