# WAF Check & Exposed API Tools

Scripts for verifying WAF protection on emedevents.com and demonstrating the exposed data API.

All commands should be run from the **git root** (`emed_utilities/`) with the virtual environment activated:

```bash
.venv\Scripts\activate
```

---

## 1. WAF Verification — `check_waf.py`

Tests whether the WAF actually blocks automated scraping across 5 checks.

### Basic run (unauthenticated, default settings)
```bash
python scripts/waf_check/check_waf.py
```

### With authenticated scrape test (Test 6)
```bash
python scripts/waf_check/check_waf.py --email you@emedevents.com --password yourpass
```

### Probe a higher rate-limit threshold
```bash
# Test up to 500 requests, 50 at a time
python scripts/waf_check/check_waf.py --rate-total 500 --rate-concurrency 50

# Test up to 5000 requests, 100 at a time
python scripts/waf_check/check_waf.py --rate-total 5000 --rate-concurrency 100
```

### All options
| Argument | Default | Description |
|---|---|---|
| `--email` | — | emedevents.com account email (enables Test 6) |
| `--password` | — | emedevents.com account password (enables Test 6) |
| `--rate-total` | 100 | Total requests to send in rate-limit test |
| `--rate-concurrency` | 20 | Concurrent requests per batch |

### What each test checks
| Test | What it checks |
|---|---|
| 1 | Bot user-agent (`python-requests`) — should be blocked by any WAF |
| 2 | Concurrent burst — finds the rate-limit threshold (or confirms there is none) |
| 3 | Pagination scrape — walks 10 pages like a scraper |
| 4 | Playwright headless browser — executes JS, intercepts API calls, finds data endpoints |
| 5 | Next.js `/_next/data/` JSON endpoint — checks if structured data is exposed |
| 6 | Authenticated scrape — checks if logging in bypasses any WAF rules |

### Output
- Printed to console with `✓ BLOCKED` / `✗ NOT BLOCKED` per test
- Saved to `logs/waf_check_<timestamp>.log`

---

## 2. Pull Exposed API Data — `pull_exposed_api.py`

Pulls conference data directly from the exposed `newdev.emedevents.com` API (no auth required).
Saves results as a CSV with: `title`, `organization_name`, `startdate`, `detailpage_url`.

### Basic run (Cardiology, 10 pages = ~90 conferences)
```bash
python scripts/waf_check/pull_exposed_api.py
```

### Different keyword
```bash
python scripts/waf_check/pull_exposed_api.py --keyword Cardiology
python scripts/waf_check/pull_exposed_api.py --keyword Oncology
python scripts/waf_check/pull_exposed_api.py --keyword "Family Medicine"
```

### Pull more pages
```bash
# 25 pages (~225 conferences)
python scripts/waf_check/pull_exposed_api.py --pages 25

# Pull all ~257 pages (~2300 conferences)
python scripts/waf_check/pull_exposed_api.py --pages 257
```

### All options
| Argument | Default | Description |
|---|---|---|
| `--keyword` | `Cardiology` | Search keyword |
| `--pages` | `10` | Number of pages to pull (9 conferences per page) |

### Output
- Saved to `logs/exposed_api_<keyword>_<timestamp>.csv`
- Example: `logs/exposed_api_cardiology_20260420_041812.csv`

---

## 3. UI Scrape via Browser — `scrape_via_ui.py`

Simulates a real user navigating to the search results page, paginating through results,
and scraping conference data from the rendered DOM. Use this to prove the site can still
be scraped through the UI even if the direct API endpoint (`newdev.emedevents.com`) is blocked.

> **Note:** The homepage search box stays on the homepage after submit (JS-handled).
> The script navigates directly to the search results URL which renders the actual cards.

### Basic run (Cardiology, 10 pages, headless)
```bash
python scripts/waf_check/scrape_via_ui.py
```

### Watch the browser in action (non-headless)
```bash
python scripts/waf_check/scrape_via_ui.py --headless false
```

### Different keyword or more pages
```bash
python scripts/waf_check/scrape_via_ui.py --keyword Oncology --pages 10
python scripts/waf_check/scrape_via_ui.py --keyword "Family Medicine" --pages 5
```

### All options
| Argument | Default | Description |
|---|---|---|
| `--keyword` | `Cardiology` | Search keyword |
| `--pages` | `10` | Number of pages to paginate through |
| `--headless` | `true` | Set to `false` to watch the browser in real time |

### What it does
1. Navigates directly to `https://www.emedevents.com/Conferences/searchConference?keyword=<keyword>`
2. Waits for conference cards to render via JavaScript
3. Extracts `title`, `organization_name`, `startdate`, `detailpage_url` from each card
4. Deduplicates by URL so each conference appears only once
5. Paginates via URL (`?keyword=X&page=N`) for each subsequent page
6. Repeats for the requested number of pages

### Output
- CSV: `logs/ui_scrape_<keyword>_<timestamp>.csv`
- Log: `logs/ui_scrape_<keyword>_<timestamp>.log`

---

## 4. Enrich GA Report CSV — `scripts/conferences/enrich_ga_csv.py`

Takes a GA report CSV (with Conference ID, Title, Organizer, dates, and empty URL/Users/Pageviews
columns) and fills in the **URL column (column F)** by looking up `emed_url` from `tbl_conferences`.

Once GA API access is set up, Users (column G) and Pageviews (column H) will be filled separately.

### Input CSV format
```
Conference ID, Title, Organizer Name, Start Date, End Date, URL, Users, Pageviews
310994, Bahamas LiveAboard..., Wild Med Adventures LLC, 01/03/2026, 31/03/2026, , ,
...
```

### Basic usage — overwrites the input file
```bash
python scripts/conferences/enrich_ga_csv.py --input scripts/conferences/data/report.csv
```

### Save to a new file instead
```bash
python scripts/conferences/enrich_ga_csv.py --input scripts/conferences/data/report.csv --output scripts/conferences/data/enriched.csv
```

### Arguments
| Argument | Required | Description |
|---|---|---|
| `--input` | Yes | Path to the GA report CSV |
| `--output` | No | Output path — defaults to overwriting the input file |

### What it does
1. Reads all conference IDs from the CSV
2. Queries `tbl_conferences` for `emed_url` where `id IN (<ids>)` — single DB query
3. Fills column F (`URL`) as `https://www.emedevents.com/c/<emed_url>`
4. Leaves `Users` and `Pageviews` columns untouched (to be filled once GA API is ready)
5. Writes the enriched CSV back to disk

---

## Key Findings Summary

| Finding | Detail |
|---|---|
| WAF blocks bot user-agent | **NO** — `python-requests` passes through |
| WAF rate limiting | **NO** — 100 concurrent requests, all HTTP 200 |
| WAF blocks pagination scraping | **NO** — all pages freely accessible |
| Real data API exposed | **YES** — `https://newdev.emedevents.com/Conference/conferenceList` |
| Auth required for API | **NO** — `emedauthorization: undefined` is accepted |
| Data format | JSON, 9 conferences per page |
| Total conferences exposed | ~2,300 (257 pages × 9) |

### Root cause
The production frontend (`www.emedevents.com`) fetches all conference data from
`newdev.emedevents.com` — an unprotected **development server** that is publicly
accessible with no authentication or rate limiting.

**Immediate actions needed:**
1. Restrict `newdev.emedevents.com` to internal IPs only — it should not be publicly reachable
2. Move the production data API to a protected endpoint behind the WAF
3. Configure WAF rate limiting (recommended: 60–100 requests/minute per IP)
4. Add bot signature detection to block `python-requests` and similar tools
