"""
Probes the emedevents.com newsletter subscription form for two security risks:

  Test A — reCAPTCHA bypass
      Replays the captured real POST request with an empty reCAPTCHA token.
      If the server accepts it, bots can subscribe (or probe) at scale with no
      human verification.

  Test B — Email enumeration
      Submits the same email address twice (using the real captured payload)
      and compares the server's responses. If they differ, an attacker can
      silently verify whether a given HCP email exists in the database.

How it works:
  Step 0 — Opens a real browser window at /newsletter and pre-fills the form
            fields. You solve the reCAPTCHA manually and click Subscribe.
            Playwright intercepts the POST that fires, capturing the exact URL,
            headers, and body the site uses.

  Tests A & B run automatically after the capture.

Usage:
    python scripts/waf_check/probe_newsletter.py
"""
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from common import BASE_URL, BROWSER_HEADERS, green, red, yellow

_NEWSLETTER_PAGE = f"{BASE_URL}/newsletter"
_SAFE_TEST_EMAIL = "probe-test-do-not-use@example.invalid"   # RFC 2606 — never real


def _has_form_data(body: dict) -> bool:
    """True if the POST body looks like an actual form submission (contains email or name fields)."""
    body_str = json.dumps(body).lower()
    return any(k in body_str for k in ["email", "firstname", "first_name", "lastname", "subscribe"])


# ── Step 0: Human-in-the-loop capture ────────────────────────────────────────

def capture_real_submission() -> dict | None:
    """
    Open the newsletter page in a visible browser, pre-fill the form, then
    pause and wait for the user to solve reCAPTCHA and click Subscribe.

    Returns the captured request as:
        {"url": str, "headers": dict, "body": dict}
    or None if nothing was captured within the timeout.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(red("  Playwright not installed."))
        print("  Run: pip install playwright && playwright install chromium")
        return None

    captured: list[dict] = []

    def on_request(request):
        if request.method != "POST":
            return
        url = request.url
        # Skip Google/reCAPTCHA, CDN, and static asset requests
        skip = ["google.com/recaptcha", "gstatic.com", "googletagmanager",
                "analytics", "chrome-extension://", "data:"]
        if any(s in url for s in skip):
            return
        if any(url.endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".woff2", ".ico"]):
            return
        try:
            raw  = request.post_data or ""
            body = json.loads(raw) if raw.startswith("{") else {"_raw": raw}
        except Exception:
            body = {"_raw": request.post_data or ""}
        hdrs = dict(request.headers)

        # Fingerprinting/bot-detection calls — log but don't treat as the subscription endpoint
        if "DOMIdentifiers" in body or "rulesType" in body:
            print(yellow(f"  [bot-detection fingerprint] {url[:80]}..."))
            return

        print(yellow(f"  [intercepted POST] {url}"))
        captured.append({"url": url, "headers": hdrs, "body": body})

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=False)
        context = browser.new_context(
            user_agent=BROWSER_HEADERS["User-Agent"],
            locale="en-US",
            viewport={"width": 1280, "height": 900},
        )
        page = context.new_page()
        page.on("request", on_request)

        print(f"  Opening {_NEWSLETTER_PAGE} ...")
        page.goto(_NEWSLETTER_PAGE, wait_until="networkidle", timeout=30000)

        # Pre-fill form fields so you only need to solve reCAPTCHA
        for sel in ["input[placeholder*='First']", "input[name*='first']", "input[id*='first']"]:
            try:
                page.fill(sel, "Probe", timeout=2000); break
            except Exception:
                pass
        for sel in ["input[placeholder*='Last']", "input[name*='last']", "input[id*='last']"]:
            try:
                page.fill(sel, "Test", timeout=2000); break
            except Exception:
                pass
        for sel in ["input[type='email']", "input[placeholder*='Email']", "input[name*='email']"]:
            try:
                page.fill(sel, _SAFE_TEST_EMAIL, timeout=2000); break
            except Exception:
                pass

        print()
        print("  ┌─────────────────────────────────────────────────────────┐")
        print("  │  ACTION REQUIRED in the browser window:                 │")
        print("  │                                                          │")
        print("  │  1. Select a Profession and Speciality from dropdowns   │")
        print("  │  2. Solve the reCAPTCHA checkbox                        │")
        print("  │  3. Click  Subscribe                                     │")
        print("  │                                                          │")
        print("  │  Waiting up to 3 minutes for you to complete this...    │")
        print("  └─────────────────────────────────────────────────────────┘")
        print()

        # Poll until we capture a form-submission POST or time out (180 s).
        # We only break on a POST that contains actual form data (email field),
        # not on the bot-detection fingerprinting calls that fire on page load.
        deadline = time.time() + 180
        while time.time() < deadline:
            form_posts = [c for c in captured if _has_form_data(c["body"])]
            if form_posts:
                break
            time.sleep(1)

        context.close()
        browser.close()

    form_posts = [c for c in captured if _has_form_data(c["body"])]

    if not form_posts:
        print(yellow("  No form-submission POST captured within the timeout window."))
        print(yellow("  Make sure you filled all fields, solved reCAPTCHA, and clicked Subscribe."))
        return None

    print(f"\n  {len(form_posts)} form-submission POST(s) captured:")
    for i, c in enumerate(form_posts, 1):
        print(f"    {i}. {c['url']}")
        print(f"       body fields: {list(c['body'].keys())}")

    preferred = form_posts[0]
    print(green(f"\n  Using: {preferred['url']}"))
    return preferred


# ── Test A: reCAPTCHA bypass ──────────────────────────────────────────────────

def test_recaptcha_bypass(session: requests.Session, capture: dict) -> bool:
    """
    Replay the captured request with the reCAPTCHA token stripped out.
    Returns True if the server accepts it (bypass confirmed).
    """
    url     = capture["url"]
    hdrs    = {k: v for k, v in capture["headers"].items() if k.lower() != "content-length"}
    payload = dict(capture["body"])

    # Strip any reCAPTCHA token that was in the original submission
    original_token = ""
    for key in list(payload.keys()):
        if "recaptcha" in key.lower() or "captcha" in key.lower() or key.lower() == "token":
            original_token = str(payload[key])
            payload[key]   = ""   # empty the token

    print(f"  Endpoint        : {url}")
    print(f"  Original token  : {'(present, ' + str(len(original_token)) + ' chars)' if original_token else '(was already empty)'}")
    print(f"  Replaying with  : empty token")

    try:
        resp = session.post(url, json=payload, headers=hdrs, timeout=15)
        size = len(resp.content) / 1024
        print(green(f"  HTTP {resp.status_code}  {size:.1f} KB") if resp.status_code == 200
              else print(f"  HTTP {resp.status_code}  {size:.1f} KB") or f"  HTTP {resp.status_code}")

        try:
            body = resp.json()
            print(f"  Response        : {json.dumps(body)[:400]}")
            if body.get("success") is True:
                print(red("  [!!] Server ACCEPTED the submission with no valid reCAPTCHA token"))
                return True
            else:
                msg = body.get("msg") or body.get("message") or ""
                print(green(f"  Server rejected : '{msg}'"))
                return False
        except Exception:
            print(f"  Raw response    : {resp.text[:300]}")
            return False
    except Exception as e:
        print(red(f"  Request failed  : {e}"))
        return False


# ── Test B: Email enumeration ─────────────────────────────────────────────────

def test_email_enumeration(session: requests.Session, capture: dict) -> bool:
    """
    Submit the captured payload twice with the same email and compare responses.
    Returns True if responses differ (enumeration confirmed).
    """
    url     = capture["url"]
    hdrs    = {k: v for k, v in capture["headers"].items() if k.lower() != "content-length"}
    payload = dict(capture["body"])

    print(f"  Endpoint : {url}")
    print(f"  Email    : {payload.get('email', _SAFE_TEST_EMAIL)}")
    print()

    responses: list[str] = []
    for attempt in range(1, 3):
        label = "1st submit (new email)" if attempt == 1 else "2nd submit (same email)"
        try:
            resp = session.post(url, json=payload, headers=hdrs, timeout=15)
            try:
                body = resp.json()
                msg  = str(
                    body.get("msg") or body.get("message") or
                    body.get("error") or body.get("success") or ""
                ).strip().lower()
            except Exception:
                msg = resp.text[:200].strip().lower()

            responses.append(msg)
            color = green if "success" in msg else yellow
            print(color(f"  Attempt {attempt} ({label}): '{msg}'"))
        except Exception as e:
            print(red(f"  Attempt {attempt}: request failed — {e}"))
            responses.append("ERROR")
        time.sleep(1.5)

    if len(responses) < 2 or "ERROR" in responses:
        print(yellow("\n  Enumeration test inconclusive — could not complete both submissions"))
        return False

    if responses[0] != responses[1]:
        print(red(f"\n  [!!] RESPONSES DIFFER — email enumeration confirmed"))
        print(red(f"       1st : '{responses[0]}'"))
        print(red(f"       2nd : '{responses[1]}'"))
        print(red("       An attacker can verify HCP email existence by double-submitting"))
        return True
    else:
        print(green(f"\n  Both responses identical: '{responses[0]}'"))
        print(green("  No enumeration signal — server does not reveal whether email is known"))
        return False


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print("Newsletter Subscription — Security Probe")
    print(f"Target : {_NEWSLETTER_PAGE}")
    print("=" * 60)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    session = requests.Session()

    # Step 0 — human-in-the-loop capture
    print("[ Step 0 ] Open browser — waiting for you to solve reCAPTCHA and submit")
    capture = capture_real_submission()

    if not capture:
        print(red("\n  Could not capture a real submission. Exiting."))
        print("  Make sure you click Subscribe within 3 minutes of the browser opening.")
        sys.exit(1)

    print(f"\n  Full captured body:\n  {json.dumps(capture['body'], indent=4)}")

    # Test A — reCAPTCHA bypass
    print("\n" + "─" * 60)
    print("[ Test A ] reCAPTCHA bypass — replay with empty token")
    print("─" * 60)
    bypassed = test_recaptcha_bypass(session, capture)

    # Test B — email enumeration
    print("\n" + "─" * 60)
    print("[ Test B ] Email enumeration — same email submitted twice")
    print("─" * 60)
    enumerable = test_email_enumeration(session, capture)

    # Summary
    print("\n" + "=" * 60)
    print("NEWSLETTER PROBE — SUMMARY")
    print("=" * 60)
    print(f"  Captured endpoint : {capture['url']}")
    print(f"  reCAPTCHA bypass  : {red('VULNERABLE') if bypassed   else green('Protected')}")
    print(f"  Email enumeration : {red('VULNERABLE') if enumerable else green('Protected')}")
    print("=" * 60)

    logs_dir  = Path(__file__).parent.parent.parent / "logs"
    logs_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path  = logs_dir / f"newsletter_probe_{timestamp}.log"
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(f"Newsletter Security Probe — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Target            : {_NEWSLETTER_PAGE}\n")
        f.write(f"Captured endpoint : {capture['url']}\n")
        f.write(f"Captured body     : {json.dumps(capture['body'])}\n\n")
        f.write(f"reCAPTCHA bypass  : {'VULNERABLE' if bypassed   else 'Protected'}\n")
        f.write(f"Email enumeration : {'VULNERABLE' if enumerable else 'Protected'}\n")
    print(f"\nLog saved to: {log_path}")


if __name__ == "__main__":
    main()
