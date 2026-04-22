"""
WAF Check — Test 1: User-Agent Detection
=========================================
WHAT WE ARE TESTING
-------------------
The WAF's first line of defence is recognising *who* is making the request
by inspecting the User-Agent header sent with every HTTP request.

We test six distinct groups:

  BAD BOTS         — well-known scraper/automation HTTP libraries. The WAF
                     should block all of these.

  ATTACK TOOLS     — active security scanners and known malicious crawlers.
                     The WAF should block all of these.

  HEADLESS         — automation tools that try to disguise themselves as real
                     browsers but leave traces (HeadlessChrome, Selenium, etc.).
                     The WAF ideally blocks these too.

  SEO CRAWLERS     — mainstream search-engine bots (Google, Bing, etc.) that
                     the site needs for organic search ranking. Must NOT be
                     blocked.

  AI / LLM BOTS    — crawlers from AI companies (OpenAI, Anthropic, Perplexity,
                     etc.) that power AI-generated answers. Blocking these means
                     the site won't appear in ChatGPT, Claude, or Perplexity
                     responses — increasingly important for discovery.

  SOCIAL / PREVIEW — bots that generate link previews on Slack, Twitter,
                     Facebook, Discord etc. Blocking these breaks unfurls
                     whenever a URL is shared.

  MONITORING       — uptime and synthetic monitoring agents. Blocking these
                     silences your own alerting infrastructure.

WHY IT MATTERS
--------------
If the WAF only blocks "python" in the User-Agent string, a scraper can evade
it in seconds. A properly configured WAF maintains a broad blocklist of known
bad agents while explicitly allowing every legitimate crawler category.
The good-bot checks are just as important as the bad-bot checks — a WAF
misconfiguration that blocks Googlebot or PerplexityBot has real business
consequences (lost SEO rank, absent from AI answers).

Usage:
    python scripts/waf_check/test1_user_agent_detection.py
"""
import time

import requests

from common import BASE_URL, BROWSER_HEADERS, CheckResult, Report, is_blocked, green, red, yellow

URL = f"{BASE_URL}/medical-conferences"

# Each entry: (display_label, user_agent_string, category)
# category drives pass/fail logic:
#   "BAD BOT" / "ATTACK TOOL" / "HEADLESS" → blocked = PASS
#   anything starting with "GOOD" → allowed = PASS
USER_AGENTS: list[tuple[str, str, str]] = [

    # ── BAD BOTS ─────────────────────────────────────────────────────────────
    # Common HTTP libraries used in scrapers. Should all be blocked.
    ("python-requests",     "python-requests/2.32.0",                                               "BAD BOT"),
    ("python-httpx",        "python-httpx/0.27.0",                                                  "BAD BOT"),
    ("python-urllib",       "Python-urllib/3.12",                                                   "BAD BOT"),
    ("aiohttp",             "Python/3.12 aiohttp/3.9.1",                                            "BAD BOT"),
    ("curl",                "curl/8.5.0",                                                           "BAD BOT"),
    ("wget",                "Wget/1.21.4",                                                          "BAD BOT"),
    ("scrapy",              "Scrapy/2.11.0 (+https://scrapy.org)",                                  "BAD BOT"),
    ("Go http client",      "Go-http-client/2.0",                                                   "BAD BOT"),
    ("Java",                "Java/21.0.2",                                                          "BAD BOT"),
    ("libwww-perl",         "libwww-perl/6.72",                                                     "BAD BOT"),
    ("Ruby Net::HTTP",      "Ruby/3.3.0 (ruby-net-http)",                                           "BAD BOT"),
    ("node-fetch",          "node-fetch/3.3.2",                                                     "BAD BOT"),
    ("axios",               "axios/1.6.8",                                                          "BAD BOT"),
    ("GuzzleHttp (PHP)",    "GuzzleHttp/7.0",                                                       "BAD BOT"),
    ("okhttp (Android)",    "okhttp/4.12.0",                                                        "BAD BOT"),
    ("empty user-agent",    "",                                                                      "BAD BOT"),

    # ── ATTACK TOOLS ─────────────────────────────────────────────────────────
    # Active scanners and known aggressive crawlers. Should all be blocked.
    ("Nikto",               "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:map_codes)",         "ATTACK TOOL"),
    ("sqlmap",              "sqlmap/1.8 (https://sqlmap.org)",                                      "ATTACK TOOL"),
    ("Nmap",                "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", "ATTACK TOOL"),
    ("ZmEu",                "ZmEu",                                                                 "ATTACK TOOL"),
    ("MJ12bot",             "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)",        "ATTACK TOOL"),
    ("AhrefsBot",           "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",   "ATTACK TOOL"),
    ("SemrushBot",          "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)", "ATTACK TOOL"),
    ("DataForSeoBot",       "Mozilla/5.0 (compatible; DataForSeoBot/1.0; +https://dataforseo.com/dataforseo-bot)", "ATTACK TOOL"),
    ("Bytespider",          "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; https://zhanzhang.toutiao.com/)", "ATTACK TOOL"),
    ("Fake Googlebot",      "Mozilla/5.0 (compatible; Googlebot/2.1)",                              "ATTACK TOOL"),  # missing the +http://www.google.com/bot.html — common spoof

    # ── HEADLESS BROWSERS ────────────────────────────────────────────────────
    # Automation tools that disguise themselves as browsers. Should be blocked.
    ("HeadlessChrome",      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/124.0.0.0 Safari/537.36", "HEADLESS"),
    ("Selenium+Chrome",     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Selenium/4.0", "HEADLESS"),
    ("PhantomJS",           "Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) PhantomJS/1.9.8 Safari/534.34", "HEADLESS"),
    ("Playwright",          "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.29 Safari/537.36 Playwright/1.44.0", "HEADLESS"),
    ("Puppeteer",           "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 PuppeteerAgent/1.0", "HEADLESS"),
    ("Cypress",             "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Cypress/13.0.0", "HEADLESS"),

    # ── GOOD: SEO CRAWLERS ───────────────────────────────────────────────────
    # Mainstream search engine bots. Must NOT be blocked — affects organic ranking.
    ("Googlebot",           "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",  "GOOD: SEO CRAWLERS"),
    ("Googlebot-Mobile",    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "GOOD: SEO CRAWLERS"),
    ("Googlebot-Image",     "Googlebot-Image/1.0",                                                  "GOOD: SEO CRAWLERS"),
    ("Googlebot-News",      "Googlebot-News",                                                       "GOOD: SEO CRAWLERS"),
    ("AdsBot-Google",       "AdsBot-Google (+http://www.google.com/adsbot.html)",                   "GOOD: SEO CRAWLERS"),
    ("Applebot",            "Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot.html)", "GOOD: SEO CRAWLERS"),
    ("Bingbot",             "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "GOOD: SEO CRAWLERS"),
    ("DuckDuckBot",         "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",           "GOOD: SEO CRAWLERS"),
    ("YandexBot",           "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",     "GOOD: SEO CRAWLERS"),
    ("Baiduspider",         "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)", "GOOD: SEO CRAWLERS"),

    # ── GOOD: AI / LLM BOTS ──────────────────────────────────────────────────
    # Crawlers that feed AI models and AI-powered search (ChatGPT, Claude,
    # Perplexity etc.). Blocking these means the site won't appear in AI answers.
    ("GPTBot",              "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)", "GOOD: AI / LLM BOTS"),
    ("ChatGPT-User",        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot", "GOOD: AI / LLM BOTS"),
    ("ClaudeBot",           "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ClaudeBot/1.0; +claudebot@anthropic.com", "GOOD: AI / LLM BOTS"),
    ("PerplexityBot",       "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot.html", "GOOD: AI / LLM BOTS"),
    ("YouBot",              "Mozilla/5.0 (compatible; YouBot/1.0; +https://about.you.com/en/youbot/)", "GOOD: AI / LLM BOTS"),
    ("Google-Extended",     "Mozilla/5.0 (compatible; Google-Extended/1.0)",                        "GOOD: AI / LLM BOTS"),
    ("CCBot",               "CCBot/2.0 (https://commoncrawl.org/faq/)",                             "GOOD: AI / LLM BOTS"),
    ("Diffbot",             "Mozilla/5.0 (compatible; Diffbot/1.0; +https://www.diffbot.com)",      "GOOD: AI / LLM BOTS"),
    ("meta-externalagent",  "meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)", "GOOD: AI / LLM BOTS"),

    # ── GOOD: SOCIAL / PREVIEW BOTS ──────────────────────────────────────────
    # Generate link previews when URLs are shared on social platforms.
    # Blocking these means broken unfurls on Slack, Twitter, WhatsApp, etc.
    ("Twitterbot",          "Twitterbot/1.0",                                                       "GOOD: SOCIAL"),
    ("LinkedInBot",         "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient/4.1.1 +http://www.linkedin.com)", "GOOD: SOCIAL"),
    ("facebookexternalhit", "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", "GOOD: SOCIAL"),
    ("WhatsApp",            "WhatsApp/2.23.24.0 A",                                                 "GOOD: SOCIAL"),
    ("TelegramBot",         "TelegramBot (like TwitterBot)",                                        "GOOD: SOCIAL"),
    ("Slackbot",            "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",           "GOOD: SOCIAL"),
    ("Discordbot",          "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",    "GOOD: SOCIAL"),

    # ── GOOD: MONITORING ─────────────────────────────────────────────────────
    # Uptime and synthetic monitoring services. Blocking these silences
    # your own alerting — you'd stop receiving downtime notifications.
    ("UptimeRobot",         "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)", "GOOD: MONITORING"),
    ("Pingdom",             "Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)",                "GOOD: MONITORING"),
    ("DatadogSynthetics",   "Datadog/Synthetics",                                                   "GOOD: MONITORING"),
    ("StatusCake",          "StatusCake/1.0",                                                       "GOOD: MONITORING"),
]

GOOD_CATEGORIES = {"GOOD: SEO CRAWLERS", "GOOD: AI / LLM BOTS", "GOOD: SOCIAL", "GOOD: MONITORING"}


def run(report: Report) -> None:
    print(f"  Target  : {URL}")
    print(f"  Testing : {len(USER_AGENTS)} User-Agent variants across {len(set(c for _, _, c in USER_AGENTS))} categories\n")

    current_category = None
    by_category: dict[str, list[tuple[str, int, bool, bool]]] = {}

    for label, ua, category in USER_AGENTS:
        if category != current_category:
            current_category = category
            is_good = category in GOOD_CATEGORIES
            expectation = "should be ALLOWED" if is_good else "should be BLOCKED"
            print(f"\n  ── {category} ({expectation}) {'─' * max(1, 44 - len(category))}")
            print(f"  {'Agent':<28} {'HTTP':<6} {'Result'}")
            print(f"  {'-' * 55}")

        if ua:
            headers = {**BROWSER_HEADERS, "User-Agent": ua}
        else:
            headers = {k: v for k, v in BROWSER_HEADERS.items() if k != "User-Agent"}

        try:
            resp    = requests.get(URL, headers=headers, timeout=10)
            blocked = is_blocked(resp)
            status  = resp.status_code
        except Exception:
            blocked, status = False, 0

        is_good_category = category in GOOD_CATEGORIES
        if is_good_category:
            check_passed = not blocked
            verdict = green("ALLOWED  ✓") if not blocked else red("BLOCKED  ✗  ← RISK")
        else:
            check_passed = blocked
            verdict = green("BLOCKED  ✓") if blocked else red("NOT BLOCKED  ✗  ← WAF gap")

        print(f"  {label:<28} {status:<6} {verdict}")
        by_category.setdefault(category, []).append((label, status, blocked, check_passed))
        time.sleep(0.2)

    # Summary and CheckResults
    print("\n")
    for category, entries in by_category.items():
        passed_count = sum(1 for *_, cp in entries if cp)
        total        = len(entries)
        all_correct  = passed_count == total
        gaps         = [lbl for lbl, _, _, cp in entries if not cp]
        is_good      = category in GOOD_CATEGORIES

        if is_good:
            detail = (
                f"All {total} correctly allowed through"
                if all_correct
                else f"RISK — WAF is incorrectly blocking: {gaps}"
            )
        else:
            detail = (
                f"All {total} correctly blocked"
                if all_correct
                else f"WAF gap — {len(gaps)}/{total} not blocked: {gaps}"
            )

        report.add(CheckResult(
            name=f"User-Agent — {category}",
            passed=all_correct,
            status_code=0,
            detail=detail,
        ))


def main() -> None:
    print("=" * 60)
    print("Test 1 — User-Agent Detection")
    print("Can the WAF correctly block scrapers and attack tools")
    print("while allowing SEO bots, AI crawlers, social preview")
    print("bots, and monitoring agents through?")
    print("=" * 60 + "\n")

    report = Report()
    run(report)
    report.summary()
    report.write_log("test1_user_agent_detection")


if __name__ == "__main__":
    main()
