"""
Shared constants, dataclasses, and helpers used by all WAF check scripts.
"""
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import requests

# ── Colour helpers ────────────────────────────────────────────────────────────
# Enable ANSI escape codes on Windows (no-op on Mac/Linux).
if sys.platform == "win32":
    os.system("color")  # activates VT100 processing in the current console session

_GREEN  = "\033[92m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_RESET  = "\033[0m"


def green(text: str) -> str:
    return f"{_GREEN}{text}{_RESET}"


def red(text: str) -> str:
    return f"{_RED}{text}{_RESET}"


def yellow(text: str) -> str:
    return f"{_YELLOW}{text}{_RESET}"

BASE_URL  = "https://www.emedevents.com"
LOGIN_URL = f"{BASE_URL}/login"

LISTING_URLS = [
    f"{BASE_URL}/medical-conferences/medical-conferences-2025",
    f"{BASE_URL}/medical-conferences/medical-conferences-2026",
]

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}


@dataclass
class CheckResult:
    name: str
    passed: bool    # True = WAF behaved correctly; False = gap found
    status_code: int
    detail: str


@dataclass
class Report:
    results: list[CheckResult] = field(default_factory=list)

    def add(self, result: CheckResult) -> None:
        self.results.append(result)
        if result.passed:
            label = green("PASS  ✓")
        else:
            label = red("FAIL  ✗")
        print(f"  {label} [{result.status_code}] {result.name}")
        print(f"         {result.detail}")

    def summary(self) -> None:
        passed = sum(1 for r in self.results if r.passed)
        total  = len(self.results)
        print("\n" + "=" * 60)
        score = green(f"{passed}/{total}") if passed == total else red(f"{passed}/{total}")
        print(f"RESULT: {score} checks passed")
        if passed == total:
            print(green("All checks passed."))
        else:
            gaps = [r.name for r in self.results if not r.passed]
            print(red(f"FAILURES: {', '.join(gaps)}"))
        print("=" * 60)

    def write_log(self, prefix: str) -> None:
        logs_dir = Path(__file__).parent.parent.parent / "logs"
        logs_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path  = logs_dir / f"{prefix}_{timestamp}.log"
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(f"WAF Check — {prefix}\n")
            f.write(f"Target : {BASE_URL}\n")
            f.write(f"Run at : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for r in self.results:
                status = "PASS" if r.passed else "FAIL"
                f.write(f"[{r.status_code}] {r.name}: {status}\n")
                f.write(f"  {r.detail}\n\n")
            passed = sum(1 for r in self.results if r.passed)
            f.write(f"\nRESULT: {passed}/{len(self.results)} checks passed\n")
        print(f"\nLog saved to: {log_path}")


def is_blocked(response: requests.Response) -> bool:
    """Return True if the response looks like a WAF block."""
    if response.status_code in (403, 429, 503):
        return True
    body = response.text.lower()
    return any(k in body for k in ["access denied", "blocked", "captcha", "cloudflare", "ray id"])
