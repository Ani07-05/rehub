import subprocess
from pathlib import Path

RULES_URL = "https://github.com/Yara-Rules/rules"
RULES_SHA = "0f93570194a80d2f2032869055808b0ddcdfb360"
LICENSE_NOTE = (
    "Yara-Rules is GPL-2.0 and written for legacy YARA. It is fetched into your directory only "
    "and is not bundled with rehub. Some rules may not compile under YARA-X."
)


class FetchError(RuntimeError):
    pass


def _git(*args: str) -> None:
    proc = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise FetchError(f"git {args[0]} failed: {proc.stderr.strip()}")


def fetch(dest: Path, url: str = RULES_URL, sha: str = RULES_SHA) -> None:
    if dest.exists() and any(dest.iterdir()):
        raise FetchError(f"{dest} exists and is not empty")
    _git("clone", "--quiet", url, str(dest))
    _git("-C", str(dest), "checkout", "--quiet", sha)
