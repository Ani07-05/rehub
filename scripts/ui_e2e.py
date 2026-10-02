"""Walk the whole interface in a real browser. Not part of the test suite.

Start `rehub web --port 8765` with an empty REHUB_HOME first, then:
    uv run --no-project --with playwright python scripts/ui_e2e.py
Needs Google Chrome and the tool image. Screenshots go to a temporary directory.
"""

import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

OUT = tempfile.mkdtemp(prefix="rehub-ui-")
ROOT = str(Path(__file__).resolve().parents[1])
errors = []

with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome", headless=True)
    page = browser.new_page(viewport={"width": 1440, "height": 1100})
    page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
    page.on(
        "console",
        lambda m: (
            errors.append(f"console {m.type}: {m.text}") if m.type in ("error", "warning") else None
        ),
    )
    page.goto("http://127.0.0.1:8765/")
    page.wait_for_selector(".step")
    print("title:", page.locator("h1").inner_text())
    print("data card:", page.locator(".datapaths").inner_text().replace("\n", " | ")[:140])
    page.screenshot(path=f"{OUT}/n1.png", full_page=True)

    # help assistant: chip answers from the manual, no model
    page.get_by_role("button", name="Ask for help").click()
    page.get_by_role("button", name="Where is my data stored?").click()
    page.wait_for_selector("#help .a:has-text('rehub.db')")
    print("help answer ok:", "rehub.db" in page.locator("#help .log").inner_text())
    page.fill("#help input[aria-label='Your question']", "how tall is the eiffel tower")
    page.get_by_role("button", name="Ask", exact=True).click()
    page.wait_for_selector("#help:has-text('Ask the AI model instead')")
    print("unknown question falls back, no guessing")
    page.screenshot(path=f"{OUT}/n2.png")
    page.get_by_role("button", name="Ask for help").click()

    # normal flow with samples on the Start page
    page.locator(".step.next").get_by_role("button", name="Check tool versions").click()
    page.wait_for_selector(".step:has-text('All tools are the expected versions')", timeout=120000)
    page.locator(".step.next").get_by_role("button", name="normal", exact=False).first.click()
    page.wait_for_selector(".step.done:has-text('1 recording loaded')", timeout=180000)
    page.fill(".step.next input[type=text]", "plant-normal")
    page.locator(".step.next").get_by_role("button", name="Save as normal").click()
    page.wait_for_selector(".step.done:has-text('Snapshot plant-normal')", timeout=30000)
    page.locator(".step.next").get_by_role("button", name="plant changed").click()
    page.wait_for_selector(".step.done:has-text('newer recording is ready')", timeout=180000)
    page.get_by_role("button", name="See what changed").click()
    page.wait_for_selector(".changes li")
    print("plain words:")
    for t in page.locator(".changes .said").all_inner_texts():
        print("  -", t)
    page.screenshot(path=f"{OUT}/n3.png", full_page=True)

    # PLC code: approve v1, then check the updated program
    page.get_by_role("button", name="PLC code", exact=True).click()
    page.set_input_files("input[type=file]", f"{ROOT}/fixtures/plc/boiler_approved.st")
    page.get_by_role("button", name="Check program").click()
    page.wait_for_selector("text=No approved version to compare with")
    page.get_by_role("button", name="Approve this version").click()
    page.wait_for_selector(".banner:has-text('Approved boiler_approved')")
    page.set_input_files("input[type=file]", f"{ROOT}/fixtures/plc/boiler_updated.st")
    page.fill("input[placeholder=boiler_updated]", "boiler_approved")
    page.get_by_role("button", name="Check program").click()
    page.wait_for_selector("text=Compared with the approved version of boiler_approved")
    print("plc findings:", page.locator(".finding h4").all_inner_texts())
    print("value change:", page.locator(".diffline.val").all_inner_texts())
    page.screenshot(path=f"{OUT}/n4.png", full_page=True)
    browser.close()
print("screenshots:", OUT)
print("errors:", errors)
raise SystemExit(1 if errors else 0)
