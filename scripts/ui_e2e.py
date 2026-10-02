"""Walk the guided flow in a real browser. Not part of the test suite.

Start `rehub web --port 8765` with an empty REHUB_HOME first, then:
    uv run --no-project --with playwright python scripts/ui_e2e.py
Needs Google Chrome and the tool image. Screenshots go to a temporary directory.
"""

import tempfile

from playwright.sync_api import sync_playwright

OUT = tempfile.mkdtemp(prefix="rehub-ui-")
errors = []


def nxt(page):
    return (
        page.locator(".step.next h2").inner_text()
        if page.locator(".step.next").count()
        else "(none)"
    )


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
    print("lands on:", page.locator("h1").inner_text(), "| next:", nxt(page))
    page.screenshot(path=f"{OUT}/f1.png", full_page=True)

    page.get_by_role("button", name="Check tool versions").click()
    page.wait_for_selector(".step:has-text('Every tool matches')", timeout=120000)
    print("after tools | next:", nxt(page))

    page.locator(".step.next").get_by_role("button", name="plant_normal", exact=True).click()
    page.wait_for_selector(".step.done:has-text('1 capture analyzed')", timeout=180000)
    print("after capture | next:", nxt(page), "| view:", page.locator("h1").inner_text())

    page.fill(".step.next input[type=text]", "plant-normal")
    page.locator(".step.next").get_by_role("button", name="Save baseline").click()
    page.wait_for_selector(".step.done:has-text('Baseline plant-normal')", timeout=30000)
    print("after baseline | next:", nxt(page))
    page.screenshot(path=f"{OUT}/f2.png", full_page=True)

    page.locator(".step.next").get_by_role("button", name="plant_changed", exact=True).click()
    page.wait_for_selector(".step.done:has-text('later capture is ready')", timeout=180000)
    print("after compare | next:", nxt(page))
    page.get_by_role("button", name="See the changes").click()
    page.wait_for_selector(".rung.new-pair")
    print(
        "changes: lit windows:",
        page.locator(".win.lit").count(),
        "| nextline:",
        page.locator(".nextline").inner_text(),
    )
    page.screenshot(path=f"{OUT}/f3.png")
    page.get_by_role("button", name="Go to Start").click()
    page.get_by_role("button", name="Run doctor").click()
    page.wait_for_selector(".step.done:has-text('Every tool matches its golden')", timeout=300000)
    print("after doctor | next:", nxt(page))
    page.screenshot(path=f"{OUT}/f4.png", full_page=True)
    browser.close()
print("screenshots:", OUT)
print("errors:", errors)
raise SystemExit(1 if errors else 0)
