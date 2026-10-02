"""Drive the live interface in a real browser. Not part of the test suite.

Start `rehub web --port 8765` with an empty REHUB_HOME first, then:
    uv run --no-project --with playwright python scripts/ui_e2e.py
Needs Google Chrome and the tool image. Screenshots go to a temporary directory.
"""

import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = str(Path(__file__).resolve().parents[1])
OUT = tempfile.mkdtemp(prefix="rehub-ui-")
errors = []

with sync_playwright() as p:
    browser = p.chromium.launch(channel="chrome", headless=True)
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
    page.on(
        "console",
        lambda m: (
            errors.append(f"console {m.type}: {m.text}") if m.type in ("error", "warning") else None
        ),
    )
    page.goto("http://127.0.0.1:8765/")
    page.wait_for_selector("#nav button")
    page.screenshot(path=f"{OUT}/l1.png")

    # analyze normal capture through the drop zone input
    page.get_by_role("button", name="Traffic", exact=True).click()
    page.set_input_files("input[type=file]", f"{ROOT}/fixtures/scenarios/plant_normal.pcap")
    page.wait_for_selector(".banner:not(.busy)", timeout=180000)
    page.wait_for_selector(".toolrow")
    print("after analyze banner:", page.inner_text("#banner"))
    page.screenshot(path=f"{OUT}/l2.png")

    # save baseline from the analysis card
    page.fill("input[type=text]", "plant-normal")
    page.get_by_role("button", name="Save baseline").click()
    page.wait_for_selector(".banner:has-text('Saved baseline')", timeout=30000)
    print("baseline banner:", page.inner_text("#banner"))

    # analyze the changed capture
    page.get_by_role("button", name="Traffic", exact=True).click()
    page.set_input_files("input[type=file]", f"{ROOT}/fixtures/scenarios/plant_changed.pcap")
    page.wait_for_selector(".banner:has-text('Analyzed plant_changed')", timeout=180000)
    page.get_by_role("button", name="Changes", exact=True).click()
    page.wait_for_selector(".rung.new-pair")
    print(
        "lit:",
        page.locator(".win.lit").count(),
        "new-pair rungs:",
        page.locator(".rung.new-pair").count(),
        "new-action:",
        page.locator(".rung.new-action").count(),
        "missing:",
        page.locator(".rung.missing-pair").count(),
    )
    page.screenshot(path=f"{OUT}/l3.png")

    # yara scan
    page.get_by_role("button", name="Rules", exact=True).click()
    page.fill("textarea", 'rule T { strings: $a = "P_PROGRAM" condition: $a }')
    page.set_input_files("input[type=file]", f"{ROOT}/fixtures/yara/samples/s7_stop_payload.bin")
    page.get_by_role("button", name="Scan").click()
    page.wait_for_selector(".matches li", timeout=60000)
    print("yara:", page.inner_text(".matches"))
    page.screenshot(path=f"{OUT}/l4.png")

    # doctor
    page.get_by_role("button", name="Doctor", exact=True).click()
    page.get_by_role("button", name="Run doctor").click()
    page.wait_for_selector(".banner:has-text('Every tool matches')", timeout=300000)
    print("doctor:", page.inner_text("#banner"))
    page.get_by_role("button", name="Check tool versions").click()
    page.wait_for_selector(".toolrow:has-text('suricata')", timeout=120000)
    page.screenshot(path=f"{OUT}/l5.png", full_page=True)
    browser.close()

print("screenshots:", OUT)
print("errors:", errors)
raise SystemExit(1 if errors else 0)
