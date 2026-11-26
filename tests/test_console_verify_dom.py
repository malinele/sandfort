"""The console page script run in node against a stub dom: verify results never go stale.

The verify result is the page's one integrity signal, so it must belong to the current key
and to the current call. A response that lands after the key changed is dropped, and a new
call empties the previous summary before it starts.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from sandfort.api.console_assets import NONCE_TOKEN, PAGE

needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

HARNESS = r"""
const fs = require("fs");
const src = fs.readFileSync(process.argv[2], "utf8");
function el(id) {
  return {id, children: [], className: "", textContent: "", disabled: false, value: "",
    listeners: {},
    replaceChildren() { this.children = []; },
    insertRow() {
      const r = {className: "", cells: [],
        insertCell() { const c = {textContent: ""}; this.cells.push(c); return c; },
        appendChild(c) { this.cells.push(c); }};
      this.children.push(r);
      return r;
    },
    addEventListener(t, f) { this.listeners[t] = f; }};
}
const els = {};
const document = {hidden: false, listeners: {},
  getElementById(id) { return els[id] || (els[id] = el(id)); },
  createElement() { return {textContent: ""}; },
  addEventListener(t, f) { this.listeners[t] = f; }};
const okChain = {data: {ok: true, checked: 2, last_id: "aud_2", last_hash: "abc",
  findings: [], findings_truncated: false}};
let verifyMode = "ok";
let release = null;
async function fetch(path, opts) {
  if (path === "/v1/audit-events/verify") {
    if (verifyMode === "fail") { return {ok: false, status: 500, json: async () => ({})}; }
    if (verifyMode === "hold" || verifyMode === "holdfail") {
      await new Promise((r) => { release = r; });
    }
    if (verifyMode === "holdfail") { return {ok: false, status: 500, json: async () => ({})}; }
    return {ok: true, status: 200, json: async () => okChain};
  }
  return {ok: true, status: 200, json: async () => ({data: []})};
}
new Function("document", "fetch", "setInterval", "clearInterval", src)(
  document, fetch, () => 1, () => {});
const tick = () => new Promise((r) => setTimeout(r, 10));
function connect(key) {
  document.getElementById("key").value = key;
  els["keyform"].listeners.submit({preventDefault() {}});
}
function snap() {
  return {status: els["verify-status"].textContent,
    statusClass: els["verify-status"].className,
    summaryRows: els["verify-summary"].children.length,
    disabled: els["verify-button"].disabled};
}
(async () => {
  const out = {};
  connect("sf_a");
  await tick();
  await els["verify-button"].listeners.click();
  out.ok = snap();
  verifyMode = "fail";
  await els["verify-button"].listeners.click();
  out.failAfterOk = snap();
  verifyMode = "hold";
  const pending = els["verify-button"].listeners.click();
  await tick();
  connect("sf_b");
  await tick();
  release();
  await pending;
  out.staleAfterKeyChange = snap();
  verifyMode = "holdfail";
  const failing = els["verify-button"].listeners.click();
  await tick();
  connect("sf_c");
  await tick();
  release();
  await failing;
  out.staleErrorAfterKeyChange = snap();
  console.log(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
"""


def page_script() -> str:
    match = re.search(rf'<script nonce="{NONCE_TOKEN}">(.*?)</script>', PAGE, re.S)
    assert match is not None
    return match.group(1)


def run_page(tmp_path: Path) -> dict[str, Any]:
    script = tmp_path / "page.js"
    harness = tmp_path / "harness.js"
    script.write_text(page_script(), encoding="utf-8")
    harness.write_text(HARNESS, encoding="utf-8")
    node = shutil.which("node")
    assert node is not None
    done = subprocess.run(
        [node, str(harness), str(script)], capture_output=True, text=True, check=True, timeout=30
    )
    result: dict[str, Any] = json.loads(done.stdout.strip().splitlines()[-1])
    return result


@needs_node
def test_verify_renders_the_summary_for_the_current_key(tmp_path: Path) -> None:
    ok = run_page(tmp_path)["ok"]
    assert ok["status"] == "chain ok"
    assert ok["statusClass"] == ""
    assert ok["summaryRows"] > 0
    assert ok["disabled"] is False


@needs_node
def test_a_failed_verify_empties_the_previous_summary(tmp_path: Path) -> None:
    failed = run_page(tmp_path)["failAfterOk"]
    assert failed["statusClass"] == "error"
    assert "HTTP 500" in failed["status"]
    assert failed["summaryRows"] == 0
    assert failed["disabled"] is False


@needs_node
def test_a_verify_answer_for_an_older_key_is_dropped(tmp_path: Path) -> None:
    stale = run_page(tmp_path)["staleAfterKeyChange"]
    assert stale["status"] != "chain ok"
    assert stale["summaryRows"] == 0
    assert stale["disabled"] is False


@needs_node
def test_a_verify_error_for_an_older_key_is_dropped(tmp_path: Path) -> None:
    stale = run_page(tmp_path)["staleErrorAfterKeyChange"]
    assert "HTTP 500" not in stale["status"]
    assert stale["statusClass"] == ""
    assert stale["disabled"] is False


def test_main_status_error_is_red() -> None:
    assert "#status.error{color:#f85149}" in PAGE
