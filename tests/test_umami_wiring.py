"""Umami analytics wiring: tracker snippet, event attributes, CSP and pinned image."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
COMPOSE = (ROOT / "deploy" / "umami" / "compose.yml").read_text(encoding="utf-8")
HOST = "https://umami.sandfort.dev"
UMAMI_ID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def test_landing_loads_the_tracker_once_for_the_landing_host() -> None:
    tags = re.findall(r"<script\b[^>]*umami[^>]*>", INDEX)
    assert len(tags) == 1
    assert f'src="{HOST}/script.js"' in tags[0]
    assert "defer" in tags[0]
    assert re.search(rf'data-website-id="(UMAMI_WEBSITE_ID|{UMAMI_ID})"', tags[0])
    assert 'data-domains="sandfort.dev"' in tags[0]


def test_landing_quickstart_copy_button_sends_its_event() -> None:
    buttons = re.findall(r"<button\b[^>]*data-copy[^>]*>", INDEX)
    assert buttons
    assert all('data-umami-event="quickstart_copy"' in b for b in buttons)


def test_every_beta_request_mailto_link_sends_its_event_with_a_placement() -> None:
    links = re.findall(
        r"<a\b[^>]*href=\"mailto:office@sandfort\.dev\?subject=Sandfort[^>]*>", INDEX
    )
    assert len(links) == 4
    placements = []
    for link in links:
        assert 'data-umami-event="beta_request"' in link
        placements.append(re.search(r'data-umami-event-placement="(\w+)"', link).group(1))
    assert placements == ["nav", "hero", "cta", "footer"]


def test_umami_image_is_pinned_by_digest() -> None:
    image = re.search(r"image:\s*(ghcr\.io/umami-software/umami\S*)", COMPOSE)
    assert image is not None
    assert re.search(r"@sha256:[0-9a-f]{64}$", image.group(1))
