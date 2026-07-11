#!/usr/bin/env python3
"""
redact.py — produce publication-safe copies of the committed screenshots.

The live-capture figures show real device data from the operator's **own**
authorised LAN: the operator's hostname (``santhas-MacBook-Air[.local]``) and
MAC addresses (mostly OS-randomised, but real). None of this is third-party
data, but a published figure should not carry the operator's machine name or
hardware addresses. This script blurs those regions and writes ``*-redacted.png``
copies alongside the originals — the originals are kept for the operator's own
reference; the ``-redacted`` copies are the ones to publish.

It is deliberately data-driven and conservative: each region is a generously
sized box (over-covering is safe — better to hide a little too much than to leak
an address), and the transform is a heavy Gaussian blur + darken so the redaction
is visually obvious (the reader sees that something was hidden, not a suspicious
clean gap). Regions are expressed in the **original** pixel space of each frame
(the desktop frames are 3024×1900, captured at native 2×).

Run:  python docs/screenshots/redact.py [--check]

``--check`` verifies every referenced source exists and every region is inside
the image bounds, without writing anything (used in CI-style sanity checks).
"""

from __future__ import annotations

import argparse
import os
import sys

from PIL import Image, ImageFilter

_HERE = os.path.dirname(os.path.abspath(__file__))

# Each entry: filename -> list of (x0, y0, x1, y1) boxes in ORIGINAL pixels.
# Coordinates were read off the 2× captures; boxes are padded for safety.
#
# What each box covers:
#   * sidebar "THIS DEVICE → Host" value  — the operator hostname
#   * the "scanning from … · <hostname>" line in the standby panel
#   * the asset-matrix MAC column          — real (mostly randomised) MACs
#   * the one resolved-hostname cell / node label for the operator's own machine
REGIONS: dict[str, list[tuple[int, int, int, int]]] = {
    "command-center-standby.png": [
        (110, 528, 515, 580),      # sidebar THIS DEVICE host
        (1795, 1415, 2245, 1465),  # centre "scanning from … · santhas-MacBook-Air.local"
    ],
    "privilege-elevation.png": [
        (110, 528, 515, 580),      # sidebar THIS DEVICE host
        (1795, 1415, 2245, 1465),  # centre "scanning from … · <hostname>"
    ],
    "scan-live.png": [
        (110, 565, 515, 620),      # sidebar THIS DEVICE host (MACs/hostnames not yet populated)
    ],
    "scan-complete.png": [
        (110, 515, 515, 570),      # sidebar THIS DEVICE host
        (1885, 855, 2148, 1900),   # MAC column (all rows)
        (960, 1378, 1240, 1428),   # .154 row resolved hostname (operator machine)
    ],
    "topology.png": [
        (110, 512, 515, 565),      # sidebar THIS DEVICE host
        (1970, 1378, 2230, 1430),  # .154 node label (operator machine)
    ],
    # mobile.png (1170×2532) shows only the KPI strip + filter toolbar in the
    # captured crop — no hostname or MAC on screen — so it needs no redaction.
}


def _redact_box(img: Image.Image, box: tuple[int, int, int, int]) -> None:
    """Blur + darken one region in place so the underlying text is unrecoverable."""
    x0, y0, x1, y1 = box
    x0, y0 = max(0, x0), max(0, y0)
    x1, y1 = min(img.width, x1), min(img.height, y1)
    if x1 <= x0 or y1 <= y0:
        return
    region = img.crop((x0, y0, x1, y1))
    # A blur radius proportional to the box height guarantees the glyphs smear
    # past recognition even at 2× resolution; the darken removes residual contrast.
    radius = max(12, (y1 - y0) // 2)
    region = region.filter(ImageFilter.GaussianBlur(radius))
    region = region.point(lambda p: int(p * 0.45))  # darken to ~45 %
    img.paste(region, (x0, y0))


def _out_path(src: str) -> str:
    stem, ext = os.path.splitext(src)
    return f"{stem}-redacted{ext}"


def check() -> int:
    """Validate sources exist and boxes are in-bounds; write nothing."""
    problems = 0
    for name, boxes in REGIONS.items():
        path = os.path.join(_HERE, name)
        if not os.path.exists(path):
            print(f"  MISSING source: {name}", file=sys.stderr)
            problems += 1
            continue
        with Image.open(path) as im:
            w, h = im.size
        for b in boxes:
            x0, y0, x1, y1 = b
            if not (0 <= x0 < x1 <= w and 0 <= y0 < y1 <= h):
                print(f"  OUT-OF-BOUNDS {name} {b} (image {w}×{h})", file=sys.stderr)
                problems += 1
    if problems:
        print(f"redact --check: {problems} problem(s)", file=sys.stderr)
        return 1
    print(f"redact --check: OK — {len(REGIONS)} frames, all regions in bounds")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Blur operator hostname/MACs in committed screenshots")
    ap.add_argument("--check", action="store_true",
                    help="validate sources + region bounds without writing")
    args = ap.parse_args(argv)
    if args.check:
        return check()

    written = 0
    for name, boxes in REGIONS.items():
        src = os.path.join(_HERE, name)
        if not os.path.exists(src):
            print(f"  skip (missing): {name}", file=sys.stderr)
            continue
        with Image.open(src) as im:
            img = im.convert("RGB")
            for b in boxes:
                _redact_box(img, b)
            out = _out_path(src)
            img.save(out)
        print(f"  → {os.path.basename(out)}  ({len(boxes)} region(s) blurred)")
        written += 1
    print(f"redacted {written} frame(s); publish the *-redacted.png copies.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
