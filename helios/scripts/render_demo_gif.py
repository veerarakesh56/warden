"""Render a typewriter-style animated GIF of the canonical `make demo` flow.

Produces docs/demo.gif from a hard-coded transcript of real `make demo` output.
This is a v0.1.0 stop-gap until a live terminal recording is captured.

Run:
    python scripts/render_demo_gif.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

# (text-to-append, delay-ms-after-frame). Use "" + delay for pure-pause frames.
SCRIPT: list[tuple[str, int]] = [
    ("$ git clone https://github.com/veerarakesh56/helios && cd helios\n", 600),
    ("Cloning into 'helios'...\n", 400),
    ("$ make demo\n", 600),
    ("cargo build --bin helios\n", 400),
    ("    Finished `dev` profile [unoptimized] target(s) in 0.81s\n", 600),
    ("cargo run -q -p helios-cli -- simulate fixtures/three-tier-webapp \\\n", 350),
    ("    --scenario fixtures/scenarios/az-outage.yaml --json \\\n", 350),
    ("    | cargo run -q -p helios-cli -- explain\n", 700),
    ("\n", 200),
    ("# Failure narrative for lose-us-east-1a\n", 500),
    ("\n", 200),
    ("Three resources fail when us-east-1a goes dark:\n", 500),
    ("  - aws_subnet.public_a (single-AZ in us-east-1a)\n", 400),
    ("  - aws_instance.web   (subnet propagation)\n", 400),
    ("  - aws_elasticache_cluster.cache (single-AZ default)\n", 700),
    ("\n", 200),
    ("cargo run -q -p helios-cli -- verify fixtures/three-tier-webapp \\\n", 350),
    ("    --scenario fixtures/scenarios/az-outage.yaml \\\n", 350),
    ("    --fix fixes/az-outage.json\n", 700),
    ("\n", 200),
    ("Scenario: lose-us-east-1a\n", 400),
    ("Pre-fix failures:  3\n", 400),
    ("Post-fix failures: 0\n", 600),
    ("\n", 200),
    ("Resolved (3):\n", 400),
    ("  [OK] aws_elasticache_cluster.cache\n", 400),
    ("  [OK] aws_instance.web\n", 400),
    ("  [OK] aws_subnet.public_a\n", 800),
    ("\n", 200),
    ("# Engine re-verified the fix. Safe to ship.\n", 1500),
]

# Terminal styling.
COLS = 78
ROWS = 22
PAD = 16
LINE_HEIGHT = 18
CHAR_WIDTH = 9
BG = (24, 26, 32)
FG = (220, 220, 220)
PROMPT_FG = (130, 200, 130)
COMMENT_FG = (140, 170, 220)
OK_FG = (130, 200, 130)


def load_font() -> ImageFont.ImageFont:
    candidates = [
        r"C:\Windows\Fonts\consola.ttf",
        r"C:\Windows\Fonts\cour.ttf",
        "/System/Library/Fonts/Menlo.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    ]
    for p in candidates:
        try:
            return ImageFont.truetype(p, 14)
        except OSError:
            continue
    return ImageFont.load_default()


def line_color(line: str) -> tuple[int, int, int]:
    if line.startswith("$ "):
        return PROMPT_FG
    if line.startswith("# "):
        return COMMENT_FG
    if "[OK]" in line:
        return OK_FG
    return FG


def render_frame(font, text: str) -> Image.Image:
    width = COLS * CHAR_WIDTH + PAD * 2
    height = ROWS * LINE_HEIGHT + PAD * 2
    img = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(img)
    lines = text.split("\n")
    visible = lines[-ROWS:] if len(lines) > ROWS else lines
    y = PAD
    for line in visible:
        draw.text((PAD, y), line, fill=line_color(line), font=font)
        y += LINE_HEIGHT
    return img


def main() -> int:
    out_path = Path(__file__).resolve().parent.parent / "docs" / "demo.gif"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    font = load_font()
    frames: list[Image.Image] = []
    durations: list[int] = []

    accumulated = ""
    for chunk, delay in SCRIPT:
        if chunk:
            accumulated += chunk
        frames.append(render_frame(font, accumulated))
        durations.append(delay)

    # Hold final frame longer.
    if frames:
        frames.append(frames[-1])
        durations.append(2500)

    frames[0].save(
        out_path,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=False,
        disposal=2,
    )
    print(f"wrote {out_path} ({out_path.stat().st_size} bytes, {len(frames)} frames)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
