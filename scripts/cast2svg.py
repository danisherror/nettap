#!/usr/bin/env python3
"""Turn an asciinema v2 recording into an animated SVG for the README.

    python scripts/cast2svg.py demo.cast docs/demo-inspect.svg

Only handles what scripts/record_demo.sh produces: lines of text, colour
and bold from SGR escapes, typed input and scrolling. The SVG loops with
CSS animations, which GitHub shows in an <img>. No dependencies.
"""
from __future__ import annotations

import json
import re
import sys
from html import escape

FONT_SIZE = 13
LINE_H = 17
CHAR_W = 7.8          # 0.6em, the usual monospace advance
PAD = 14
TITLE_H = 28
HOLD = 5.0            # seconds the last frame stays before the loop restarts
COLORS = {"30": "#3b3b3b", "31": "#f14c4c", "32": "#23d18b", "33": "#e5e510",
          "34": "#3b8eea", "35": "#d670d6", "36": "#29b8db", "37": "#e5e5e5"}
FG, BG = "#d4d4d4", "#1e1e1e"
SGR = re.compile(r"\x1b\[([0-9;]*)m")
OTHER_ESC = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def parse(path: str):
    """(cols, rows, lines, end): lines are lists of (time, char, style)."""
    with open(path) as f:
        header = json.loads(f.readline())
        events = [json.loads(line) for line in f if line.strip()]
    cols, rows = header["width"], header["height"]
    lines, cur, style = [], [], (FG, False)
    for t, kind, data in events:
        if kind != "o":
            continue
        pos = 0
        for m in SGR.finditer(data):
            _feed(data[pos:m.start()], t, style, cur, lines, cols)
            style = _apply(m.group(1), style)
            pos = m.end()
        _feed(data[pos:], t, style, cur, lines, cols)
    if cur:
        lines.append(list(cur))
    end = events[-1][0] if events else 0
    return cols, rows, lines, end


def _feed(text, t, style, cur, lines, cols):
    for ch in OTHER_ESC.sub("", text):
        if ch == "\n":
            lines.append(list(cur) or [(t, "", style)])
            cur.clear()
        elif ch == "\r":
            continue
        elif ch >= " ":
            if len(cur) == cols:  # the terminal wraps long lines
                lines.append(list(cur))
                cur.clear()
            cur.append((t, ch, style))


def _apply(params: str, style):
    fg, bold = style
    for p in (params or "0").split(";"):
        if p in ("", "0"):
            fg, bold = FG, False
        elif p == "1":
            bold = True
        elif p == "22":
            bold = False
        elif p == "39":
            fg = FG
        elif p in COLORS:
            fg = COLORS[p]
    return fg, bold


def _pct(t: float, total: float) -> str:
    return f"{min(100.0, 100.0 * t / total):.3f}%"


def render(cols, rows, lines, end) -> str:
    total = end + HOLD
    width = cols * CHAR_W + 2 * PAD
    height = rows * LINE_H + 2 * PAD + TITLE_H
    css, body = [], []

    def appear(cls, t):
        css.append(f"@keyframes {cls}{{0%{{fill-opacity:0}}{_pct(t, total)}{{fill-opacity:1}}"
                   f"100%{{fill-opacity:1}}}}.{cls}{{fill-opacity:0;animation:{cls} {total:.2f}s "
                   f"steps(1,end) infinite}}")

    for i, line in enumerate(lines):
        y = (i + 1) * LINE_H
        typed = len({t for t, _, _ in line}) > 3   # characters arrived one by one
        spans = []
        # group runs of the same style (and, when typed, the same time)
        runs: list[list] = []
        for t, ch, style in line:
            if runs and runs[-1][1] == style and (not typed or runs[-1][0] == t):
                runs[-1][2] += ch
            else:
                runs.append([t, style, ch])
        for j, (t, (fg, bold), text) in enumerate(runs):
            attrs = f' fill="{fg}"' if fg != FG else ""
            attrs += ' font-weight="bold"' if bold else ""
            if typed:
                cls = f"c{i}_{j}"
                appear(cls, t)
                attrs += f' class="{cls}"'
            spans.append(f"<tspan{attrs}>{escape(text)}</tspan>")
        line_attr = ""
        if not typed:
            appear(f"l{i}", line[0][0] if line else 0)
            line_attr = f' class="l{i}"'
        body.append(f'<text y="{y}"{line_attr}>{"".join(spans)}</text>')

    # scroll up one line each time a line past the last row starts
    steps = [f"0%{{transform:translateY(0)}}"]
    for i, line in enumerate(lines[rows:], start=rows):
        t = line[0][0] if line else 0
        steps.append(f"{_pct(t, total)}{{transform:translateY({-(i - rows + 1) * LINE_H}px)}}")
    steps.append(f"100%{{transform:translateY({-max(0, len(lines) - rows) * LINE_H}px)}}")
    css.append(f"@keyframes scroll{{{''.join(steps)}}}"
               f".scroll{{animation:scroll {total:.2f}s steps(1,end) infinite}}")

    dots = "".join(f'<circle cx="{PAD + 6 + k * 18}" cy="{TITLE_H / 2 + 2}" r="6" fill="{c}"/>'
                   for k, c in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")))
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" \
viewBox="0 0 {width:.0f} {height:.0f}" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,\
'DejaVu Sans Mono',monospace" font-size="{FONT_SIZE}" fill="{FG}">
<style>text{{white-space:pre}}{''.join(css)}</style>
<rect width="100%" height="100%" rx="8" fill="{BG}"/>{dots}
<svg x="{PAD}" y="{TITLE_H + PAD - 4}" width="{cols * CHAR_W:.0f}" height="{rows * LINE_H + 4}">
<g class="scroll" xml:space="preserve">
{chr(10).join(body)}
</g></svg></svg>
"""


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    with open(argv[2], "w") as f:
        f.write(render(*parse(argv[1])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
