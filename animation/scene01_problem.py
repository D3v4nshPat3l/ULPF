"""Scene 1 — The problem: every device speaks a different language.

Three real perimeter devices describe the same kind of event — a network
connection — in three mutually incompatible formats. The point of the scene is
that a security analyst asking one question ("show me everything from
10.2.4.7") has to know all three, and the other forty in the building.

Every log line here is a genuine format, not invented for the animation.
"""

from manim import *

# Palette shared across every scene in this project, so the whole animation
# reads as one piece rather than five unrelated clips.
INK = "#15181f"
PAPER = "#f7f8fa"
ACCENT = "#0a5ca8"
GOOD = "#0f6b4f"
WARN = "#8a5a00"
BAD = "#a52f22"
MUTED = "#6b7280"


def glyphs_for(text_mobject, source: str, fragment: str):
    """Return the glyphs of `text_mobject` that render `fragment`.

    A Manim `Text` does not index its glyphs the way Python indexes the source
    string: spaces produce no glyph at all, so `"abc def"` is seven characters
    but only six glyphs. Slicing by the raw string offset therefore selects the
    wrong characters on any line containing a space — which highlighted
    `2.4.7 TC` instead of the address on the Squid line.

    Offsetting by the number of spaces before the fragment fixes it. There is no
    `get_part_by_text` on `Text` in Manim 0.19 (it belongs to `MarkupText`), so
    this is the portable way to do it.
    """
    start = source.index(fragment)
    glyph_start = start - source[:start].count(" ")
    glyph_len = len(fragment) - fragment.count(" ")
    return text_mobject[glyph_start : glyph_start + glyph_len]


class Problem(Scene):
    def construct(self):
        self.camera.background_color = PAPER

        # ---------------------------------------------------------------- title
        title = Text("The problem", font="Helvetica", weight=BOLD, color=INK).scale(0.9)
        subtitle = Text(
            "Every device describes the same event differently",
            font="Helvetica",
            color=MUTED,
        ).scale(0.42)
        subtitle.next_to(title, DOWN, buff=0.25)
        header = VGroup(title, subtitle)

        self.play(FadeIn(title, shift=UP * 0.3), run_time=0.8)
        self.play(FadeIn(subtitle), run_time=0.6)
        self.wait(0.6)
        self.play(header.animate.scale(0.6).to_edge(UP, buff=0.4), run_time=0.8)

        # ------------------------------------------------------- the three logs
        # Each entry: vendor label, the log line, and the fragment to highlight.
        devices = [
            (
                "Fortinet firewall",
                "srcip=10.2.4.7 srcport=40589 dstip=8.8.8.8 action=accept",
                "srcip=10.2.4.7",
            ),
            (
                "Squid web proxy",
                "1756636800.123 152 10.2.4.7 TCP_MISS/200 12345 GET http://x.com",
                "10.2.4.7",
            ),
            (
                "Suricata IDS",
                '{"src_ip":"10.2.4.7","dest_port":443,"event_type":"alert"}',
                '"10.2.4.7"',
            ),
        ]

        rows = VGroup()
        for vendor, line, _ in devices:
            label = Text(vendor, font="Helvetica", weight=BOLD, color=ACCENT).scale(0.33)
            code = Text(line, font="Menlo", color=INK).scale(0.29)
            code.next_to(label, DOWN, buff=0.14, aligned_edge=LEFT)

            block = VGroup(label, code)
            box = SurroundingRectangle(
                block, buff=0.22, corner_radius=0.08, color="#d8dce5", stroke_width=1.5
            )
            box.set_fill("#ffffff", opacity=1).set_z_index(-1)
            rows.add(VGroup(box, block))

        rows.arrange(DOWN, buff=0.38, aligned_edge=LEFT)
        rows.next_to(header, DOWN, buff=0.55)

        for row in rows:
            self.play(FadeIn(row, shift=RIGHT * 0.25), run_time=0.55)
        self.wait(0.8)

        # ------------------------------------------- they all mean the same thing
        # Highlight the same address in all three, to make the point visually
        # rather than by assertion.
        highlights = VGroup()
        for row, (_, line, fragment) in zip(rows, devices):
            code = row[1][1]
            piece = glyphs_for(code, line, fragment)
            piece.set_color(BAD)
            highlights.add(SurroundingRectangle(piece, buff=0.05, color=BAD, stroke_width=2))

        self.play(LaggedStart(*[Create(h) for h in highlights], lag_ratio=0.25), run_time=1.2)

        same = Text(
            "Same address. Same kind of event. Three formats.",
            font="Helvetica",
            weight=BOLD,
            color=BAD,
        ).scale(0.4)
        same.next_to(rows, DOWN, buff=0.45)
        self.play(FadeIn(same, shift=UP * 0.2), run_time=0.7)
        self.wait(1.4)

        # -------------------------------------------------------- the real cost
        self.play(FadeOut(same), FadeOut(highlights), run_time=0.5)

        cost = VGroup(
            Text("~40 formats in a typical network", font="Helvetica", color=INK).scale(0.42),
            Text(
                "A hand-written parser for each one",
                font="Helvetica",
                color=INK,
            ).scale(0.42),
            Text(
                "Every firmware update can break them",
                font="Helvetica",
                color=BAD,
                weight=BOLD,
            ).scale(0.42),
        ).arrange(DOWN, buff=0.22)
        cost.next_to(rows, DOWN, buff=0.45)

        for item in cost:
            self.play(FadeIn(item, shift=UP * 0.15), run_time=0.5)
        self.wait(2.0)

        self.play(FadeOut(VGroup(rows, cost, header)), run_time=0.8)
        self.wait(0.3)
