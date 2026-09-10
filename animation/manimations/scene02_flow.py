"""Block 1 — the map builds itself.

A single picture the jury can hold in their head for the rest of the pitch:
many different devices on the left, one chain of five steps in the middle,
usable output on the right. No log text anywhere, and every label is plain
English rather than the project's internal vocabulary.

The plain-English label on each step maps to the real stage name like this,
for anyone answering questions afterwards:

    Preserve   -> vault append   (ulpf-vault)
    Identify   -> pack detect    (ulpf-pack)
    Extract    -> pack extract   (ulpf-decode)
    Translate  -> normalize      (ulpf-ocsf, OCSF 1.9)
    Seal       -> attest         (hash chain + Merkle + Ed25519)

This block only assembles the graph. The record that travels along it, and
what happens when a step fails, are the blocks after this one.
"""

from manim import *

from graph_style import (
    BG,
    LINK,
    NODE_DIM,
    NODE_GOOD,
    NODE_LIT,
    TEXT,
    TEXT_DIM,
    glow_node,
    link,
)

# Where every node sits. Kept as data at the top of the file so the layout can
# be nudged after a review without hunting through the animation calls.
SOURCES = [
    ("Firewall", -6.0, 2.3),
    ("Web proxy", -6.0, 0.9),
    ("IDS sensor", -6.0, -0.5),
    ("VPN gateway", -6.0, -1.9),
]

STAGES = [
    ("Preserve", "keep the original", -3.5, 0.85),
    ("Identify", "which device is this?", -1.75, -0.75),
    ("Extract", "pull out the facts", 0.0, 0.85),
    ("Translate", "into one common shape", 1.75, -0.75),
    ("Seal", "tamper-evident proof", 3.5, 0.85),
]

OUTPUTS = [
    ("Search", "one question, every device", 5.35, 0.75),
    ("Evidence", "provable in court", 5.35, -0.95),
]


class Flow(Scene):
    def construct(self):
        self.camera.background_color = BG

        # ---------------------------------------------------------------- title
        title = Text("How it works", font="Helvetica", weight=BOLD, color=TEXT).scale(0.95)
        self.play(FadeIn(title, shift=UP * 0.3), run_time=0.9)
        self.wait(0.7)
        self.play(title.animate.scale(0.48).to_corner(UL, buff=0.45), run_time=0.8)

        # -------------------------------------------------------- the log sources
        # Small and dim on purpose: individually they are unremarkable, and the
        # point of the scene is that there are many of them.
        sources = VGroup()
        for name, x, y in SOURCES:
            node = glow_node(color=NODE_DIM, radius=0.22, label=name)
            node.core.move_to([x, y, 0])
            node.halo.move_to([x, y, 0])
            node.caption.next_to(node.core, DOWN, buff=0.18)
            node.caption.scale(0.85)
            sources.add(node)

        self.play(
            LaggedStart(*[FadeIn(n, scale=0.6) for n in sources], lag_ratio=0.18),
            run_time=1.4,
        )

        # The devices that are not drawn. A real network has around forty
        # formats; four nodes would quietly understate the problem.
        more = VGroup(
            *[
                Dot(radius=0.06, color=NODE_DIM, fill_opacity=0.45).move_to(
                    [-6.0 + dx, -2.75 + dy, 0]
                )
                for dx, dy in [(-0.42, 0.1), (0.0, -0.05), (0.42, 0.08)]
            ]
        )
        more_label = Text("+ 36 more formats", font="Helvetica", color=TEXT_DIM).scale(0.24)
        more_label.next_to(more, DOWN, buff=0.16)
        self.play(FadeIn(more), FadeIn(more_label), run_time=0.7)
        self.wait(0.5)

        # ----------------------------------------------------------- the five steps
        stages = VGroup()
        for name, sub, x, y in STAGES:
            node = glow_node(color=NODE_DIM, label=name, sub=sub)
            node.shift([x, y, 0] - node.core.get_center())
            stages.add(node)

        outputs = VGroup()
        for name, sub, x, y in OUTPUTS:
            node = glow_node(color=NODE_DIM, radius=0.30, label=name, sub=sub)
            node.shift([x, y, 0] - node.core.get_center())
            outputs.add(node)

        # Every device, whatever it speaks, enters at the same door. This is the
        # single most important line in the picture.
        funnel = VGroup(*[link(s, stages[0]) for s in sources])
        self.play(
            LaggedStart(*[Create(e) for e in funnel], lag_ratio=0.12),
            run_time=1.0,
        )
        self.play(FadeIn(stages[0], scale=0.7), run_time=0.6)
        self.wait(0.4)

        # The chain grows one step at a time, so the eye follows the order.
        chain = VGroup()
        for i in range(1, len(stages)):
            edge = link(stages[i - 1], stages[i])
            chain.add(edge)
            self.play(Create(edge), run_time=0.45)
            self.play(FadeIn(stages[i], scale=0.7), run_time=0.55)

        self.wait(0.4)

        # --------------------------------------------------------------- outputs
        tails = VGroup(*[link(stages[-1], o) for o in outputs])
        self.play(
            LaggedStart(*[Create(e) for e in tails], lag_ratio=0.15),
            run_time=0.8,
        )
        self.play(
            LaggedStart(*[FadeIn(o, scale=0.7) for o in outputs], lag_ratio=0.2),
            run_time=0.9,
        )
        self.wait(0.8)

        # ------------------------------------------------------------ the one line
        summary = Text(
            "Anything in.  One shape out.  Nothing lost on the way.",
            font="Helvetica",
            weight=BOLD,
            color=NODE_LIT,
        ).scale(0.42)
        summary.to_edge(DOWN, buff=0.45)
        self.play(FadeIn(summary, shift=UP * 0.2), run_time=0.8)
        self.wait(2.2)
