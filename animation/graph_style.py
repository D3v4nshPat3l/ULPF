"""Shared Obsidian-style graph vocabulary for every ULPF animation block.

The jury is largely non-technical, so the visual language has to carry the
explanation on its own: a viewer should follow what is happening without
reading a single log line. Obsidian's graph view is the reference — a dark
canvas, soft glowing circular nodes, thin low-contrast links, and labels that
sit quietly under each node rather than competing with it.

Every block imports from here, so the scenes read as one film rather than a
handful of unrelated clips.
"""

from manim import *

# ----------------------------------------------------------------- palette
# Obsidian's own dark theme, sampled: near-black canvas, muted violet accent,
# links dim enough to recede behind the nodes they connect.
BG = "#1b1b1f"
NODE_DIM = "#4a4458"
NODE_LIT = "#a78bfa"
NODE_GOOD = "#4ade80"
NODE_WARN = "#fbbf24"
NODE_BAD = "#f87171"
LINK = "#3a3a42"
LINK_LIT = "#6d6487"
TEXT = "#d4d4d8"
TEXT_DIM = "#71717a"

# Resting radius of a standard pipeline node.
R = 0.40


def glow_node(color=NODE_DIM, radius=R, label=None, sub=None, layers=4):
    """One graph node: a filled circle wrapped in soft concentric glow.

    Manim has no bloom filter, so the glow is faked the way it usually is —
    several progressively larger circles at low opacity stacked behind the
    core. Four layers is where it stops reading as distinct rings and starts
    reading as light.

    The parts are exposed as attributes (`.core`, `.halo`, `.caption`) rather
    than left to positional indexing, because whether a node has a label or a
    sub-label changes what `node[2]` means — and that is exactly the kind of
    silent off-by-one that produced a wrong highlight in scene 1.
    """
    core = Circle(radius=radius, color=color, fill_opacity=1, stroke_width=0)

    halo = VGroup()
    for i in range(1, layers + 1):
        halo.add(
            Circle(
                radius=radius * (1 + 0.30 * i),
                color=color,
                fill_opacity=0.11 / i,
                stroke_width=0,
            )
        )
    halo.set_z_index(-1)

    node = VGroup(core, halo)
    node.core = core
    node.halo = halo
    node.caption = None

    below = core
    if label:
        caption = Text(label, font="Helvetica", weight=BOLD, color=TEXT).scale(0.30)
        caption.next_to(core, DOWN, buff=0.24)
        node.add(caption)
        node.caption = caption
        below = caption
    if sub:
        detail = Text(sub, font="Helvetica", color=TEXT_DIM).scale(0.225)
        detail.next_to(below, DOWN, buff=0.10)
        node.add(detail)

    return node


def link(a, b, color=LINK, width=2.5, opacity=1.0):
    """A link drawn between the *edges* of two nodes, not their centres.

    Centre-to-centre looks identical until a node is recoloured or shrinks, at
    which point the stale line shows through it. Reading each radius from the
    circle's current width rather than from `R` also lets small source nodes
    and full-size stage nodes share this one function.
    """
    start, end = a.core.get_center(), b.core.get_center()
    direction = normalize(end - start)
    line = Line(
        start + direction * (a.core.width / 2),
        end - direction * (b.core.width / 2),
        color=color,
        stroke_width=width,
    )
    line.set_stroke(opacity=opacity)
    line.set_z_index(-2)
    return line


def light_up(node, color=NODE_LIT):
    """Recolour a node — used when a record reaches it."""
    return AnimationGroup(
        node.core.animate.set_color(color),
        node.halo.animate.set_color(color),
        lag_ratio=0,
    )


def spark(color=NODE_LIT, radius=0.10):
    """A single travelling log record."""
    dot = Dot(radius=radius, color=color)
    halo = VGroup(
        *[
            Dot(radius=radius * (1 + 0.6 * i), color=color, fill_opacity=0.18 / i)
            for i in range(1, 4)
        ]
    )
    halo.set_z_index(-1)
    return VGroup(dot, halo)
