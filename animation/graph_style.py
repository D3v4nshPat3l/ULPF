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
    """A single travelling log record, already in ULPF's one common shape."""
    dot = Dot(radius=radius, color=color)
    halo = VGroup(
        *[
            Dot(radius=radius * (1 + 0.6 * i), color=color, fill_opacity=0.18 / i)
            for i in range(1, 4)
        ]
    )
    halo.set_z_index(-1)
    return VGroup(dot, halo)


# --------------------------------------------------------- shared layout
# The map every later block opens on. Kept here, not copied into each scene
# file, so a coordinate tweak cannot quietly drift between blocks the way the
# highlight fragments in scene 1 could have if two scenes each hand-typed
# their own copy of the same string.
PIPELINE_SOURCES = [
    ("Firewall", -6.0, 2.3),
    ("Web proxy", -6.0, 0.9),
    ("IDS sensor", -6.0, -0.5),
    ("VPN gateway", -6.0, -1.9),
]

PIPELINE_STAGES = [
    ("Preserve", "keep the original", -3.5, 0.85),
    ("Identify", "which device is this?", -1.75, -0.75),
    ("Extract", "pull out the facts", 0.0, 0.85),
    ("Translate", "into one common shape", 1.75, -0.75),
    ("Seal", "tamper-evident proof", 3.5, 0.85),
]

PIPELINE_OUTPUTS = [
    ("Search", "one question, every device", 5.35, 0.75),
    ("Evidence", "provable in court", 5.35, -0.95),
]

# Four colours for four vendor formats, deliberately distinct from the status
# palette above (NODE_GOOD/WARN/BAD/LIT). A format token happening to land on
# the exact hue reserved for "tampered" or "verified" would teach the eye the
# wrong lesson the moment a later block actually uses that colour to mean it.
FORMAT_COLORS = ["#f472b6", "#fb923c", "#38bdf8", "#2dd4bf"]


def build_pipeline():
    """The standing map: sources, the five stages, outputs, and their links.

    Returns `(sources, stages, outputs, funnel, chain, tails)` — five VGroups
    of nodes plus two of edges, already positioned and connected. A later
    block fades this whole thing in as an already-assembled backdrop rather
    than re-running scene02's build-up, the way a film cuts back to a
    location instead of replaying the establishing shot.
    """
    sources = VGroup()
    for name, x, y in PIPELINE_SOURCES:
        node = glow_node(color=NODE_DIM, radius=0.22, label=name)
        node.shift([x, y, 0] - node.core.get_center())
        node.caption.scale(0.85)
        sources.add(node)

    stages = VGroup()
    for name, sub, x, y in PIPELINE_STAGES:
        node = glow_node(color=NODE_DIM, label=name, sub=sub)
        node.shift([x, y, 0] - node.core.get_center())
        stages.add(node)

    outputs = VGroup()
    for name, sub, x, y in PIPELINE_OUTPUTS:
        node = glow_node(color=NODE_DIM, radius=0.30, label=name, sub=sub)
        node.shift([x, y, 0] - node.core.get_center())
        outputs.add(node)

    funnel = VGroup(*[link(s, stages[0]) for s in sources])
    chain = VGroup(*[link(stages[i - 1], stages[i]) for i in range(1, len(stages))])
    tails = VGroup(*[link(stages[-1], o) for o in outputs])

    return sources, stages, outputs, funnel, chain, tails


def shaped_token(shape: VMobject, color) -> VGroup:
    """A record before it has been through Translate: `shape`, not a circle.

    `shape` is consumed in place (filled, stroked, wrapped in a soft halo of
    the same outline) rather than copied, so the caller's reference to it
    keeps working after this call.
    """
    shape.set_fill(color, opacity=1).set_stroke(width=0)
    glow = shape.copy().scale(1.8).set_fill(color, opacity=0.18).set_stroke(width=0)
    glow.set_z_index(-1)
    return VGroup(shape, glow)


def morph_to_uniform(tok, color=NODE_LIT, radius=0.10):
    """The instant a record loses its original shape: `tok` becomes a circle.

    `Transform` reshapes `tok`'s own two mobjects to match a circle built at
    their *current* location — built there deliberately, since a bare
    `Circle()` defaults to screen centre, and combining that with a
    simultaneous `.animate.move_to(...)` in the same `self.play` would leave
    two animations disagreeing about where the same points end up. Calling
    this only after a token has finished moving avoids that fight; the object
    identity is unchanged, so the caller keeps moving the same `tok`
    afterward with no bookkeeping to swap it for a fresh mobject.
    """
    center = tok[0].get_center()
    new_core = Circle(radius=radius, color=color, fill_opacity=1, stroke_width=0)
    new_core.move_to(center)
    new_glow = Circle(radius=radius * 1.8, color=color, fill_opacity=0.18, stroke_width=0)
    new_glow.move_to(center)
    new_glow.set_z_index(-1)
    return AnimationGroup(Transform(tok[0], new_core), Transform(tok[1], new_glow))
