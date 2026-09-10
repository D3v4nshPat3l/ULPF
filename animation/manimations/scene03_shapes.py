"""Block 2 — every format becomes one shape.

Four records leave four different devices as four different shapes. They
travel unchanged through Preserve, Identify and Extract — nothing about a
record's original form is touched until a pack actually maps it. Only at
Translate does each one become an identical circle, which is the one moment
this block exists to show: normalization is a single, precise event, not a
gradual blur.

Continues directly from Block 1 (`scene02_flow.py`): same map, same
coordinates, drawn from `graph_style.build_pipeline()` so the two can never
quietly drift apart.
"""

from manim import *

from graph_style import (
    BG,
    FORMAT_COLORS,
    NODE_LIT,
    TEXT,
    build_pipeline,
    light_up,
    morph_to_uniform,
    shaped_token,
)


class Shapes(Scene):
    def construct(self):
        self.camera.background_color = BG

        # ------------------------------------------------------- the standing map
        # No build-up animation here — Block 1 already earned that. This block
        # opens on the map already assembled, the way a film cuts back to a
        # location instead of replaying the establishing shot.
        sources, stages, outputs, funnel, chain, tails = build_pipeline()
        graph = VGroup(funnel, chain, tails, sources, stages, outputs)

        title = Text(
            "Every format becomes one shape", font="Helvetica", weight=BOLD, color=TEXT
        ).scale(0.48)
        title.to_corner(UL, buff=0.45)

        self.play(FadeIn(graph), FadeIn(title), run_time=0.9)
        self.wait(0.3)

        # ------------------------------------------------------------- the tokens
        # One shape per source, deliberately not a circle: a record has not
        # been through Translate yet, so it should not look like one.
        specs = [
            (Square(side_length=0.18), FORMAT_COLORS[0]),
            (Triangle().scale(0.16), FORMAT_COLORS[1]),
            (RegularPolygon(6).scale(0.13), FORMAT_COLORS[2]),
            (RegularPolygon(4, start_angle=45 * DEGREES).scale(0.15), FORMAT_COLORS[3]),
        ]
        tokens = VGroup()
        for (shape, color), src in zip(specs, sources):
            tok = shaped_token(shape, color)
            tok.move_to(src.core.get_center())
            tokens.add(tok)

        self.play(
            LaggedStart(*[FadeIn(t, scale=0.4) for t in tokens], lag_ratio=0.15),
            run_time=0.8,
        )

        def travel_to(stage, run_time=1.0):
            self.play(
                LaggedStart(
                    *[t.animate.move_to(stage.core.get_center()) for t in tokens],
                    lag_ratio=0.08,
                ),
                run_time=run_time,
            )

        # ---------------------------------------- Preserve, Identify, Extract
        # Three hops, original shape untouched at every one of them — the
        # point being that nothing here has looked at what the record means
        # yet, only that it exists and where it came from.
        travel_to(stages[0])
        self.play(light_up(stages[0]), run_time=0.3)

        travel_to(stages[1])
        self.play(light_up(stages[1]), run_time=0.3)

        travel_to(stages[2])
        self.play(light_up(stages[2]), run_time=0.3)

        # ------------------------------------------------------------ Translate
        # Move first, morph second — deliberately two separate `self.play`
        # calls. `morph_to_uniform` and `.animate.move_to` both work by
        # setting a mobject's absolute target points; combined in one call
        # they would disagree about where those points end up. Sequencing
        # them removes the conflict rather than working around it.
        travel_to(stages[3], run_time=1.1)
        self.play(*[morph_to_uniform(t) for t in tokens], run_time=0.7)
        self.play(light_up(stages[3]), run_time=0.3)

        same_shape = Text(
            "Same shape from here on.", font="Helvetica", weight=BOLD, color=NODE_LIT
        ).scale(0.36)
        same_shape.next_to(stages[3], DOWN, buff=1.0)
        self.play(FadeIn(same_shape, shift=UP * 0.15), run_time=0.5)
        self.wait(0.6)
        self.play(FadeOut(same_shape), run_time=0.4)

        # --------------------------------------------------------------- Seal
        travel_to(stages[4])
        self.play(light_up(stages[4]), run_time=0.3)

        # ----------------------------------------------------------- Outputs
        # Split evenly rather than sent to both — every record goes somewhere
        # specific, not everywhere at once.
        self.play(
            LaggedStart(
                tokens[0].animate.move_to(outputs[0].core.get_center()),
                tokens[1].animate.move_to(outputs[0].core.get_center()),
                tokens[2].animate.move_to(outputs[1].core.get_center()),
                tokens[3].animate.move_to(outputs[1].core.get_center()),
                lag_ratio=0.1,
            ),
            run_time=1.1,
        )
        self.play(light_up(outputs[0]), light_up(outputs[1]), run_time=0.3)
        self.play(FadeOut(tokens), run_time=0.4)

        # ------------------------------------------------------------ the one line
        summary = Text(
            "Four formats. One shape after Translate. Nothing changed before that.",
            font="Helvetica",
            weight=BOLD,
            color=NODE_LIT,
        ).scale(0.38)
        summary.to_edge(DOWN, buff=0.45)
        self.play(FadeIn(summary, shift=UP * 0.2), run_time=0.7)
        self.wait(2.2)
