#!/usr/bin/env -S uv run
# Copyright (C) 2026 Deltik <https://www.deltik.net/>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This file is part of LibreProtect.
#
# LibreProtect is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# LibreProtect is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with LibreProtect.  If not, see <https://www.gnu.org/licenses/>.

# /// script
# requires-python = ">=3.14"
# dependencies = [
#     "resvg-py==0.5.0",
#     "uharfbuzz==0.56.2",
# ]
# ///

"""Draw LibreProtect's images, render them, and convert its store description.

commands:
  render  Render the SVGs here as PNGs, and description.md as BBCode, into
          build/ (the default)
  draw    Redraw the SVGs here from the design in this script
  bbcode  Print description.md as BBCode

draw downloads the fonts that the lettering is set in, once, and copies the
outlines of the letters into the SVGs, which then look the same everywhere.
"""

import argparse
import hashlib
import html
import http.client
import math
import random
import re
import sys
import unicodedata
import urllib.request
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from enum import Enum, auto
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Final, Self, override

import resvg_py
import uharfbuzz

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

HERE: Final = Path(__file__).resolve().parent
BUILD: Final = HERE / "build"
# White on this blue has a contrast ratio of 4.5:1, which WCAG AA asks of text
BLUE: Final = "#007dba"
WHITE: Final = "#fff"
TAGLINE: Final = "free, private block logging, rollbacks and restores"


class BrandingError(Exception):
    """A problem that stops this script, reported without a traceback."""


# --- Geometry ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Point:
    """A point in an image, in pixels from its top left corner."""

    x: float
    y: float

    def toward(self, degrees: float, distance: float) -> Self:
        """Return the point at a distance, counterclockwise from 3 o'clock."""
        angle = math.radians(degrees)
        return replace(
            self,
            x=self.x + distance * math.cos(angle),
            y=self.y - distance * math.sin(angle),
        )

    def below(self, distance: float) -> Self:
        """Return the point a distance below this one."""
        return replace(self, y=self.y + distance)


@dataclass(frozen=True, slots=True)
class Box:
    """A rectangle with sides parallel to the image's."""

    left: float
    top: float
    right: float
    bottom: float

    @classmethod
    def around(cls, center: Point, reach: float) -> Self:
        """Return the square whose sides are a distance from its center."""
        return cls(
            center.x - reach, center.y - reach, center.x + reach, center.y + reach
        )

    def grown(self, margin: float) -> Self:
        """Return this box with a margin around it."""
        return replace(
            self,
            left=self.left - margin,
            top=self.top - margin,
            right=self.right + margin,
            bottom=self.bottom + margin,
        )

    def joined(self, other: Box) -> Self:
        """Return the smallest box that holds this box and another."""
        return replace(
            self,
            left=min(self.left, other.left),
            top=min(self.top, other.top),
            right=max(self.right, other.right),
            bottom=max(self.bottom, other.bottom),
        )

    def overlaps(self, other: Box) -> bool:
        """Return whether this box and another share any area."""
        return (
            self.left < other.right
            and self.right > other.left
            and self.top < other.bottom
            and self.bottom > other.top
        )


# --- SVG -----------------------------------------------------------------------


class SvgElement:
    """An element of an SVG document, to which elements can be added."""

    def __init__(self, element: ET.Element) -> None:
        """Wrap an element."""
        self.element = element

    def add(
        self, tag: str, /, text: str | None = None, **attributes: str | float | None
    ) -> SvgElement:
        """Add an element with text and attributes, and return it.

        Attributes that are None are left out. In attribute names, an
        underscore stands for a hyphen, and a trailing underscore avoids a
        Python keyword: stroke_width is stroke-width, and in_ is in.
        """
        child = ET.SubElement(
            self.element,
            tag,
            {
                name.removesuffix("_").replace("_", "-"): Svg.attribute(value)
                for name, value in attributes.items()
                if value is not None
            },
        )
        child.text = text
        return SvgElement(child)


class Svg:
    """An SVG document, built as XML."""

    NAMESPACE: ClassVar[str] = "http://www.w3.org/2000/svg"

    def __init__(self, width: int, height: int, title: str) -> None:
        """Start a document of a size in pixels, with a title."""
        self.root = SvgElement(
            ET.Element(
                "svg",
                xmlns=self.NAMESPACE,
                width=str(width),
                height=str(height),
                viewBox=f"0 0 {width} {height}",
            )
        )
        self.root.add("title", text=title)
        self.defs = self.root.add("defs")

    @staticmethod
    def number(value: float, places: int = 3) -> str:
        """Format a number as briefly as its precision allows."""
        text = f"{value:.{places}f}"
        if places:
            text = text.rstrip("0").rstrip(".")
        return "0" if text == "-0" else text

    @classmethod
    def attribute(cls, value: str | float) -> str:
        """Format an attribute's value."""
        return value if isinstance(value, str) else cls.number(value)

    def text(self) -> str:
        """Return the document as text."""
        ET.indent(self.root.element)
        return ET.tostring(self.root.element, encoding="unicode") + "\n"


class PathData:
    """SVG path data, built one command at a time."""

    def __init__(self) -> None:
        """Start with no commands."""
        self._commands: list[str] = []

    def move(self, point: Point) -> Self:
        """Start a new subpath at a point."""
        return self._add("M", point)

    def line(self, point: Point) -> Self:
        """Draw a straight line to a point."""
        return self._add("L", point)

    def arc(self, radius: float, end: Point, *, large: bool, sweep: bool) -> Self:
        """Draw a circular arc to a point."""
        size = Svg.number(radius, 2)
        return self._add(f"A {size} {size} 0 {int(large)} {int(sweep)}", end)

    def cubic(self, first: Point, second: Point, end: Point) -> Self:
        """Draw a cubic Bézier curve to a point."""
        return self._add("C", first, second, end)

    def quadratic(self, control: Point, end: Point) -> Self:
        """Draw a quadratic Bézier curve to a point."""
        return self._add("Q", control, end)

    def close(self) -> Self:
        """Close the subpath."""
        self._commands.append("Z")
        return self

    def polygon(self, first: Point, *others: Point) -> Self:
        """Draw a closed polygon through points."""
        self.move(first)
        for point in others:
            self.line(point)
        return self.close()

    @override
    def __str__(self) -> str:
        return " ".join(self._commands)

    def _add(self, command: str, *points: Point) -> Self:
        coordinates = (f"{Svg.number(p.x, 2)},{Svg.number(p.y, 2)}" for p in points)
        self._commands.append(" ".join((command, *coordinates)))
        return self


# --- Lettering -----------------------------------------------------------------


class FontError(BrandingError):
    """A font that can't be downloaded, or isn't the font that was pinned."""


@dataclass(frozen=True, slots=True)
class Typeface:
    """A font that lettering is set in, downloaded once and checked by its hash."""

    url: str
    sha256: str

    CACHE: ClassVar[Path] = BUILD / "fonts"

    def font(self) -> uharfbuzz.Font:
        """Load the font, downloading it if it isn't downloaded yet."""
        path = self.CACHE / self.url.rsplit("/", 1)[-1]
        data = path.read_bytes() if path.is_file() else b""
        if hashlib.sha256(data).hexdigest() != self.sha256:
            data = self._download()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return uharfbuzz.Font(uharfbuzz.Face(uharfbuzz.Blob(data)))

    def _download(self) -> bytes:
        try:
            # The URL is one of the https URLs below
            with urllib.request.urlopen(self.url, timeout=60) as response:  # noqa: S310
                data: bytes = response.read()
        except (OSError, http.client.HTTPException) as error:
            message = f"can't download {self.url}: {error}"
            raise FontError(message) from error
        if hashlib.sha256(data).hexdigest() != self.sha256:
            message = f"{self.url} doesn't have the SHA-256 hash {self.sha256}"
            raise FontError(message)
        return data


# URW Gothic Book, from URW++ under the AGPL with an exception for fonts in
# documents
URW_GOTHIC: Final = Typeface(
    "https://raw.githubusercontent.com/ArtifexSoftware/urw-base35-fonts/20200910/fonts/URWGothic-Book.otf",
    "04318316cee29950805110c9c8949eea189ef5575132881f4d4d7e03e5299903",
)
# Ubuntu Regular, from Canonical under the Ubuntu Font Licence
UBUNTU: Final = Typeface(
    "https://raw.githubusercontent.com/google/fonts/a50de97857f6626d6628c91e6a34c12ee8a16ede/ufl/ubuntu/Ubuntu-Regular.ttf",
    "3128df86a31805618436d0ae5651ba4285d0c9de0a39057d025f64ee33bceb64",
)


class GlyphOutliner:
    """Traces a glyph's outline, as HarfBuzz draws it, into path data."""

    def __init__(self, path: PathData, origin: Point, scale: float) -> None:
        """Trace into path data, with the glyph's origin at a point and scaled."""
        self._path = path
        self._origin = origin
        self._scale = scale

    @classmethod
    def draw_funcs(cls) -> uharfbuzz.DrawFuncs[GlyphOutliner]:
        """Return HarfBuzz's callbacks for tracing, which get an outliner."""
        funcs: uharfbuzz.DrawFuncs[GlyphOutliner] = uharfbuzz.DrawFuncs()
        funcs.set_move_to_func(cls._move)
        funcs.set_line_to_func(cls._line)
        funcs.set_cubic_to_func(cls._cubic)
        funcs.set_quadratic_to_func(cls._quadratic)
        funcs.set_close_path_func(cls._close)
        return funcs

    def _point(self, x: float, y: float) -> Point:
        # Fonts measure up from the baseline, and images down from the top
        return Point(self._origin.x + x * self._scale, self._origin.y - y * self._scale)

    @staticmethod
    def _move(x: float, y: float, outliner: GlyphOutliner) -> None:
        outliner._path.move(outliner._point(x, y))

    @staticmethod
    def _line(x: float, y: float, outliner: GlyphOutliner) -> None:
        outliner._path.line(outliner._point(x, y))

    # HarfBuzz passes the coordinates of three points, then the outliner
    @staticmethod
    def _cubic(  # noqa: PLR0913, PLR0917
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        x: float,
        y: float,
        outliner: GlyphOutliner,
    ) -> None:
        outliner._path.cubic(
            outliner._point(x1, y1), outliner._point(x2, y2), outliner._point(x, y)
        )

    @staticmethod
    def _quadratic(
        x1: float, y1: float, x: float, y: float, outliner: GlyphOutliner
    ) -> None:
        outliner._path.quadratic(outliner._point(x1, y1), outliner._point(x, y))

    @staticmethod
    def _close(outliner: GlyphOutliner) -> None:
        outliner._path.close()


@dataclass(frozen=True, slots=True)
class Line:
    """A line of text, as the outlines of its letters."""

    outline: str
    # Where the letters' ink is
    ink: Box


@dataclass(frozen=True, slots=True)
class Placement:
    """Where a centered line of text goes: its center, baseline and size."""

    center: float
    baseline: float
    size: float


class Typesetter:
    """Sets lines of text in a font, shaped as HarfBuzz shapes them."""

    def __init__(self, typeface: Typeface) -> None:
        """Set text in a typeface."""
        self._font = typeface.font()
        self._draw_funcs = GlyphOutliner.draw_funcs()

    def set(self, text: str, placement: Placement, spacing: float = 0) -> Line:
        """Set a line of text, with extra space between letters."""
        buffer = uharfbuzz.Buffer()
        buffer.add_str(text)
        buffer.guess_segment_properties()
        uharfbuzz.shape(self._font, buffer)
        glyphs = list(zip(buffer.glyph_infos, buffer.glyph_positions, strict=True))
        scale = placement.size / self._font.face.upem
        width = sum(position.x_advance for _, position in glyphs) * scale
        width += spacing * (len(glyphs) - 1)

        path = PathData()
        ink: Box | None = None
        x = placement.center - width / 2
        for info, position in glyphs:
            origin = Point(
                x + position.x_offset * scale,
                placement.baseline - position.y_offset * scale,
            )
            outliner = GlyphOutliner(path, origin, scale)
            self._font.draw_glyph(info.codepoint, self._draw_funcs, outliner)
            extents = self._font.get_glyph_extents(info.codepoint)
            # A space has no ink
            if extents is not None and extents.width:
                glyph_ink = Box(
                    origin.x + extents.x_bearing * scale,
                    origin.y - extents.y_bearing * scale,
                    origin.x + (extents.x_bearing + extents.width) * scale,
                    origin.y - (extents.y_bearing + extents.height) * scale,
                )
                ink = glyph_ink if ink is None else ink.joined(glyph_ink)
            x += position.x_advance * scale + spacing
        if ink is None:
            message = f"{text!r} has no letters to see"
            raise BrandingError(message)
        return Line(str(path), ink)


class Fonts:
    """The typesetters for the lettering, which load their fonts when first used."""

    @cached_property
    def wordmark(self) -> Typesetter:
        """Return the typesetter for the wordmark."""
        return Typesetter(URW_GOTHIC)

    @cached_property
    def tagline(self) -> Typesetter:
        """Return the typesetter for the tagline."""
        return Typesetter(UBUNTU)


# --- Artwork -------------------------------------------------------------------


class Mark:
    """The icon's mark: a block inside an arrow that turns back, as in a rollback.

    It's drawn in a frame of SIZE by SIZE pixels. Angles are in degrees,
    counterclockwise from 3 o'clock.
    """

    SIZE: ClassVar[int] = 512
    # How far the arrowhead reaches from the frame's center
    REACH: ClassVar[int] = 225
    # The arrow's arc: its radius and width, and the angles where it starts
    # and where it ends, 18 degrees after going around once
    RADIUS: ClassVar[int] = 180
    WIDTH: ClassVar[int] = 42
    TAIL: ClassVar[int] = 62
    HEAD: ClassVar[int] = 378
    # How far before the head the arc stops, under the arrowhead
    ARC_SHORTFALL: ClassVar[int] = 14
    # How far before the head the arrowhead's base is, how far along the arc
    # its tip is from there in pixels, and the stroke that rounds its corners
    ARROWHEAD_BASE: ClassVar[int] = 16
    ARROWHEAD_LENGTH: ClassVar[int] = 48
    ARROWHEAD_ROUNDING: ClassVar[int] = 6
    # The block: the length of its edges, how far below the frame's center its
    # center is, and the width of the seams between its faces
    BLOCK_SIDE: ClassVar[int] = 112
    BLOCK_DROP: ClassVar[int] = 4
    SEAM_WIDTH: ClassVar[int] = 8

    def __init__(self, seam_color: str) -> None:
        """Draw the block's seams in a color, which is normally the background's."""
        self._seam_color = seam_color

    def draw(self, parent: SvgElement, transform: str | None = None) -> None:
        """Draw the mark, in a group with a transform if one is given."""
        group = parent.add("g", transform=transform)
        center = Point(self.SIZE / 2, self.SIZE / 2)
        self._draw_arrow(group, center)
        self._draw_block(group, center.below(self.BLOCK_DROP))

    def _draw_arrow(self, parent: SvgElement, center: Point) -> None:
        start = center.toward(self.TAIL, self.RADIUS)
        end = center.toward(self.HEAD - self.ARC_SHORTFALL, self.RADIUS)
        arc = PathData().move(start).arc(self.RADIUS, end, large=True, sweep=False)
        parent.add(
            "path", d=str(arc), fill="none", stroke=WHITE, stroke_width=self.WIDTH
        )
        base = self.HEAD - self.ARROWHEAD_BASE
        tip = base + math.degrees(self.ARROWHEAD_LENGTH / self.RADIUS)
        arrowhead = PathData().polygon(
            center.toward(base, self.RADIUS - self.WIDTH),
            center.toward(tip, self.RADIUS),
            center.toward(base, self.RADIUS + self.WIDTH),
        )
        parent.add(
            "path",
            d=str(arrowhead),
            fill=WHITE,
            stroke=WHITE,
            stroke_width=self.ARROWHEAD_ROUNDING,
            stroke_linejoin="round",
        )

    def _draw_block(self, parent: SvgElement, center: Point) -> None:
        side = self.BLOCK_SIDE
        across = side * math.cos(math.radians(30))
        top = Point(center.x, center.y - side)
        bottom = Point(center.x, center.y + side)
        top_left = Point(center.x - across, center.y - side / 2)
        top_right = Point(center.x + across, center.y - side / 2)
        bottom_left = Point(center.x - across, center.y + side / 2)
        bottom_right = Point(center.x + across, center.y + side / 2)
        for face in (
            (top, top_right, center, top_left),
            (top_left, center, bottom, bottom_left),
            (center, top_right, bottom_right, bottom),
        ):
            parent.add("path", d=str(PathData().polygon(*face)), fill=WHITE)
        seams = PathData().move(top_left).line(center).line(top_right)
        seams.move(center).line(bottom)
        parent.add(
            "path",
            d=str(seams),
            stroke=self._seam_color,
            stroke_width=self.SEAM_WIDTH,
            stroke_linejoin="round",
            fill="none",
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class Scatter:
    """Faint squares, some of them blurred, anywhere but in keep-out boxes."""

    seed: int
    count: int
    area: Box
    sides: Sequence[int]
    opacity: tuple[float, float]
    # Whether squares may reach past the area by half their side
    overhang: bool = False
    # The share of the squares of BLURRED_SIDE pixels or more that are blurred
    blurred_share: float = 0
    keepouts: Sequence[Box] = ()

    BLURRED_SIDE: ClassVar[int] = 32
    # The standard deviation of the blur, which spreads about three of them
    BLUR: ClassVar[int] = 4
    # How many places each square may try on average, outside the keep-outs
    TRIES: ClassVar[int] = 1000

    def define_blur(self, defs: SvgElement) -> None:
        """Define the blur that the blurred squares use."""
        blur = defs.add(
            "filter", id="soft", x="-50%", y="-50%", width="200%", height="200%"
        )
        blur.add("feGaussianBlur", stdDeviation=self.BLUR)

    def draw(self, parent: SvgElement) -> None:
        """Draw the squares."""
        # The squares only have to look random, and to be the same every time
        rng = random.Random(self.seed)  # noqa: S311
        drawn = tries = 0
        while drawn < self.count:
            tries += 1
            if tries > self.TRIES * self.count:
                message = "the squares don't fit around the keep-out boxes"
                raise BrandingError(message)
            side = rng.choice(self.sides)
            reach = side / 2 if self.overhang else 0
            x = rng.uniform(self.area.left - reach, self.area.right - side + reach)
            y = rng.uniform(self.area.top - reach, self.area.bottom - side + reach)
            blurred = side >= self.BLURRED_SIDE and rng.random() < self.blurred_share
            opacity = rng.uniform(*self.opacity)
            square = Box(x, y, x + side, y + side)
            margin = 3 * self.BLUR if blurred else 0
            if any(square.overlaps(box.grown(margin)) for box in self.keepouts):
                continue
            parent.add(
                "rect",
                x=x,
                y=y,
                width=side,
                height=side,
                fill=WHITE,
                fill_opacity=opacity,
                filter="url(#soft)" if blurred else None,
            )
            drawn += 1


class Artwork(ABC):
    """An image, drawn as an SVG and rendered as a PNG."""

    NAME: ClassVar[str]
    # The PNG's size, at least twice the size that it's shown at
    PNG_SIZE: ClassVar[tuple[int, int]]

    @property
    def svg_path(self) -> Path:
        """Return where the SVG is."""
        return HERE / f"{self.NAME}.svg"

    @property
    def png_path(self) -> Path:
        """Return where the PNG goes."""
        return BUILD / f"{self.NAME}.png"

    @abstractmethod
    def draw(self) -> Svg:
        """Draw the image."""

    def render(self) -> None:
        """Render the SVG as a PNG."""
        if not self.svg_path.is_file():
            message = f"{self.svg_path} is missing; draw it first"
            raise BrandingError(message)
        width, height = self.PNG_SIZE
        try:
            png = resvg_py.svg_to_bytes(
                svg_path=str(self.svg_path),
                width=width,
                height=height,
                # The images' text is drawn as outlines
                skip_system_fonts=True,
            )
        except ValueError as error:
            message = f"can't render {self.svg_path}: {error}"
            raise BrandingError(message) from error
        self.png_path.parent.mkdir(parents=True, exist_ok=True)
        self.png_path.write_bytes(png)


class Icon(Artwork):
    """The icon: the mark on a disc, for stores and avatars."""

    NAME = "icon"
    PNG_SIZE = (Mark.SIZE, Mark.SIZE)
    # Where the squares go, inside the disc
    INSET: ClassVar[int] = 40

    @override
    def draw(self) -> Svg:
        size = Mark.SIZE
        middle = size / 2
        svg = Svg(size, size, "LibreProtect")
        svg.defs.add("clipPath", id="disc").add(
            "circle", cx=middle, cy=middle, r=middle
        )
        svg.root.add("circle", cx=middle, cy=middle, r=middle, fill=BLUE)
        Scatter(
            seed=19,
            count=11,
            area=Box(0, 0, size, size).grown(-self.INSET),
            sides=(10, 14, 18, 24, 30),
            opacity=(0.07, 0.15),
        ).draw(svg.root.add("g", clip_path="url(#disc)"))
        Mark(seam_color=BLUE).draw(svg.root)
        return svg


@dataclass(frozen=True, slots=True)
class MarkPlacement:
    """Where the mark goes: its center, and how far it reaches from there."""

    center: Point
    reach: float


class Poster(Artwork):
    """The wordmark and the tagline on a field of squares, maybe below the mark."""

    SIZE: ClassVar[tuple[int, int]]
    WORDMARK: ClassVar[Placement]
    TAGLINE: ClassVar[Placement]
    MARK: ClassVar[MarkPlacement | None] = None
    # The seed and count of the squares
    SQUARES: ClassVar[tuple[int, int]]
    # The wordmark's size that its stroke, shadow and spacing are measured at
    WORDMARK_SCALE: ClassVar[int] = 186
    WORDMARK_STROKE: ClassVar[int] = 8
    WORDMARK_SHADOW: ClassVar[int] = 4
    WORDMARK_SPACING: ClassVar[int] = -1
    # The space that squares keep from the tagline and the mark
    CLEARANCE: ClassVar[int] = 20

    def __init__(self, fonts: Fonts) -> None:
        """Set the lettering in fonts."""
        self._fonts = fonts

    @override
    def draw(self) -> Svg:
        width, height = self.SIZE
        scale = self.WORDMARK.size / self.WORDMARK_SCALE
        wordmark = self._fonts.wordmark.set(
            "libreprotect", self.WORDMARK, self.WORDMARK_SPACING * scale
        )
        tagline = self._fonts.tagline.set(TAGLINE, self.TAGLINE)
        keepouts = [tagline.ink.grown(self.CLEARANCE)]
        if self.MARK:
            reach = self.MARK.reach + self.CLEARANCE
            keepouts.append(Box.around(self.MARK.center, reach))
        seed, count = self.SQUARES
        squares = Scatter(
            seed=seed,
            count=count,
            area=Box(0, 0, width, height),
            sides=(8, 10, 14, 18, 24, 32, 42, 56),
            opacity=(0.04, 0.13),
            overhang=True,
            blurred_share=0.6,
            keepouts=keepouts,
        )

        svg = Svg(width, height, f"LibreProtect: {TAGLINE}")
        self._define_lettering(svg.defs, scale)
        squares.define_blur(svg.defs)
        svg.root.add("rect", width=width, height=height, fill=BLUE)
        squares.draw(svg.root.add("g"))
        if self.MARK:
            self._draw_mark(svg.root, self.MARK)
        svg.root.add(
            "path",
            d=wordmark.outline,
            fill="url(#letters)",
            stroke="url(#letters)",
            stroke_width=self.WORDMARK_STROKE * scale,
            stroke_linejoin="round",
            filter="url(#shadow)",
        )
        svg.root.add("path", d=tagline.outline, fill=WHITE)
        return svg

    def _define_lettering(self, defs: SvgElement, scale: float) -> None:
        gradient = defs.add("linearGradient", id="letters", x1=0, y1=0, x2=0, y2=1)
        gradient.add("stop", offset=0.45, stop_color="#ffffff")
        gradient.add("stop", offset=1, stop_color="#e8eef3")
        shadow = defs.add(
            "filter", id="shadow", x="-5%", y="-20%", width="110%", height="150%"
        )
        spread = self.WORDMARK_SHADOW * scale
        shadow.add("feGaussianBlur", in_="SourceAlpha", stdDeviation=spread)
        shadow.add("feOffset", dy=spread, result="offset")
        shadow.add("feFlood", flood_color="#002a40", flood_opacity=0.3)
        shadow.add("feComposite", in2="offset", operator="in")
        merge = shadow.add("feMerge")
        merge.add("feMergeNode")
        merge.add("feMergeNode", in_="SourceGraphic")

    @staticmethod
    def _draw_mark(parent: SvgElement, placement: MarkPlacement) -> None:
        scale = placement.reach / Mark.REACH
        corner = Mark.SIZE / 2 * scale
        left = Svg.number(placement.center.x - corner, 2)
        top = Svg.number(placement.center.y - corner, 2)
        transform = f"translate({left} {top}) scale({Svg.number(scale, 4)})"
        Mark(seam_color=BLUE).draw(parent, transform)


class Banner(Poster):
    """The banner at the top of the README and the store descriptions."""

    NAME = "banner"
    SIZE = (1600, 400)
    PNG_SIZE = (2400, 600)
    WORDMARK = Placement(800, 222, 186)
    TAGLINE = Placement(800, 318, 50)
    SQUARES = (2026, 64)


class SocialPreview(Poster):
    """The image that shows with links to the repository, on GitHub and elsewhere."""

    NAME = "social-preview"
    SIZE = (1280, 640)
    # Twice the size that GitHub recommends
    PNG_SIZE = (2560, 1280)
    WORDMARK = Placement(640, 438, 150)
    TAGLINE = Placement(640, 530, 40)
    MARK = MarkPlacement(Point(640, 180), 92)
    SQUARES = (640, 82)
    # The most that GitHub takes
    PNG_LIMIT: ClassVar[int] = 1_000_000

    @override
    def render(self) -> None:
        super().render()
        size = self.png_path.stat().st_size
        if size > self.PNG_LIMIT:
            message = f"{self.png_path} has {size} bytes, more than GitHub takes"
            raise BrandingError(message)


# --- Store description -----------------------------------------------------------


class UnsupportedMarkdownError(BrandingError):
    """Markdown that the store description can't use, since BBCode can't say it."""

    def __init__(self, line: int, text: str, reason: str, hint: str = "") -> None:
        """Report a line of the description, why and at what text, and what to do."""
        message = f"description.md, line {line}: {reason} {text.strip()[:40]!r}"
        super().__init__(f"{message}. {hint}" if hint else message)


class InlineMarkdown:
    """Converts the Markdown inside a block, such as links and emphasis, to BBCode.

    It reads the text once, from left to right, as CommonMark does, and refuses
    Markdown that it can't convert faithfully rather than guess at it.
    """

    # Text without any character that may start Markdown
    PLAIN: ClassVar[re.Pattern[str]] = re.compile(r"[^\\`!\[\]<*_~&]+")
    # A backslash before ASCII punctuation makes it literal
    ESCAPED: ClassVar[re.Pattern[str]] = re.compile(r"\\([!-/:-@\[-`{-~])")
    AUTOLINK: ClassVar[re.Pattern[str]] = re.compile(r"<(https?://[^<>\s'\[\]]+)>")
    DESTINATION: ClassVar[re.Pattern[str]] = re.compile(r"\(([^()\s]+)\)")
    # Links go to absolute URLs, since the description is shown away from the
    # repository, and BBCode can't quote some characters
    ABSOLUTE_URL: ClassVar[re.Pattern[str]] = re.compile(r"https?://[^\s'\[\]]+")
    ENTITY: ClassVar[re.Pattern[str]] = re.compile(
        r"&(?:[A-Za-z][A-Za-z0-9]*|#[0-9]+|#[Xx][0-9A-Fa-f]+);"
    )
    BRACKETS: ClassVar[str] = (
        "Use brackets only for links, since BBCode would read others as tags"
    )
    URL: ClassVar[str] = (
        "Link to an absolute http or https URL, without a title, spaces, "
        "parentheses, brackets or apostrophes"
    )

    def __init__(self, text: str, line: int) -> None:
        """Read text from a line of the description."""
        self._text = text
        self._line = line
        self._position = 0
        self._in_link = False
        self._handlers: dict[str, Callable[[], str]] = {
            "\\": self._escape,
            "`": self._code,
            "!": self._exclamation,
            "[": self._link,
            "]": self._stray_bracket,
            "<": self._autolink,
            "*": self._emphasis,
            "_": self._emphasis,
            "~": self._tilde,
            "&": self._ampersand,
        }

    def bbcode(self) -> str:
        """Return the text in BBCode."""
        self._position = 0
        self._in_link = False
        return self._until(None, 0)

    def _until(self, closing: str | None, start: int) -> str:
        """Convert text until the closing delimiter, or to the end without one."""
        parts: list[str] = []
        while self._position < len(self._text):
            if closing is not None and self._closes(closing):
                self._position += len(closing)
                return "".join(parts)
            plain = self.PLAIN.match(self._text, self._position)
            if plain:
                self._position = plain.end()
                parts.append(plain[0])
            else:
                parts.append(self._handlers[self._text[self._position]]())
        if closing is not None:
            raise self._refusal(start, f"can't find the {closing!r} that closes")
        return "".join(parts)

    def _refusal(
        self, start: int, reason: str, hint: str = ""
    ) -> UnsupportedMarkdownError:
        return UnsupportedMarkdownError(self._line, self._text[start:], reason, hint)

    def _run(self, position: int) -> int:
        """Return how many times the character at a position repeats from there."""
        character = self._text[position]
        end = position
        while end < len(self._text) and self._text[end] == character:
            end += 1
        return end - position

    @staticmethod
    def _punctuation(character: str) -> bool:
        return unicodedata.category(character)[0] in "PS"

    def _flanking(self, position: int, length: int) -> tuple[bool, bool]:
        """Return whether a run of * or _ can open emphasis, and close it.

        These are CommonMark's rules for left-flanking and right-flanking
        delimiter runs, with the ends of the text counting as spaces.
        """
        before = self._text[position - 1] if position else " "
        after = self._text[position + length : position + length + 1] or " "
        left = not after.isspace() and (
            not self._punctuation(after)
            or before.isspace()
            or self._punctuation(before)
        )
        right = not before.isspace() and (
            not self._punctuation(before) or after.isspace() or self._punctuation(after)
        )
        if self._text[position] == "_":
            # An underscore can't emphasize part of a word
            opens = left and (not right or self._punctuation(before))
            closes = right and (not left or self._punctuation(after))
            return opens, closes
        return left, right

    def _closes(self, closing: str) -> bool:
        if not self._text.startswith(closing, self._position):
            return False
        if closing == "]":
            return True
        length = self._run(self._position)
        return length == len(closing) and self._flanking(self._position, length)[1]

    def _escape(self) -> str:
        escaped = self.ESCAPED.match(self._text, self._position)
        if not escaped:
            self._position += 1
            return "\\"
        if escaped[1] in "[]":
            raise self._refusal(self._position, "can't escape", self.BRACKETS)
        self._position = escaped.end()
        return escaped[1]

    def _code(self) -> str:
        start = self._position
        length = self._run(start)
        fence = "`" * length
        end = re.compile(rf"(?<!`){fence}(?!`)").search(self._text, start + length)
        if not end:
            raise self._refusal(start, "can't find the end of the code")
        code = self._text[start + length : end.start()]
        # One space on each side separates the code from backticks inside it
        if code.startswith(" ") and code.endswith(" ") and code.strip():
            code = code[1:-1]
        if "[/plain]" in code.lower():
            raise self._refusal(start, "can't show [/PLAIN] in the code")
        self._position = end.end()
        # Brackets in code would otherwise read as BBCode
        if "[" in code or "]" in code:
            code = f"[PLAIN]{code}[/PLAIN]"
        return f"[FONT=Courier New]{code}[/FONT]"

    def _exclamation(self) -> str:
        start = self._position
        if not self._text.startswith("![", start):
            self._position += 1
            return "!"
        # BBCode has no place for the alternative text, which is skipped
        close = self._text.find("]", start + 2)
        if close < 0:
            raise self._refusal(start, "can't find the end of the image")
        if "[" in self._text[start + 2 : close]:
            raise self._refusal(start, "can't convert the brackets in", self.BRACKETS)
        self._position = close + 1
        return f"[IMG]{self._destination(start)}[/IMG]"

    def _link(self) -> str:
        start = self._position
        if self._in_link:
            raise self._refusal(start, "can't put a link in a link")
        self._position += 1
        self._in_link = True
        label = self._until("]", start)
        self._in_link = False
        return f"[URL='{self._destination(start)}']{label}[/URL]"

    def _destination(self, start: int) -> str:
        if not self._text.startswith("(", self._position):
            raise self._refusal(start, "can't convert", self.BRACKETS)
        destination = self.DESTINATION.match(self._text, self._position)
        url = self._decoded(destination[1]) if destination else ""
        if not destination or not self.ABSOLUTE_URL.fullmatch(url):
            raise self._refusal(start, "can't convert the link in", self.URL)
        self._position = destination.end()
        return url

    def _decoded(self, destination: str) -> str:
        """Return a destination without its escapes and entities, as CommonMark does.

        Only entities with their semicolons count, unlike in HTML.
        """
        unescaped = self.ESCAPED.sub(r"\1", destination)
        return self.ENTITY.sub(lambda entity: html.unescape(entity[0]), unescaped)

    def _stray_bracket(self) -> str:
        if self._in_link:
            # A link's text ends here, but emphasis that started in it doesn't
            raise self._refusal(self._position, "can't end a link inside emphasis at")
        raise self._refusal(self._position, "can't convert", self.BRACKETS)

    def _autolink(self) -> str:
        link = self.AUTOLINK.match(self._text, self._position)
        if not link:
            raise self._refusal(self._position, "can't convert HTML")
        self._position = link.end()
        return f"[URL]{link[1]}[/URL]"

    def _emphasis(self) -> str:
        start = self._position
        length = self._run(start)
        delimiter = self._text[start : start + length]
        opens, closes = self._flanking(start, length)
        if not opens and not closes:
            # Surrounded by spaces, or inside a word, it's just text
            self._position += length
            return delimiter
        if not opens:
            raise self._refusal(start, "can't match the emphasis that ends at")
        if length > len("**"):
            raise self._refusal(start, "can't tell bold from italic in")
        self._position += length
        tag = "B" if length == len("**") else "I"
        return f"[{tag}]{self._until(delimiter, start)}[/{tag}]"

    def _tilde(self) -> str:
        if self._text.startswith("~~", self._position):
            raise self._refusal(self._position, "can't convert strikethrough")
        self._position += 1
        return "~"

    def _ampersand(self) -> str:
        if self.ENTITY.match(self._text, self._position):
            raise self._refusal(self._position, "can't convert the HTML entity")
        self._position += 1
        return "&"


class BlockKind(Enum):
    """What a block of the description is."""

    HEADING = auto()
    LIST = auto()
    PARAGRAPH = auto()


@dataclass(frozen=True, slots=True)
class Block:
    """A block of the description, in BBCode."""

    kind: BlockKind
    bbcode: str


class MarkdownToBBCode:
    """Converts the store description's Markdown to XenForo's BBCode.

    It converts headings, lists, paragraphs, links, images, emphasis and code,
    and refuses the rest of Markdown.
    """

    # A closing sequence of #s needs a space before it
    HEADING: ClassVar[re.Pattern[str]] = re.compile(
        r"(#{1,3})[ \t]+(.+?)(?:[ \t]+#+)?[ \t]*"
    )
    # A list item: its bullet, or its number and the delimiter after it
    ITEM: ClassVar[re.Pattern[str]] = re.compile(r"(?:([*+-])|(\d+)([.)]))[ \t]+(.*)")
    # Lines that CommonMark reads as something that BBCode can't say: rules,
    # the line under a table's header, empty list items and headings, deeper
    # headings, quotes, tables, code blocks, and indented lines
    UNSUPPORTED: ClassVar[re.Pattern[str]] = re.compile(
        r"([*_-])(?:[ \t]*\1){2,}[ \t]*$"
        r"|\|?[ \t]*:?-+:?[ \t]*(?:\|[ \t]*:?-+:?[ \t]*)+\|?[ \t]*$"
        r"|(?:[*+-]|\d+[.)]|#+)[ \t]*$"
        r"|#{4,}|>|\||```|~~~|=+[ \t]*$|\s"
    )
    # XenForo's sizes: 4 is 15 pixels, 5 is 18, and 6 is 22
    HEADING_SIZES: ClassVar[dict[int, int]] = {1: 6, 2: 5, 3: 4}
    HINT: ClassVar[str] = (
        "Separate lists from paragraphs with blank lines, don't indent other "
        "than to continue a list item's text, and don't nest lists or use "
        "quotes, tables, code blocks, rules or line breaks"
    )

    def __init__(self, markdown: str) -> None:
        """Read Markdown."""
        self._markdown = markdown
        self._blocks: list[Block] = []
        self._paragraph: list[tuple[int, str]] = []
        self._items: list[tuple[int, str]] = []
        # The current list's bullet or delimiter, and whether it's numbered
        self._marker = ""
        self._ordered = False
        # Whether a blank line came after list items, which more may follow
        self._after_blank = False

    def bbcode(self) -> str:
        """Return the Markdown in BBCode."""
        self._blocks = []
        for number, line in enumerate(self._markdown.splitlines(), 1):
            self._read(number, line)
        self._close()
        return self._joined()

    def _read(self, number: int, line: str) -> None:
        item = self.ITEM.fullmatch(line)
        if not line.strip():
            self._close_paragraph()
            self._after_blank = bool(self._items)
            return
        if self._after_blank and not (item and self._marker_of(item) == self._marker):
            self._close()
        self._after_blank = False
        heading = self.HEADING.fullmatch(line)
        if heading:
            self._close()
            text = InlineMarkdown(heading[2], number).bbcode()
            size = self.HEADING_SIZES[len(heading[1])]
            bbcode = f"[SIZE={size}][B]{text}[/B][/SIZE]"
            self._blocks.append(Block(BlockKind.HEADING, bbcode))
        elif self.UNSUPPORTED.match(line) and not self._continues_item(line):
            raise UnsupportedMarkdownError(number, line, "can't convert", self.HINT)
        elif line.endswith(("  ", "\\")):
            raise UnsupportedMarkdownError(
                number, line, "can't convert the line break in", self.HINT
            )
        elif item and not self._paragraph:
            self._add_item(number, line, item)
        elif self._continues_item(line):
            first, text = self._items[-1]
            self._items[-1] = (first, f"{text} {line.strip()}")
        elif item or self._items:
            raise UnsupportedMarkdownError(number, line, "can't convert", self.HINT)
        else:
            self._paragraph.append((number, line.strip()))

    @staticmethod
    def _marker_of(item: re.Match[str]) -> str:
        return item[1] or item[3]

    def _add_item(self, number: int, line: str, item: re.Match[str]) -> None:
        if self._is_block_syntax(item[4]):
            raise UnsupportedMarkdownError(number, line, "can't convert", self.HINT)
        # A new bullet or delimiter starts a new list, as in CommonMark
        if self._items and self._marker_of(item) != self._marker:
            self._close()
        if not self._items:
            if item[2] is not None and int(item[2]) != 1:
                raise UnsupportedMarkdownError(
                    number, line, "can't start a numbered list at", "Start it at 1"
                )
            self._marker = self._marker_of(item)
            self._ordered = item[2] is not None
        self._items.append((number, item[4]))

    def _continues_item(self, line: str) -> bool:
        """Return whether an indented line continues the last list item's text."""
        return (
            bool(self._items)
            and line.startswith(" ")
            and not self._is_block_syntax(line.strip())
        )

    def _is_block_syntax(self, text: str) -> bool:
        """Return whether text in a list item would start a block inside it."""
        return bool(
            self.ITEM.fullmatch(text)
            or self.HEADING.fullmatch(text)
            or self.UNSUPPORTED.match(text)
        )

    def _close_paragraph(self) -> None:
        if self._paragraph:
            first = self._paragraph[0][0]
            text = " ".join(text for _, text in self._paragraph)
            bbcode = InlineMarkdown(text, first).bbcode()
            self._blocks.append(Block(BlockKind.PARAGRAPH, bbcode))
        self._paragraph = []

    def _close(self) -> None:
        self._close_paragraph()
        if self._items:
            tag = "LIST=1" if self._ordered else "LIST"
            items = "\n".join(
                f"[*]{InlineMarkdown(text, number).bbcode()}"
                for number, text in self._items
            )
            self._blocks.append(Block(BlockKind.LIST, f"[{tag}]\n{items}\n[/LIST]"))
        self._items = []
        self._after_blank = False

    def _joined(self) -> str:
        parts: list[str] = []
        previous: Block | None = None
        for block in self._blocks:
            if previous:
                # XenForo already sets headings and lists apart
                tight = (
                    previous.kind is not BlockKind.PARAGRAPH
                    or block.kind is BlockKind.LIST
                )
                parts.append("\n" if tight else "\n\n")
            parts.append(block.bbcode)
            previous = block
        return "".join(parts) + "\n"


# --- Commands --------------------------------------------------------------------


class Branding:
    """This script's commands."""

    DESCRIPTION: ClassVar[Path] = HERE / "description.md"

    def __init__(self) -> None:
        """Know every image, without loading fonts until one is drawn."""
        fonts = Fonts()
        self._artworks: list[Artwork] = [Icon(), Banner(fonts), SocialPreview(fonts)]

    def draw(self) -> None:
        """Redraw the SVGs."""
        for artwork in self._artworks:
            artwork.svg_path.write_text(artwork.draw().text(), encoding="utf-8")
            sys.stdout.write(f"Drew {artwork.svg_path}\n")

    def render(self) -> None:
        """Render the SVGs as PNGs, and the description as BBCode."""
        for artwork in self._artworks:
            artwork.render()
            sys.stdout.write(f"Wrote {artwork.png_path}\n")
        bbcode = BUILD / "description.bbcode"
        bbcode.write_text(self._bbcode(), encoding="utf-8")
        sys.stdout.write(f"Wrote {bbcode}\n")

    def bbcode(self) -> None:
        """Print the description as BBCode."""
        sys.stdout.write(self._bbcode())

    def run(self, arguments: Sequence[str]) -> int:
        """Run the command that the arguments name, and return the exit status."""
        commands: dict[str, Callable[[], None]] = {
            "render": self.render,
            "draw": self.draw,
            "bbcode": self.bbcode,
        }
        parser = argparse.ArgumentParser(
            description=__doc__,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument("command", nargs="?", choices=commands, default="render")
        command: str = parser.parse_args(arguments).command
        try:
            commands[command]()
        except BrandingError as error:
            sys.stderr.write(f"error: {error}\n")
            return 1
        return 0

    def _bbcode(self) -> str:
        try:
            markdown = self.DESCRIPTION.read_text(encoding="utf-8")
        except OSError as error:
            message = f"can't read {self.DESCRIPTION}: {error.strerror}"
            raise BrandingError(message) from error
        except UnicodeDecodeError as error:
            message = f"{self.DESCRIPTION} isn't UTF-8: {error.reason}"
            raise BrandingError(message) from error
        return MarkdownToBBCode(markdown).bbcode()


if __name__ == "__main__":
    sys.exit(Branding().run(sys.argv[1:]))
