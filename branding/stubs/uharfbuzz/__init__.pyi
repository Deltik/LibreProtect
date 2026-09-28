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

# Types for the part of uharfbuzz that generate.py uses, which it ships without

from collections.abc import Callable
from typing import NamedTuple

class Blob:
    def __init__(self, data: bytes) -> None: ...

class Face:
    def __init__(self, blob: Blob) -> None: ...
    @property
    def upem(self) -> int: ...

class GlyphExtents(NamedTuple):
    x_bearing: int
    y_bearing: int
    width: int
    height: int

class GlyphInfo:
    @property
    def codepoint(self) -> int: ...

class GlyphPosition:
    @property
    def x_advance(self) -> int: ...
    @property
    def x_offset(self) -> int: ...
    @property
    def y_offset(self) -> int: ...

# Generic in the state that a glyph's outline is drawn with, which each callback
# gets. Only the stub is generic: name DrawFuncs[...] only in annotations.
class DrawFuncs[State]:
    def set_move_to_func(
        self, func: Callable[[float, float, State], object]
    ) -> None: ...
    def set_line_to_func(
        self, func: Callable[[float, float, State], object]
    ) -> None: ...
    def set_cubic_to_func(
        self,
        func: Callable[[float, float, float, float, float, float, State], object],
    ) -> None: ...
    def set_quadratic_to_func(
        self,
        func: Callable[[float, float, float, float, State], object],
    ) -> None: ...
    def set_close_path_func(self, func: Callable[[State], object]) -> None: ...

class Font:
    def __init__(self, face: Face) -> None: ...
    @property
    def face(self) -> Face: ...
    def draw_glyph[State](
        self,
        gid: int,
        draw_funcs: DrawFuncs[State],
        draw_state: State,
    ) -> None: ...
    def get_glyph_extents(self, gid: int) -> GlyphExtents | None: ...

class Buffer:
    def __init__(self) -> None: ...
    def add_str(self, text: str) -> None: ...
    def guess_segment_properties(self) -> None: ...
    @property
    def glyph_infos(self) -> list[GlyphInfo]: ...
    @property
    def glyph_positions(self) -> list[GlyphPosition]: ...

def shape(
    font: Font,
    buffer: Buffer,
    features: dict[str, bool | int] | None = None,
) -> None: ...
