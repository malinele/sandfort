"""Column layout of a CLI table when the width is short.

A table has two kinds of columns. *Fixed* columns (state, isolation, counts, ids, timestamps)
never shrink below the width of their header or longest value: no wrap, no ellipsis. *Free-text*
columns (name, labels, image, url, error) absorb the shrinking and are cut with an ellipsis.
When the free-text columns cannot be cut enough, the lowest-priority one is dropped instead of
squeezing a fixed column. If the fixed columns alone are wider than the terminal, the table is
printed at the width they need (the terminal wraps the lines) rather than cut.

:func:`plan_layout` is pure (no Rich, no I/O); :func:`add_columns` turns its answer into Rich
columns.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from rich.cells import cell_len
from rich.table import Table
from rich.text import Text

# A free-text column is never cut below this many cells (or its header, if that is wider).
MIN_FREE_WIDTH = 8
# Headers of columns that hold free text. A table with none of them takes its last column as
# free text; a table with one never does (its last column is often a status or a date).
FREE_TEXT_HEADERS = frozenset(
    {"NAME", "EMAIL", "LABELS", "IMAGE", "URL", "EVENTS", "ERROR", "LAST ERROR", "REASON"}
)
# Rich draws one space of padding on each side of a cell and one border in front of it.
BORDER_AND_PADDING_PER_COLUMN = 3
CLOSING_BORDER = 1

Cell = str | Text
# Cuts ``text`` to at most ``limit`` characters at a grapheme boundary, ending in an ellipsis.
Cutter = Callable[[str, int], str]


@dataclass(frozen=True)
class TableLayout:
    """Which columns a table prints and how wide.

    ``kept`` are the indexes of the printed columns, in order. ``limits`` maps the index of a
    free-text column that is cut to its width. ``naturals`` is the width of every column of the
    input (header or longest line). ``width`` is the width to print at: the available width, or
    more when the fixed columns alone need more.
    """

    kept: tuple[int, ...]
    limits: Mapping[int, int]
    naturals: tuple[int, ...]
    width: int


def default_free_columns(columns: Sequence[str]) -> tuple[str, ...]:
    """The free-text columns, highest priority first, when the caller does not mark them.

    The columns with a free-text header (left to right); when there is none, the last column.
    """
    marked = [name for name in columns if name in FREE_TEXT_HEADERS]
    if not marked and columns:
        marked.append(columns[-1])
    return tuple(marked)


def cell_width(cell: Cell) -> int:
    """The widest line of ``cell`` in terminal cells."""
    plain = cell.plain if isinstance(cell, Text) else cell
    return max((cell_len(line) for line in plain.splitlines()), default=0)


def _table_overhead(column_count: int) -> int:
    return BORDER_AND_PADDING_PER_COLUMN * column_count + CLOSING_BORDER


def _free_indexes(columns: Sequence[str], free: Sequence[str]) -> list[int]:
    """The indexes of the ``free`` columns, in priority order; an unknown name is an error."""
    indexes: list[int] = []
    for name in free:
        found = [i for i, column in enumerate(columns) if column == name]
        if not found:
            raise ValueError(f"unknown free-text column: {name}")
        indexes.extend(i for i in found if i not in indexes)
    return indexes


def _natural_widths(columns: Sequence[str], rows: Sequence[Sequence[Cell]]) -> tuple[int, ...]:
    return tuple(
        max([cell_len(name), *(cell_width(row[index]) for row in rows)])
        for index, name in enumerate(columns)
    )


def _grow(minimums: Mapping[int, int], naturals: Sequence[int], spare: int) -> dict[int, int]:
    """``minimums`` grown towards the natural widths, highest priority first, by ``spare``."""
    widths = dict(minimums)
    for index in widths:
        step = max(0, min(naturals[index] - widths[index], spare))
        widths[index] += step
        spare -= step
    return widths


def plan_layout(
    columns: Sequence[str],
    rows: Sequence[Sequence[Cell]],
    free: Sequence[str],
    width: int,
    uncut: Sequence[str] = (),
) -> TableLayout:
    """Decide which columns are printed and how wide, for a table ``width`` cells wide.

    ``free`` names the free-text columns, highest priority first; every other column is fixed.
    A column of ``free`` that is also named in ``uncut`` (an id) is never cut: it is printed
    whole or dropped, in its place of the priority order.
    """
    free_order = _free_indexes(columns, free)  # validated first, also when everything fits
    naturals = _natural_widths(columns, rows)
    all_indexes = tuple(range(len(columns)))
    if sum(naturals) + _table_overhead(len(columns)) <= width:
        return TableLayout(all_indexes, {}, naturals, width)
    fixed = [i for i in all_indexes if i not in free_order]
    fixed_total = sum(naturals[i] for i in fixed)
    uncut_names = set(uncut)
    minimums = {
        i: naturals[i]
        if columns[i] in uncut_names
        else min(naturals[i], max(MIN_FREE_WIDTH, cell_len(columns[i])))
        for i in free_order
    }
    kept_free = list(free_order)
    while kept_free and (
        fixed_total
        + sum(minimums[i] for i in kept_free)
        + _table_overhead(len(fixed) + len(kept_free))
        > width
    ):
        kept_free.pop()  # the lowest priority goes first
    kept = tuple(sorted([*fixed, *kept_free]))
    spare = width - _table_overhead(len(kept)) - fixed_total - sum(minimums[i] for i in kept_free)
    grown = _grow({i: minimums[i] for i in kept_free}, naturals, spare)
    limits = {i: w for i, w in grown.items() if w < naturals[i]}
    needed = fixed_total + _table_overhead(len(fixed))
    return TableLayout(kept, limits, naturals, max(width, needed))


def hidden_columns(columns: Sequence[str], layout: TableLayout) -> tuple[str, ...]:
    """The names of the columns ``layout`` drops, in table order."""
    return tuple(name for index, name in enumerate(columns) if index not in layout.kept)


def add_columns(table: Table, columns: Sequence[str], layout: TableLayout) -> None:
    """Add the kept columns of ``layout`` to ``table``. A column that is cut gets its width as
    the maximum (its cells are cut by :func:`cut_cell` beforehand, so Rich never has to); every
    other column keeps at least its natural width and is never wrapped or cut."""
    for index in layout.kept:
        limit = layout.limits.get(index)
        if limit is None:
            table.add_column(
                columns[index], no_wrap=True, overflow="fold", min_width=layout.naturals[index]
            )
        else:
            table.add_column(columns[index], no_wrap=True, overflow="fold", max_width=limit)


def cut_cell(text: str, limit: int, cut: Cutter) -> str:
    """``text`` cut line by line to at most ``limit`` terminal cells with ``cut`` (which counts
    characters; a wide character is shortened until the line fits). Rich's own ellipsis is
    not used: it counts code points and can split a flag or an emoji sequence."""
    return "\n".join(_cut_line(line, limit, cut) for line in text.split("\n"))


def _cut_line(line: str, limit: int, cut: Cutter) -> str:
    cut_line = cut(line, limit)
    while cell_len(cut_line) > limit and len(cut_line) > 1:
        cut_line = cut(line, len(cut_line) - 1)
    return cut_line


def layout_table(
    title: str,
    columns: Sequence[str],
    rows: Sequence[Sequence[Cell]],
    free: Sequence[str],
    width: int,
    cut: Cutter,
    uncut: Sequence[str] = (),
) -> tuple[Table, TableLayout]:
    """The table of ``rows`` laid out for ``width`` cells, and the layout it follows (its
    ``width`` is the width to print at, :func:`hidden_columns` names what was dropped).

    Columns that do not fit are dropped, free-text cells that are too long are cut with
    ``cut`` (a :class:`Text` cell keeps its own settings), fixed columns stay whole.
    """
    layout = plan_layout(columns, rows, free, width, uncut)
    table = Table(title=Text(title))
    add_columns(table, columns, layout)
    for row in rows:
        table.add_row(*(_cell(row[i], layout.limits.get(i), cut) for i in layout.kept))
    return table, layout


def fit_table(
    title: str,
    columns: Sequence[str],
    rows: Sequence[Sequence[Cell]],
    free: Sequence[str],
    width: int,
    cut: Cutter,
) -> tuple[Table, int]:
    """:func:`layout_table` for a caller that needs only the table and the width to print at."""
    table, layout = layout_table(title, columns, rows, free, width, cut)
    return table, layout.width


def _cell(cell: Cell, limit: int | None, cut: Cutter) -> Text:
    """``cell`` as :class:`Text`, never markup: a cell holding "[/x]" is data."""
    if isinstance(cell, Text):
        return cell
    return Text(cell if limit is None else cut_cell(cell, limit, cut))


def whole_column_table(
    title: str, columns: Sequence[str], rows: Sequence[Sequence[Cell]], whole: Sequence[str]
) -> Table:
    """A table whose ``whole`` columns get their full width and never wrap or cut; the other
    columns may fold onto several lines."""
    table = Table(title=Text(title))
    for index, column in enumerate(columns):
        if column in whole:
            widest = max([cell_len(column), *(cell_width(row[index]) for row in rows)])
            table.add_column(column, no_wrap=True, overflow="ignore", min_width=widest)
        else:
            table.add_column(column, no_wrap=False, overflow="fold")
    for row in rows:
        table.add_row(*(cell if isinstance(cell, Text) else Text(cell) for cell in row))
    return table
