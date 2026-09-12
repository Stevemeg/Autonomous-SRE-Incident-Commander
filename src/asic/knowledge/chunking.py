"""Deterministic, structure-aware chunking of canonical operational text.

Operational documents have meaning in their structure: a runbook step, a command block, a
table of thresholds, a known-error entry. A chunk that splits a rollback procedure in half
retrieves well and advises badly, so chunk boundaries follow structure first and size
second (``docs/architecture/memory-and-rag.md`` section 2.1).

The algorithm, in order:

1. Split the text into **blocks**: headings, fenced code, tables, list runs (runbook steps)
   and paragraphs. A fenced block is never split by the block pass.
2. Assemble blocks into chunks within one **section** - a heading always starts a new
   chunk, so a chunk never straddles two sections.
3. A chunk closes when adding the next block would exceed the target size.
4. A single block larger than the maximum is split: structured blocks at line boundaries,
   prose and over-long lines by a bounded window with overlap. Only the window fallback is
   recorded as ``window_overlap``.

Every chunk carries exact character offsets and 1-based line numbers into the canonical
text, and its heading breadcrumb, so a citation can point at the precise source location.
No model is involved: boundaries are a pure function of the text and :class:`ChunkLimits`.
"""

from __future__ import annotations

import bisect
import hashlib
import re
from dataclasses import dataclass
from typing import Final

from asic.domain.enums import ChunkStrategy
from asic.knowledge.errors import KnowledgeRejected

#: Version of these rules. Recorded on every version row; changing it is a re-index.
CHUNKER_VERSION: Final[str] = "structure-aware/1"

_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_FENCE = re.compile(r"^\s*(```|~~~)")
_LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d{1,3}[.)])\s+")
_TABLE_ROW = re.compile(r"^\s*\|")


@dataclass(frozen=True, slots=True)
class ChunkLimits:
    """Bounds that keep a pathological document from exhausting memory or storage."""

    target_chars: int = 900
    max_chars: int = 1200
    window_overlap_chars: int = 150
    max_chunks: int = 256
    max_section_depth: int = 6
    max_heading_chars: int = 200

    def __post_init__(self) -> None:
        if not 0 <= self.window_overlap_chars < self.max_chars // 2:
            raise ValueError("overlap must be non-negative and under half the maximum")
        if not 0 < self.target_chars <= self.max_chars:
            raise ValueError("target must be positive and no larger than the maximum")


@dataclass(frozen=True, slots=True)
class ChunkDraft:
    sequence: int
    text: str
    section_path: tuple[str, ...]
    start_offset: int
    end_offset: int
    start_line: int
    end_line: int
    strategy: ChunkStrategy
    content_hash: str


@dataclass(frozen=True, slots=True)
class _Block:
    kind: str
    start: int
    end: int
    section: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Span:
    start: int
    end: int
    section: tuple[str, ...]
    strategy: ChunkStrategy


def chunk_document(text: str, limits: ChunkLimits | None = None) -> tuple[ChunkDraft, ...]:
    """Chunk canonical text.

    Raises:
        KnowledgeRejected: ``too_many_chunks`` when the document exceeds ``max_chunks``;
            ``empty_document`` when there is nothing to chunk.
    """
    limits = limits or ChunkLimits()
    if not text.strip():
        raise KnowledgeRejected("empty_document")
    line_starts = _line_starts(text)
    blocks = _blocks(text, line_starts, limits)
    spans = _assemble(text, blocks, limits)

    drafts: list[ChunkDraft] = []
    for span in spans:
        start, end = _trim(text, span.start, span.end)
        if start >= end:
            continue
        if len(drafts) >= limits.max_chunks:
            raise KnowledgeRejected("too_many_chunks")
        piece = text[start:end]
        drafts.append(
            ChunkDraft(
                sequence=len(drafts),
                text=piece,
                section_path=span.section,
                start_offset=start,
                end_offset=end,
                start_line=bisect.bisect_right(line_starts, start),
                end_line=bisect.bisect_right(line_starts, end - 1),
                strategy=span.strategy,
                content_hash=hashlib.sha256(piece.encode("utf-8")).hexdigest(),
            )
        )
    if not drafts:
        raise KnowledgeRejected("empty_document")
    return tuple(drafts)


# ------------------------------------------------------------------------ block pass


def _line_starts(text: str) -> list[int]:
    starts = [0]
    for index, char in enumerate(text):
        if char == "\n":
            starts.append(index + 1)
    return starts


def _lines(text: str, line_starts: list[int]) -> list[tuple[int, int, str]]:
    """(start, end-exclusive-of-newline, content) for every line."""
    result = []
    for number, start in enumerate(line_starts):
        end = line_starts[number + 1] - 1 if number + 1 < len(line_starts) else len(text)
        result.append((start, end, text[start:end]))
    return result


def _blocks(text: str, line_starts: list[int], limits: ChunkLimits) -> list[_Block]:
    lines = _lines(text, line_starts)
    blocks: list[_Block] = []
    section: tuple[str, ...] = ()
    index = 0
    while index < len(lines):
        start, end, content = lines[index]
        if not content.strip():
            index += 1
            continue

        fence = _FENCE.match(content)
        if fence:
            marker = fence.group(1)
            closing = index + 1
            while closing < len(lines) and not lines[closing][2].lstrip().startswith(marker):
                closing += 1
            last = min(closing, len(lines) - 1)
            blocks.append(_Block("code", start, lines[last][1], section))
            index = last + 1
            continue

        heading = _HEADING.match(content)
        if heading:
            level = len(heading.group(1))
            title = heading.group(2).strip()[: limits.max_heading_chars]
            section = (*section[: level - 1], title)[: limits.max_section_depth]
            blocks.append(_Block("heading", start, end, section))
            index += 1
            continue

        kind = (
            "table"
            if _TABLE_ROW.match(content)
            else "list"
            if _LIST_ITEM.match(content)
            else "paragraph"
        )
        last = index
        while last + 1 < len(lines):
            following = lines[last + 1][2]
            if not following.strip() or _FENCE.match(following) or _HEADING.match(following):
                break
            if kind == "table" and not _TABLE_ROW.match(following):
                break
            if kind == "paragraph" and (_TABLE_ROW.match(following) or _LIST_ITEM.match(following)):
                break
            if kind == "list" and _TABLE_ROW.match(following):
                break
            last += 1
        blocks.append(_Block(kind, start, lines[last][1], section))
        index = last + 1
    return blocks


# --------------------------------------------------------------------- assembly pass


def _assemble(text: str, blocks: list[_Block], limits: ChunkLimits) -> list[_Span]:
    spans: list[_Span] = []
    current: list[_Block] = []

    def flush() -> None:
        if current:
            spans.append(
                _Span(
                    current[0].start,
                    current[-1].end,
                    current[0].section,
                    ChunkStrategy.STRUCTURE_AWARE,
                )
            )
            current.clear()

    for block in blocks:
        if block.kind == "heading":
            flush()
        size = block.end - block.start
        if size > limits.max_chars:
            flush()
            spans.extend(_split_block(text, block, limits))
            continue
        pending = (block.end - current[0].start) if current else size
        if current and (pending > limits.target_chars or block.section != current[0].section):
            flush()
        current.append(block)
    flush()
    return spans


def _split_block(text: str, block: _Block, limits: ChunkLimits) -> list[_Span]:
    """Split one over-sized block. Structured blocks break at lines; prose at a window."""
    if block.kind == "paragraph":
        return _window(text, block.start, block.end, block.section, limits)

    spans: list[_Span] = []
    piece_start = block.start
    cursor = block.start
    while cursor < block.end:
        newline = text.find("\n", cursor, block.end)
        line_end = block.end if newline == -1 else newline
        if line_end - cursor > limits.max_chars:
            # One line longer than a chunk: close what we have, window the line itself.
            if cursor > piece_start:
                spans.append(
                    _Span(piece_start, cursor, block.section, ChunkStrategy.STRUCTURE_AWARE)
                )
            spans.extend(_window(text, cursor, line_end, block.section, limits))
            piece_start = cursor = line_end + 1
            continue
        if line_end - piece_start > limits.max_chars and cursor > piece_start:
            spans.append(_Span(piece_start, cursor, block.section, ChunkStrategy.STRUCTURE_AWARE))
            piece_start = cursor
        cursor = line_end + 1
    if piece_start < block.end:
        spans.append(_Span(piece_start, block.end, block.section, ChunkStrategy.STRUCTURE_AWARE))
    return spans


def _window(
    text: str, start: int, end: int, section: tuple[str, ...], limits: ChunkLimits
) -> list[_Span]:
    """Bounded windows with overlap, breaking at whitespace where one exists."""
    spans: list[_Span] = []
    position = start
    while position < end:
        stop = min(position + limits.max_chars, end)
        if stop < end:
            floor = position + limits.max_chars // 2
            space = max(text.rfind(" ", floor, stop), text.rfind("\n", floor, stop))
            if space > position:
                stop = space
        spans.append(_Span(position, stop, section, ChunkStrategy.WINDOW_OVERLAP))
        if stop >= end:
            break
        restart = max(stop - limits.window_overlap_chars, position + 1)
        boundary = text.find(" ", restart, stop)
        position = boundary + 1 if boundary != -1 else restart
    return spans


def _trim(text: str, start: int, end: int) -> tuple[int, int]:
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return start, end


__all__ = ["CHUNKER_VERSION", "ChunkDraft", "ChunkLimits", "chunk_document"]
