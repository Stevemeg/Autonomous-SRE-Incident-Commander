"""Deterministic canonicalization of imported documents.

The canonical text is what gets hashed, chunked, embedded and cited. It must therefore be a
pure function of the input bytes and the declared format: the same document imported twice,
on any host, yields byte-identical canonical text, and so the same content hash and the same
chunk boundaries.

Canonicalization also removes the characters that exist mainly to hide things from a
reader - zero-width and bidirectional-control characters, and every other format or control
character except newline. The count is recorded. HTML is reduced to text with its active
content (scripts, styles, frames, embedded objects) dropped entirely rather than escaped.

None of this is the prompt-injection defence. Injection patterns are *detected* here and
recorded as a signal; the defence is that retrieved text only ever reaches a model inside a
fenced untrusted block and has no path to authorization (``docs/architecture/memory-and-rag.md``
section 4).
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Final

from asic.domain.enums import KnowledgeContentFormat
from asic.domain.untrusted import scan
from asic.knowledge.errors import KnowledgeRejected

#: Version of the canonicalization rules. Recorded on every version row, because a change
#: here changes content hashes and chunk boundaries - a re-index, not a refactor.
PARSER_VERSION: Final[str] = "canonical-text/1"

#: Largest accepted document, in bytes of the original encoding.
MAX_DOCUMENT_BYTES: Final[int] = 512 * 1024

#: Largest accepted document after canonicalization, in lines.
MAX_DOCUMENT_LINES: Final[int] = 20_000

#: Unicode categories removed outright: control, format (zero-width, bidirectional
#: overrides, soft hyphen), surrogate, private use and unassigned.
_REMOVED_CATEGORIES: Final[frozenset[str]] = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})

#: Line and paragraph separators. Not control characters by category, but they break lines
#: invisibly in some renderers, so they are removed with the rest.
_INVISIBLE_SEPARATORS: Final[frozenset[str]] = frozenset({chr(0x2028), chr(0x2029)})

_BLANK_RUN = re.compile(r"\n{3,}")


@dataclass(frozen=True, slots=True)
class CanonicalDocument:
    text: str
    content_hash: str
    content_format: KnowledgeContentFormat
    #: Characters removed as control/format characters. A non-zero count is not an error.
    removed_characters: int
    #: Injection-pattern names found in the canonical text. A signal, not a verdict.
    injection_flags: tuple[str, ...]


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonicalize(raw: bytes, content_format: KnowledgeContentFormat) -> CanonicalDocument:
    """Reduce one document to its canonical text.

    Raises:
        KnowledgeRejected: ``document_too_large``, ``invalid_utf8``, ``empty_document`` or
            ``too_many_lines``. Every refusal is deterministic.
    """
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise KnowledgeRejected("document_too_large")
    try:
        decoded = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise KnowledgeRejected("invalid_utf8") from exc

    if content_format is KnowledgeContentFormat.HTML:
        decoded = html_to_text(decoded)

    text, removed = sanitize(decoded)
    if not text:
        raise KnowledgeRejected("empty_document")
    if text.count("\n") + 1 > MAX_DOCUMENT_LINES:
        raise KnowledgeRejected("too_many_lines")
    return CanonicalDocument(
        text=text,
        content_hash=content_hash(text),
        content_format=content_format,
        removed_characters=removed,
        injection_flags=scan(text),
    )


def sanitize(text: str) -> tuple[str, int]:
    """NFC-normalise, unify newlines, strip control/format characters and trailing space.

    Returns the canonical text and how many characters were removed as control or format
    characters (zero-width joiners, bidirectional overrides, soft hyphens, NULs, ...).
    """
    text = unicodedata.normalize("NFC", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\t", "    ")
    kept: list[str] = []
    removed = 0
    for char in text:
        if char == "\n":
            kept.append(char)
            continue
        if unicodedata.category(char) in _REMOVED_CATEGORIES or char in _INVISIBLE_SEPARATORS:
            removed += 1
            continue
        kept.append(char)
    lines = [line.rstrip() for line in "".join(kept).split("\n")]
    joined = _BLANK_RUN.sub("\n\n", "\n".join(lines)).strip("\n")
    return joined, removed


# ----------------------------------------------------------------------------- HTML

#: Elements whose content is dropped entirely: active content and page chrome.
_SKIPPED: Final[frozenset[str]] = frozenset(
    {"script", "style", "noscript", "iframe", "object", "embed", "template", "svg", "head"}
)
_HEADINGS: Final[dict[str, int]] = {f"h{level}": level for level in range(1, 7)}
_PARAGRAPH_BREAKS: Final[frozenset[str]] = frozenset(
    {
        "p",
        "div",
        "section",
        "article",
        "header",
        "footer",
        "main",
        "aside",
        "blockquote",
        "ul",
        "ol",
        "table",
        "dl",
        "hr",
    }
)
_WHITESPACE = re.compile(r"\s+")


class _HtmlToText(HTMLParser):
    """Minimal, deterministic HTML-to-text reduction. Attributes are always discarded."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip_depth = 0
        self._in_pre = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        if tag in _SKIPPED:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag in _HEADINGS:
            self.parts.append("\n\n" + "#" * _HEADINGS[tag] + " ")
        elif tag == "li":
            self.parts.append("\n- ")
        elif tag == "pre":
            self._in_pre = True
            self.parts.append("\n\n```\n")
        elif tag == "tr":
            self.parts.append("\n|")
        elif tag == "br":
            self.parts.append("\n")
        elif tag in _PARAGRAPH_BREAKS:
            self.parts.append("\n\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIPPED:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if self._skip_depth:
            return
        if tag in _HEADINGS:
            self.parts.append("\n\n")
        elif tag == "pre":
            self._in_pre = False
            self.parts.append("\n```\n\n")
        elif tag in ("td", "th"):
            self.parts.append(" |")
        elif tag in _PARAGRAPH_BREAKS or tag == "li":
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._in_pre:
            self.parts.append(data)
            return
        collapsed = _WHITESPACE.sub(" ", data)
        if not collapsed.strip():
            return
        at_line_start = not self.parts or self.parts[-1].endswith(("\n", " "))
        self.parts.append(collapsed.lstrip() if at_line_start else collapsed)


def html_to_text(markup: str) -> str:
    parser = _HtmlToText()
    parser.feed(markup)
    parser.close()
    return "".join(parser.parts)


__all__ = [
    "MAX_DOCUMENT_BYTES",
    "MAX_DOCUMENT_LINES",
    "PARSER_VERSION",
    "CanonicalDocument",
    "canonicalize",
    "content_hash",
    "html_to_text",
    "sanitize",
]
