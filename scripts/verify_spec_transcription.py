#!/usr/bin/env python3
"""Verify that the Markdown transcription of the master specification is faithful.

The authoritative specification is the Word document in ``docs/spec/``. The Markdown
file next to it exists only to make the specification diffable and greppable in version
control. This script proves the two agree, in *both* directions:

  * every content line in the ``.docx`` appears in the Markdown  -> nothing was dropped
  * every content line in the Markdown appears in the ``.docx``  -> nothing was invented

The second direction is the one that matters most: master prompt section 20 forbids
silently rewriting the specification, and section 23 forbids inventing requirements.

Only the Python standard library is used, so this runs in CI with no dependencies.

Exit code 0 = transcription verified, 1 = mismatch, 2 = usage/IO error.
"""

from __future__ import annotations

import argparse
import html
import re
import sys
import unicodedata
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DOCX = REPO_ROOT / "docs" / "spec" / (
    "Autonomous SRE Incident Commander - Master Project Prompt V3.docx"
)
DEFAULT_MD = REPO_ROOT / "docs" / "spec" / "MASTER_PROJECT_PROMPT_V3.md"

# Markdown lines that are presentation-only or belong to the transcription notice, and
# therefore have no counterpart in the source document.
MD_SKIP_PREFIXES = (">",)
MD_SKIP_EXACT = {"", "---"}


def docx_lines(path: Path) -> list[str]:
    """Return the visible text lines of a .docx, in document order."""
    with zipfile.ZipFile(path) as zf:
        xml = zf.read("word/document.xml").decode("utf-8")

    lines: list[str] = []
    for para in re.findall(r"<w:p[ >].*?</w:p>|<w:p/>", xml, re.S):
        text = re.sub(r"<w:tab[^>]*/>", "\t", para)
        text = re.sub(r"<w:br[^>]*/>", "\n", text)
        text = re.sub(r"</w:p>", "\n", text)
        text = re.sub(r"<[^>]+>", "", text)
        text = html.unescape(text)
        lines.extend(text.split("\n"))
    return lines


def md_lines(path: Path) -> list[str]:
    """Return the content lines of the Markdown transcription, excluding presentation."""
    out: list[str] = []
    for raw in path.read_text(encoding="utf-8").split("\n"):
        line = raw.strip()
        if line in MD_SKIP_EXACT or line.startswith(MD_SKIP_PREFIXES):
            continue
        out.append(line)
    return out


def normalize(line: str) -> str:
    """Reduce a line to comparable content.

    Strips Markdown structural syntax and bullet glyphs, collapses whitespace and
    normalizes Unicode form. Deliberately case- and punctuation-preserving so that a
    silent reword of a requirement is still detected as a mismatch.
    """
    text = unicodedata.normalize("NFC", line).strip()
    text = text.replace("\t", " ")
    text = text.lstrip("#").strip()          # Markdown headings
    text = re.sub(r"^[-*+]\s+", "", text)    # Markdown bullets
    text = re.sub(r"^\d+\.\s+", "", text)    # Markdown ordered-list markers
    text = text.lstrip("•").strip()  # literal bullet glyphs from the .docx
    text = text.replace("*", "").replace("`", "")  # emphasis / code spans
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def content_set(lines: list[str]) -> list[str]:
    normalized = [normalize(line) for line in lines]
    return [line for line in normalized if line]


# Numbered section headings, detected on the RAW lines. This must not run after
# normalize(), which strips ordered-list markers and would erase the numbering,
# silently reducing the ordering check to a comparison of two empty lists.
DOCX_HEADING_RE = re.compile(r"^\s*(\d{1,2})\.\s+([A-Z].*)$")
MD_HEADING_RE = re.compile(r"^#{1,6}\s+(\d{1,2})\.\s+([A-Z].*)$")


def headings(lines: list[str], pattern: re.Pattern[str]) -> list[str]:
    """Return 'N. TITLE' for each numbered section heading, in document order."""
    found = []
    for line in lines:
        match = pattern.match(line.strip())
        if match:
            number = match.group(1)
            title = re.sub(r"\s+", " ", match.group(2)).strip()
            found.append(f"{number}. {title}")
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docx", type=Path, default=DEFAULT_DOCX)
    parser.add_argument("--md", type=Path, default=DEFAULT_MD)
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="print every compared line"
    )
    args = parser.parse_args()

    for path in (args.docx, args.md):
        if not path.is_file():
            print(f"ERROR: not found: {path}", file=sys.stderr)
            return 2

    raw_source = docx_lines(args.docx)
    raw_target = md_lines(args.md)

    source = content_set(raw_source)
    target = content_set(raw_target)
    source_set, target_set = set(source), set(target)

    missing = [line for line in source if line not in target_set]   # dropped
    added = [line for line in target if line not in source_set]     # invented

    # The numbered sections must appear in the Markdown in the source's order.
    source_headings = headings(raw_source, DOCX_HEADING_RE)
    target_headings = headings(raw_target, MD_HEADING_RE)
    heading_order_ok = bool(source_headings) and source_headings == target_headings

    print(f"source (.docx) : {args.docx.name}")
    print(f"target (.md)   : {args.md.name}")
    print(f"content lines  : {len(source)} in .docx, {len(target)} in .md")
    print(f"sections found : {len(source_headings)} in .docx, {len(target_headings)} in .md")
    print(f"section order  : {'MATCH' if heading_order_ok else 'MISMATCH'}")
    print(f"dropped lines  : {len(missing)}")
    print(f"invented lines : {len(added)}")

    if args.verbose:
        for line in target:
            print(f"  ok  | {line[:110]}")

    if missing:
        print("\nPresent in .docx but MISSING from Markdown:", file=sys.stderr)
        for line in missing:
            print(f"  - {line}", file=sys.stderr)
    if added:
        print("\nPresent in Markdown but NOT in .docx (possible invented content):", file=sys.stderr)
        for line in added:
            print(f"  + {line}", file=sys.stderr)
    if not heading_order_ok:
        print("\nSection heading sequence differs:", file=sys.stderr)
        print(f"  .docx: {source_headings}", file=sys.stderr)
        print(f"  .md  : {target_headings}", file=sys.stderr)

    if missing or added or not heading_order_ok:
        print("\nRESULT: TRANSCRIPTION MISMATCH", file=sys.stderr)
        return 1

    print("\nRESULT: TRANSCRIPTION VERIFIED (bidirectional, section order preserved)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
