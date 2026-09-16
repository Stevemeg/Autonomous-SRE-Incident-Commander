#!/usr/bin/env python3
"""Validate the documentation set before committing.

This is repository tooling, not product code. It exists because master specification
section 20 requires running relevant validation and reporting actual results before
declaring anything complete, and because an architecture package whose diagrams do not
render, whose links rot, or which silently drops a requirement is a defect that is cheap
to catch mechanically and expensive to catch by review.

Checks performed:

  1. Internal links      - every relative Markdown link resolves to a file that exists.
  2. Mermaid structure   - fenced mermaid blocks declare a known diagram type and are
                           structurally balanced (subgraph/end, brackets, quotes).
                           This is a structural check, not a full parse; full rendering
                           validation is a CI concern once Node tooling exists (Phase 14).
  3. Requirement trace   - every requirement ID defined in the SRS appears in the
                           traceability matrix, and every ID in the matrix is defined
                           in the SRS. Neither direction may drift.
  4. Spec responsibility - every agent/node responsibility named in master specification
                           section 4 has an explicit disposition in the agent topology
                           document. Nothing from the specification may silently vanish.
  5. Phase boundary      - no code exists for a phase that has not been approved:
                           no external integrations or evaluation harness.
  6. Unmeasured claims   - no invented improvement percentages (sections 9 and 22).

Standard library only. Exit code 0 = clean, 1 = findings.
"""

from __future__ import annotations

import re
import sys
import urllib.parse
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / "docs"

SPEC_MD = DOCS / "spec" / "MASTER_PROJECT_PROMPT_V3.md"
SRS_MD = DOCS / "prd" / "SRS.md"
RTM_MD = DOCS / "architecture" / "requirements-traceability.md"
TOPOLOGY_MD = DOCS / "architecture" / "agent-topology.md"

# Diagram types we use and that GitHub/Mermaid recognise.
KNOWN_DIAGRAM_TYPES = (
    "flowchart",
    "graph",
    "sequenceDiagram",
    "stateDiagram-v2",
    "stateDiagram",
    "erDiagram",
    "classDiagram",
    "journey",
    "gantt",
    "pie",
    "mindmap",
    "timeline",
)

# A requirement identifier as defined in the SRS tables.
REQ_ID = re.compile(r"\b((?:FR|NFR)-[A-Z]{3}-\d{2}|CON-\d{2})\b")
REQ_DEFINITION = re.compile(r"^\|\s*((?:FR|NFR)-[A-Z]{3}-\d{2}|CON-\d{2})\s*\|")

# [text](target) - excluding images.
MD_LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)]+)\)")

# "37% faster", "12% improvement" - the invented-metric pattern sections 9 and 22 forbid.
UNMEASURED_CLAIM = re.compile(
    r"\b\d+(?:\.\d+)?\s*%\s*(?:faster|slower|improvement|better|worse|reduction|increase\s+in\s+accuracy)",
    re.IGNORECASE,
)
SAFETY_INVARIANT_DEFINITION = re.compile(r"^\|\s*\*\*(SI-\d+)\*\*\s*\|", re.MULTILINE)

# Phase 6 adds governed operational knowledge, retrieval and memory to the read-only
# investigation. Anything belonging to a later, unapproved phase is a scope violation, and
# cheap to detect mechanically. The list moves forward one phase at a time, deliberately: a
# boundary that only ever loosens stops being a boundary.

#: Source trees that may contain implementation at the current phase.
ALLOWED_SOURCE_ROOTS = (
    "src/asic/__init__.py",
    "src/asic/contracts",
    "src/asic/db",
    "src/asic/domain",
    "src/asic/ingestion",
    "src/asic/knowledge",
    "src/asic/llm",
    "src/asic/memory",
    "src/asic/observability",
    "src/asic/orchestration",
    "src/asic/remediation",  # Phase 8 - the human-decision surface behind the graph (ADR-0023)
    "src/asic/api",  # Phase 9 - authenticated HTTP surfaces
    "src/asic/integrations",  # Phase 10 - native external adapters behind the broker
    "src/asic/notifications",  # Phase 10 - S2 deterministic notification service
    "src/asic/simulators",
    "src/asic/tools",
    "migrations",
    "scripts",
    "tests",
)

#: Packages whose existence would mean a later phase started early.
FORBIDDEN_PACKAGES = (
    # Phase 10 adapters live only in src/asic/integrations; a parallel adapter tree would
    # be a second egress path the broker does not control.
    "src/asic/adapters",
    "src/asic/connectors",
    "src/asic/evaluation",  # Phase 11 - harness
    "src/asic/agents",  # Phase 7  - specialised investigation agents
    # Phase 6 lives in knowledge/ and memory/. A parallel retrieval tree would be a second
    # path to content that bypasses the governed one.
    "src/asic/rag",
    "src/asic/retrieval",
    "src/asic/vector",
    "web",
    "ui",
    "terraform",  # Phase 14
    "charts",
)

#: Imports that would mean an unapproved capability arrived with them. LangGraph and
#: OpenTelemetry are absent because ADR-0002 and ADR-0010 approve them for this phase.
FORBIDDEN_IMPORTS = (
    "openai",
    "anthropic",
    "litellm",
    "temporalio",
    "mcp",
    "kubernetes",
    "prometheus_api_client",
    "slack_sdk",
    "jira",
    "redis",
    "kafka",
    "confluent_kafka",
    "nats",
    "elasticsearch",
    "opensearchpy",
    "langsmith",
    "langchain_openai",
    "langchain_anthropic",
    # Phase 6: PostgreSQL + pgvector is the store (ADR-0004); reranking is off unless
    # measured (ADR-0008); embeddings go through asic.knowledge.embedding.
    "pinecone",
    "weaviate",
    "qdrant_client",
    "pymilvus",
    "chromadb",
    "faiss",
    "lancedb",
    "llama_index",
    "sentence_transformers",
    "cohere",
    "voyageai",
    "phoenix",
)

#: Frontend languages are permitted only below the Phase 9 dashboard tree.
FORBIDDEN_EXTENSIONS = {".ts", ".tsx", ".jsx", ".vue", ".svelte", ".tf", ".go", ".java"}

#: Capability prefixes the read-only kernel may register. A write capability in the
#: catalogue would mean a tool exists with no policy gate in front of it.
ALLOWED_CAPABILITY_PREFIXES = ("read.",)

#: Capability prefixes the Phase 8 remediation write catalogue may register. Anything
#: outside this list - in particular, anything that is not a verb naming a *class* of
#: mutation - is not a capability this validator will accept as registered.
ALLOWED_WRITE_CAPABILITY_PREFIXES = ("mutate.", "notify.", "write.")

#: Shapes that would create an arbitrary-execution channel. Checked across the whole source
#: tree, because the guarantee is "no such field exists anywhere", not "not in the models".
FORBIDDEN_EXECUTION_PATTERNS = (
    re.compile(r"\bsubprocess\b"),
    re.compile(r"\bos\.system\b"),
    re.compile(r"\bos\.popen\b"),
    re.compile(r"\bshell\s*=\s*True\b"),
    re.compile(r"^\s*(?:import|from)\s+pty\b", re.M),
)

#: Files exempt from the execution-shape scan, and why. The validator names the forbidden
#: shapes, so it necessarily contains them as data.
EXECUTION_SCAN_EXEMPT = ("scripts/validate_docs.py", "src/asic/domain/safety.py")


class Findings:
    def __init__(self) -> None:
        self.items: list[tuple[str, str]] = []

    def add(self, check: str, message: str) -> None:
        self.items.append((check, message))

    def report(self, check: str) -> list[str]:
        return [m for c, m in self.items if c == check]


def markdown_files() -> list[Path]:
    files = sorted(DOCS.rglob("*.md"))
    root_readme = REPO / "README.md"
    if root_readme.exists():
        files.append(root_readme)
    changelog = REPO / "CHANGELOG.md"
    if changelog.exists():
        files.append(changelog)
    return files


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(REPO)).replace("\\", "/")
    except ValueError:
        return str(path)


# --------------------------------------------------------------------------- 1. links


def check_links(files: list[Path], f: Findings) -> int:
    checked = 0
    for path in files:
        text = path.read_text(encoding="utf-8")
        for match in MD_LINK.finditer(text):
            target = match.group(1).strip()
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            # Strip any anchor; we validate the file, not the heading.
            file_part = target.split("#", 1)[0]
            if not file_part:
                continue
            decoded = urllib.parse.unquote(file_part)
            resolved = (path.parent / decoded).resolve()
            checked += 1
            if not resolved.exists():
                line = text[: match.start()].count("\n") + 1
                f.add("links", f"{rel(path)}:{line} -> broken link: {target}")
    return checked


# ------------------------------------------------------------------------- 2. mermaid


def check_mermaid(files: list[Path], f: Findings) -> int:
    blocks = 0
    for path in files:
        lines = path.read_text(encoding="utf-8").splitlines()
        in_block = False
        start_line = 0
        body: list[str] = []
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not in_block and stripped.startswith("```mermaid"):
                in_block, start_line, body = True, i, []
                continue
            if in_block and stripped.startswith("```"):
                blocks += 1
                validate_mermaid_block(path, start_line, body, f)
                in_block = False
                continue
            if in_block:
                body.append(line)
        if in_block:
            f.add("mermaid", f"{rel(path)}:{start_line} -> unterminated mermaid block")
    return blocks


def validate_mermaid_block(path: Path, start: int, body: list[str], f: Findings) -> None:
    where = f"{rel(path)}:{start}"
    content = [ln for ln in body if ln.strip() and not ln.strip().startswith("%%")]
    if not content:
        f.add("mermaid", f"{where} -> empty mermaid block")
        return

    header = content[0].strip()
    if not any(header.startswith(t) for t in KNOWN_DIAGRAM_TYPES):
        f.add("mermaid", f"{where} -> unknown diagram type: {header[:60]!r}")
        return

    is_flowchart = header.startswith(("flowchart", "graph"))

    # subgraph / end balance (flowcharts only; other types use `end` differently).
    if is_flowchart:
        depth = 0
        for offset, line in enumerate(content[1:], start=1):
            s = line.strip()
            if s.startswith("subgraph "):
                depth += 1
            elif s == "end":
                depth -= 1
                if depth < 0:
                    f.add("mermaid", f"{where}+{offset} -> 'end' without matching 'subgraph'")
                    return
        if depth != 0:
            f.add("mermaid", f"{where} -> {depth} unclosed 'subgraph' block(s)")

    # Quote balance applies to every diagram type: an unclosed label breaks all of them.
    for offset, line in enumerate(content, start=0):
        s = line.strip()
        if s.count('"') % 2 != 0:
            f.add("mermaid", f"{where}+{offset} -> unbalanced quote: {s[:70]!r}")

    # Bracket balance is only meaningful per-line for flowcharts, where brackets delimit
    # node labels. erDiagram uses { and } as cardinality notation ("||--o{"), and
    # stateDiagram uses them to open composite states that span multiple lines, so a
    # per-line check would produce false positives on both.
    if is_flowchart:
        for offset, line in enumerate(content, start=0):
            s = line.strip()
            for open_c, close_c in (("[", "]"), ("(", ")"), ("{", "}")):
                if s.count(open_c) != s.count(close_c):
                    f.add(
                        "mermaid",
                        f"{where}+{offset} -> unbalanced {open_c}{close_c}: {s[:70]!r}",
                    )
                    break
    elif header.startswith("stateDiagram"):
        # Composite states must balance across the whole block.
        opens = sum(ln.count("{") for ln in content)
        closes = sum(ln.count("}") for ln in content)
        if opens != closes:
            f.add(
                "mermaid",
                f"{where} -> unbalanced composite state braces ({opens} open, {closes} close)",
            )

    # A diagram with no relationship is almost certainly a mistake.
    joined = "\n".join(content[1:])
    has_edge = bool(re.search(r"(-->|---|-\.->|==>|->>|-->>|\|\|--|\}o--|\|\|\.\.|: )", joined))
    if not has_edge and not header.startswith(("journey", "gantt", "pie", "mindmap", "timeline")):
        f.add("mermaid", f"{where} -> diagram declares no relationships")


# ----------------------------------------------------------------- 3. requirement trace


def check_requirement_traceability(f: Findings) -> tuple[int, int]:
    if not SRS_MD.exists() or not RTM_MD.exists():
        f.add("traceability", "SRS.md or requirements-traceability.md is missing")
        return (0, 0)

    defined: set[str] = set()
    for line in SRS_MD.read_text(encoding="utf-8").splitlines():
        m = REQ_DEFINITION.match(line.strip())
        if m:
            defined.add(m.group(1))

    rtm_text = RTM_MD.read_text(encoding="utf-8")
    traced = set(REQ_ID.findall(rtm_text))

    for req in sorted(defined - traced):
        f.add("traceability", f"{req} defined in SRS but absent from the traceability matrix")
    for req in sorted(traced - defined):
        f.add(
            "traceability",
            f"{req} appears in the traceability matrix but is not defined in the SRS",
        )

    return (len(defined), len(traced))


# --------------------------------------------------------- 4. spec responsibility cover


def spec_section_4_responsibilities() -> list[str]:
    """Extract the agent/node bullet list from master specification section 4."""
    if not SPEC_MD.exists():
        return []
    lines = SPEC_MD.read_text(encoding="utf-8").splitlines()
    names: list[str] = []
    in_section = False
    for line in lines:
        if line.startswith("## 4."):
            in_section = True
            continue
        if in_section and line.startswith("## "):
            break
        if in_section and line.strip().startswith("- "):
            names.append(line.strip()[2:].strip())
    return names


def check_responsibility_coverage(f: Findings) -> int:
    names = spec_section_4_responsibilities()
    if not names:
        f.add("coverage", "could not extract section 4 responsibilities from the specification")
        return 0
    if not TOPOLOGY_MD.exists():
        f.add("coverage", "agent-topology.md is missing")
        return 0
    topology = TOPOLOGY_MD.read_text(encoding="utf-8")
    for name in names:
        if name not in topology:
            f.add(
                "coverage",
                f"section 4 responsibility {name!r} has no disposition in agent-topology.md",
            )
    return len(names)


# ----------------------------------------------------------------- 5. phase boundary


def check_phase_boundary(f: Findings) -> int:
    """Assert no later phase has started early.

    Through Phase 10, the repository holds governed knowledge, bounded investigation,
    safety-gated remediation, authenticated API/dashboard surfaces and native external
    integrations behind the broker. The evaluation harness remains out of scope.
    """
    scanned = 0

    for package in FORBIDDEN_PACKAGES:
        if (REPO / package).exists():
            f.add(
                "phase",
                f"{package}/ exists, but that belongs to a later, unapproved phase",
            )

    for path in REPO.rglob("*"):
        if not path.is_file():
            continue
        parts = path.relative_to(REPO).parts
        if parts and parts[0] in {".git", ".claude", ".venv", "node_modules", "__pycache__"}:
            continue
        if any(part in {"__pycache__", "node_modules", ".next"} for part in parts):
            continue
        scanned += 1

        if path.suffix.lower() in FORBIDDEN_EXTENSIONS and parts[0] != "frontend":
            f.add("phase", f"{rel(path)}: {path.suffix} files belong to a later phase")

        if path.suffix != ".py":
            continue
        relative = rel(path)
        if parts[0] == "src":
            if not any(relative.startswith(root) for root in ALLOWED_SOURCE_ROOTS):
                f.add("phase", f"{relative} is outside the source trees this phase may touch")
            text = path.read_text(encoding="utf-8", errors="replace")
            for module in FORBIDDEN_IMPORTS:
                if re.search(rf"^\s*(?:import|from)\s+{re.escape(module)}\b", text, re.M):
                    f.add("phase", f"{relative} imports {module!r}, which belongs to a later phase")

        if relative in EXECUTION_SCAN_EXEMPT:
            continue
        if parts[0] in {"src", "migrations"}:
            text = path.read_text(encoding="utf-8", errors="replace")
            for pattern in FORBIDDEN_EXECUTION_PATTERNS:
                if pattern.search(text):
                    f.add(
                        "phase",
                        f"{relative} matches {pattern.pattern!r}: the system executes only "
                        "registered, typed operations and has no arbitrary-execution path",
                    )

    _check_capability_catalogue(f)
    return scanned


def _check_capability_catalogue(f: Findings) -> None:
    """Assert the registered catalogue is entirely read-only.

    Imported rather than parsed, so this checks what the code will actually load rather
    than what a regular expression believes it says.
    """
    sys.path.insert(0, str(REPO / "src"))
    try:
        from asic.tools.catalogue import READ_ONLY_CATALOGUE
    except Exception as exc:  # the validator reports problems, it does not crash on them
        f.add("phase", f"the capability catalogue could not be loaded: {exc}")
        return
    finally:
        sys.path.pop(0)

    for descriptor in READ_ONLY_CATALOGUE:
        if descriptor.risk_tier.value != "ro":
            f.add(
                "phase",
                f"tool {descriptor.name} is risk tier {descriptor.risk_tier.value}; this "
                "phase registers read-only capabilities only, because there is no policy "
                "gate to authorize anything else",
            )
        if not any(
            descriptor.capability.startswith(prefix) for prefix in ALLOWED_CAPABILITY_PREFIXES
        ):
            f.add(
                "phase",
                f"tool {descriptor.name} declares capability {descriptor.capability!r}, "
                f"which is not one of {list(ALLOWED_CAPABILITY_PREFIXES)}",
            )
        if descriptor.rollback_tool_name is not None:
            f.add(
                "phase",
                f"tool {descriptor.name} declares a rollback, which only a write tool needs",
            )

    _check_remediation_capability_catalogue(f)
    _check_integration_capability_catalogue(f)


def _check_integration_capability_catalogue(f: Findings) -> None:
    """Assert the Phase 10 external-record catalogue contains only external records.

    Every descriptor must be an ``external_record`` at tier ``r1``, name a ``notify.`` or
    ``write.`` capability, declare no rollback (a message cannot be un-sent) and no retry.
    """
    sys.path.insert(0, str(REPO / "src"))
    try:
        from asic.tools.integration_catalogue import INTEGRATION_CATALOGUE
    except Exception as exc:  # the validator reports problems, it does not crash on them
        f.add("phase", f"the integration capability catalogue could not be loaded: {exc}")
        return
    finally:
        sys.path.pop(0)

    for descriptor in INTEGRATION_CATALOGUE:
        if descriptor.effect_class.value != "external_record" or descriptor.risk_tier.value != "r1":
            f.add("phase", f"tool {descriptor.name} is not an r1 external record")
        if not descriptor.capability.startswith(("notify.", "write.")):
            f.add("phase", f"tool {descriptor.name} is not a notify./write. capability")
        if descriptor.rollback_tool_name is not None or descriptor.max_attempts != 1:
            f.add("phase", f"tool {descriptor.name} declares a rollback or retries")


def _check_remediation_capability_catalogue(f: Findings) -> None:
    """Assert the Phase 8 write catalogue is exactly what a write catalogue must be.

    The mirror image of the read-only check above, and the write-side layer ADR-0017
    promised would move deliberately: every descriptor is R1 or R2 (never RO, and R3 is
    already unreachable - :class:`ToolDescriptor` refuses it at construction, SI-5), every
    capability names a mutation class, and every one declares a rollback - a write tool
    with no way back is not a tool this catalogue may register at all.
    """
    sys.path.insert(0, str(REPO / "src"))
    try:
        from asic.tools.remediation_catalogue import WRITE_CATALOGUE
    except Exception as exc:  # the validator reports problems, it does not crash on them
        f.add("phase", f"the remediation capability catalogue could not be loaded: {exc}")
        return
    finally:
        sys.path.pop(0)

    for descriptor in WRITE_CATALOGUE:
        if descriptor.risk_tier.value not in {"r1", "r2"}:
            f.add(
                "phase",
                f"tool {descriptor.name} is risk tier {descriptor.risk_tier.value}; the "
                "write catalogue registers r1/r2 only - ro belongs in the read catalogue "
                "and r3 is never expressible (SI-5)",
            )
        if not any(
            descriptor.capability.startswith(prefix) for prefix in ALLOWED_WRITE_CAPABILITY_PREFIXES
        ):
            f.add(
                "phase",
                f"tool {descriptor.name} declares capability {descriptor.capability!r}, "
                f"which is not one of {list(ALLOWED_WRITE_CAPABILITY_PREFIXES)}",
            )
        if descriptor.rollback_tool_name is None:
            f.add(
                "phase",
                f"tool {descriptor.name} is a write tool with no declared rollback; the "
                "way back must be declared before the action can ever be proposed",
            )


# ----------------------------------------------------------------- 6. unmeasured claims


def check_unmeasured_claims(files: list[Path], f: Findings) -> None:
    for path in files:
        if path.resolve() == SPEC_MD.resolve():
            continue  # the specification is authoritative and quoted verbatim
        text = path.read_text(encoding="utf-8")
        for match in UNMEASURED_CLAIM.finditer(text):
            line = text[: match.start()].count("\n") + 1
            f.add(
                "claims",
                f"{rel(path)}:{line} -> possible invented metric: {match.group(0)!r}",
            )


def check_safety_invariant_ids(files: list[Path], f: Findings) -> int:
    """Require every safety-invariant table identifier to be globally unique."""
    seen: dict[str, Path] = {}
    count = 0
    for path in files:
        text = path.read_text(encoding="utf-8")
        for match in SAFETY_INVARIANT_DEFINITION.finditer(text):
            count += 1
            invariant = match.group(1)
            if invariant in seen:
                f.add(
                    "invariants",
                    f"{rel(path)} duplicates {invariant} first defined in {rel(seen[invariant])}",
                )
            else:
                seen[invariant] = path
    return count


# ------------------------------------------------------------------------------- main


def main() -> int:
    if not DOCS.exists():
        print("ERROR: docs/ not found; run from the repository.", file=sys.stderr)
        return 1

    f = Findings()
    files = markdown_files()

    links = check_links(files, f)
    blocks = check_mermaid(files, f)
    defined, traced = check_requirement_traceability(f)
    responsibilities = check_responsibility_coverage(f)
    scanned = check_phase_boundary(f)
    check_unmeasured_claims(files, f)
    invariants = check_safety_invariant_ids(files, f)

    print(f"markdown files    : {len(files)}")
    print(f"internal links    : {links} checked")
    print(f"mermaid diagrams  : {blocks} checked")
    print(f"requirement IDs   : {defined} defined in SRS, {traced} referenced in matrix")
    print(f"spec section 4    : {responsibilities} responsibilities checked for disposition")
    print(f"repository files  : {scanned} scanned against the Phase 10 boundary")
    print(f"safety invariants : {invariants} unique definitions checked")
    print()

    order = [
        ("links", "Internal links"),
        ("mermaid", "Mermaid structure"),
        ("traceability", "Requirement traceability"),
        ("coverage", "Specification coverage"),
        ("phase", "Phase 10 scope boundary"),
        ("claims", "No unmeasured claims"),
        ("invariants", "Unique safety invariant IDs"),
    ]

    total = 0
    for key, label in order:
        found = f.report(key)
        total += len(found)
        status = "OK" if not found else f"{len(found)} FINDING(S)"
        print(f"  [{status:>14}] {label}")
        for message in found:
            print(f"        - {message}")

    print()
    if total:
        print(f"RESULT: {total} finding(s). Documentation validation FAILED.")
        return 1
    print("RESULT: CLEAN - links resolve, diagrams are structurally valid,")
    print("        every requirement is traced, no specification responsibility was")
    print("        dropped, and no later-phase code exists.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
