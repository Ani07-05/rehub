"""Heuristic review of PLC source text. Not a vulnerability scanner: it flags patterns a person
should look at and shows what changed since an approved version."""

import difflib
import re
from dataclasses import dataclass, field

Severity = str
ORDER = {"high": 0, "medium": 1, "low": 2}
_BLOCK_COMMENT = re.compile(r"\(\*.*?\*\)", re.DOTALL)
_CDATA = re.compile(r"<!\[CDATA\[(.*?)\]\]>", re.DOTALL)
_NUMBER = re.compile(r"(?<![\w.])-?\d+(?:\.\d+)?(?![\w.])")


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    title: str
    pattern: re.Pattern[str]
    why: str
    check: str


def _rx(expr: str) -> re.Pattern[str]:
    return re.compile(expr, re.IGNORECASE)


RULES = [
    Rule(
        "hardcoded-secret",
        "high",
        "A password or key is written into the program",
        _rx(
            r"\b\w*(pass(word|wd)?|pwd|secret|token|api_?key|credential)\w*"
            r"\s*(?::\s*\w+(?:\[[^\]]*\])?\s*)?:?=\s*['\"][^'\"]+['\"]"
        ),
        "Anyone who can read or copy the program can read this value.",
        "Remove it from the code, change the real password, and keep secrets in a protected place.",
    ),
    Rule(
        "cpu-stop",
        "high",
        "The program can stop the controller",
        _rx(r"\b(STP|PLC_STOP|STOP_CPU|CPU_STOP|SFC46)\b\s*\("),
        "If anything triggers this unexpectedly, the whole process halts.",
        "Confirm what condition triggers it and who is allowed to cause that condition.",
    ),
    Rule(
        "force-override",
        "high",
        "A force, override or bypass is switched on",
        _rx(r"\b\w*(force|override|bypass)\w*\s*:=\s*(TRUE|1)\b"),
        "Forcing or bypassing can hide a fault or skip a protection.",
        "Check that this is intended, temporary, and approved.",
    ),
    Rule(
        "interlock-off",
        "medium",
        "A safety-related signal is set to off",
        _rx(r"\b\w*(interlock|safety|estop|e_stop|permissive)\w*\s*:=\s*(FALSE|0)\b"),
        "The name suggests a protection. It may be start-up logic, or a protection turned off.",
        "Read the surrounding code and confirm the protection is still active when it should be.",
    ),
    Rule(
        "network-call",
        "medium",
        "The program opens network connections itself",
        _rx(r"\b(TCON|TSEND|TRCV|TUSEND|TURCV|MB_CLIENT|MB_SERVER|PUT|GET)\b\s*\("),
        "The controller talks to something over the network on its own.",
        "Check that the destination and the data it sends are expected.",
    ),
    Rule(
        "fixed-address",
        "medium",
        "A network address is written into the program",
        _rx(r"(?<![\d.])(?!0\.0\.0\.0)(?!255\.)\d{1,3}(?:\.\d{1,3}){3}(?![\d.])"),
        "It shows who the controller is meant to talk to, and breaks if the network changes.",
        "Confirm this device should be talked to.",
    ),
    Rule(
        "endless-loop",
        "medium",
        "A loop that never ends by itself",
        _rx(r"\bWHILE\s+(TRUE|1)\b"),
        "A loop with no exit can freeze the scan cycle and fault the controller.",
        "Make sure it always exits, or replace it with logic that runs once per cycle.",
    ),
    Rule(
        "test-mode-on",
        "medium",
        "A test or simulation switch is on",
        _rx(r"\b\w*(debug|test_?mode|simulat\w*)\w*\s*:=\s*(TRUE|1)\b"),
        "Test switches left on can change how the real process behaves.",
        "Turn it off before this goes on a live controller.",
    ),
]


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: Severity
    title: str
    line: int
    code: str
    why: str
    check: str

    def key(self) -> tuple[str, str]:
        return (self.rule, " ".join(self.code.split()).lower())


@dataclass
class ValueChange:
    line: int
    before: str
    after: str


@dataclass
class Comparison:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    value_changes: list[ValueChange] = field(default_factory=list)
    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)

    @property
    def unchanged(self) -> bool:
        return not (self.added or self.removed)


def to_source(text: str) -> str:
    """Return program text. For Rockwell L5X exports, pull the logic out of the XML."""
    if "<RSLogix5000Content" in text:
        return "\n".join(m.strip() for m in _CDATA.findall(text) if m.strip())
    return text


def code_lines(text: str) -> list[tuple[int, str]]:
    """Source lines with comments removed, keeping original line numbers."""
    source = to_source(text)
    blanked = _BLOCK_COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), source)
    out = []
    for number, raw in enumerate(blanked.splitlines(), start=1):
        code = raw.split("//", 1)[0].rstrip()
        if code.strip():
            out.append((number, code))
    return out


def analyze(text: str) -> list[Finding]:
    found = []
    for number, code in code_lines(text):
        hits = [rule for rule in RULES if rule.pattern.search(code)]
        if any(rule.id == "network-call" for rule in hits):
            # the call finding already shows the address on this line
            hits = [rule for rule in hits if rule.id != "fixed-address"]
        for rule in hits:
            found.append(
                Finding(
                    rule.id,
                    rule.severity,
                    rule.title,
                    number,
                    code.strip(),
                    rule.why,
                    rule.check,
                )
            )
    return sorted(found, key=lambda f: (ORDER[f.severity], f.line, f.rule))


def _numbers_only_differ(a: str, b: str) -> bool:
    return a != b and _NUMBER.sub("#", a) == _NUMBER.sub("#", b)


def compare(approved: str, new: str) -> Comparison:
    old_lines = code_lines(approved)
    new_lines = code_lines(new)
    old_text = [" ".join(c.split()) for _, c in old_lines]
    new_text = [" ".join(c.split()) for _, c in new_lines]
    result = Comparison()
    matcher = difflib.SequenceMatcher(a=old_text, b=new_text, autojunk=False)
    for tag, a0, a1, b0, b1 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if tag == "replace" and (a1 - a0) == (b1 - b0):
            for offset in range(a1 - a0):
                before, after = old_text[a0 + offset], new_text[b0 + offset]
                if _numbers_only_differ(before, after):
                    result.value_changes.append(
                        ValueChange(new_lines[b0 + offset][0], before, after)
                    )
                else:
                    result.removed.append(before)
                    result.added.append(after)
            continue
        result.removed.extend(old_text[a0:a1])
        result.added.extend(new_text[b0:b1])
    old_keys = {f.key() for f in analyze(approved)}
    new_found = analyze(new)
    new_keys = {f.key() for f in new_found}
    result.new_findings = [f for f in new_found if f.key() not in old_keys]
    result.resolved_findings = [f for f in analyze(approved) if f.key() not in new_keys]
    return result
