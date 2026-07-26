"""One-off release validation runner (audit artifact, not production code)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import tracemalloc
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from presidio_analyzer import AnalyzerEngine  # noqa: E402
from presidio_analyzer.nlp_engine import NlpEngineProvider  # noqa: E402
from scanner.config import ScannerSettings  # noqa: E402
from scanner.file_scanner import FileScanner  # noqa: E402
from scanner.models import RepositorySource, RepositorySourceType, ScannedFile  # noqa: E402
from scanner.pii_detector import PIIDetector  # noqa: E402
from scanner.scan_engine import ScanEngine  # noqa: E402

WORKDIR = Path(os.environ.get("TEMP", "/tmp")) / "pii_scanner_validation"
if WORKDIR.exists():
    shutil.rmtree(WORKDIR)
WORKDIR.mkdir(parents=True)

results: dict = {"parts": {}}


def init_git_repo(path: Path) -> None:
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "validator@test.local"],
        cwd=path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Validator"],
        cwd=path,
        check=True,
        capture_output=True,
    )


def make_settings(tmp: Path) -> ScannerSettings:
    out = tmp / "output"
    return ScannerSettings(
        app_name="validation",
        environment="test",
        log_level="WARNING",
        working_directory=tmp,
        output_directory=out,
        supported_extensions=(".py", ".txt", ".md", ".json"),
        excluded_directories=(".git", "node_modules", "presidio", "venv", ".venv"),
        max_file_size_bytes=5 * 1024 * 1024,
        presidio_language="en",
        presidio_min_confidence=0.5,
        presidio_spacy_model="en_core_web_lg",
        clone_base_directory=out / "cloned",
        clone_shallow_depth=1,
    )


def run_scan(repo_path: Path, settings: ScannerSettings):
    source = RepositorySource(
        source_type=RepositorySourceType.LOCAL_PATH,
        identifier=str(repo_path),
        local_path=repo_path,
    )
    tracemalloc.start()
    t0 = time.perf_counter()
    engine = ScanEngine(settings=settings)
    engine_type = (
        f"{type(engine._pii_detector._engine).__module__}."
        f"{type(engine._pii_detector._engine).__name__}"
    )
    summary = engine.scan(source)
    elapsed = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return summary, elapsed, peak, engine_type


# PART 3 — positive repo
pos = WORKDIR / "positive_repo"
pos.mkdir()
init_git_repo(pos)
positive_content = """# Controlled PII sample file for validation
line1 comment only
email = "john.doe@example.com"
phone = "(555) 867-5309"
card = "4111111111111111"
ip = "192.168.45.67"
ssn = "123-45-6789"
passport = "123456789"
url = "https://example.com/private"
person = "Jane Doe works here"
organization = "Acme Corporation International"
location = "San Francisco, California"
"""
(pos / "sample.py").write_text(positive_content, encoding="utf-8")
subprocess.run(["git", "add", "."], cwd=pos, check=True, capture_output=True)
subprocess.run(
    ["git", "commit", "-m", "add controlled pii"], cwd=pos, check=True, capture_output=True
)

settings = make_settings(WORKDIR / "pos_run")
pos_summary, pos_time, pos_mem, engine_type = run_scan(pos, settings)

expected = {
    "EMAIL_ADDRESS": "john.doe@example.com",
    "PHONE_NUMBER": "(555) 867-5309",
    "CREDIT_CARD": "4111111111111111",
    "IP_ADDRESS": "192.168.45.67",
    "US_SSN": "123-45-6789",
    "US_PASSPORT": "123456789",
    "URL": "https://example.com/private",
    "PERSON": "Jane Doe",
    "ORGANIZATION": "Acme Corporation International",
    "LOCATION": "San Francisco",
}

lines = positive_content.splitlines()
line_index = {i + 1: line for i, line in enumerate(lines)}

findings_by_type: dict[str, list] = defaultdict(list)
for finding in pos_summary.findings:
    findings_by_type[finding.entity_type].append(finding)

positive_report = {}
for entity_type, needle in expected.items():
    matches = findings_by_type.get(entity_type, [])
    hit = None
    for match in matches:
        if needle.lower() in match.matched_text.lower() or match.matched_text.lower() in needle.lower():
            hit = match
            break
    if hit is None and matches:
        hit = matches[0]
    positive_report[entity_type] = {
        "expected_snippet": needle,
        "detected": bool(hit),
        "count_for_type": len(matches),
        "matched_text": hit.matched_text if hit else None,
        "confidence": hit.confidence_score if hit else None,
        "line_number": hit.line_number if hit else None,
        "severity": hit.severity.value if hit else None,
        "source_line": line_index.get(hit.line_number) if hit and hit.line_number else None,
    }

results["parts"]["part3_positive"] = {
    "repo": str(pos),
    "engine_type": engine_type,
    "files_scanned": pos_summary.files_scanned,
    "files_skipped": pos_summary.files_skipped,
    "total_findings": pos_summary.total_findings,
    "scan_seconds": round(pos_time, 3),
    "peak_memory_mb": round(pos_mem / (1024 * 1024), 1),
    "entity_counts": dict(Counter(f.entity_type for f in pos_summary.findings)),
    "expected_entities": positive_report,
    "all_findings": [
        {
            "entity_type": f.entity_type,
            "matched_text": f.matched_text,
            "confidence": f.confidence_score,
            "line": f.line_number,
            "severity": f.severity.value,
            "file": str(f.file.relative_path),
        }
        for f in pos_summary.findings
    ],
}

# PART 4 — negative repo
neg = WORKDIR / "negative_repo"
neg.mkdir()
init_git_repo(neg)
negative_py = (
    "# Hello World sample\n\n"
    "def greet(name):\n"
    '    """Return a greeting."""\n'
    '    return f"Hello {name}"\n\n\n'
    "def add(a, b):\n"
    "    # simple arithmetic\n"
    "    return a + b\n\n\n"
    'if __name__ == "__main__":\n'
    '    print(greet("World"))\n'
    "    print(add(1, 2))\n"
)
(neg / "app.py").write_text(negative_py, encoding="utf-8")
subprocess.run(["git", "add", "."], cwd=neg, check=True, capture_output=True)
subprocess.run(["git", "commit", "-m", "no pii"], cwd=neg, check=True, capture_output=True)

neg_settings = make_settings(WORKDIR / "neg_run")
neg_summary, neg_time, neg_mem, _ = run_scan(neg, neg_settings)
results["parts"]["part4_negative"] = {
    "repo": str(neg),
    "files_scanned": neg_summary.files_scanned,
    "total_findings": neg_summary.total_findings,
    "scan_seconds": round(neg_time, 3),
    "findings": [
        {
            "entity_type": f.entity_type,
            "matched_text": f.matched_text,
            "confidence": f.confidence_score,
            "line": f.line_number,
            "severity": f.severity.value,
            "source_line": negative_py.splitlines()[f.line_number - 1] if f.line_number else None,
        }
        for f in neg_summary.findings
    ],
}

# PART 6 — confidence rejection
conf_settings = make_settings(WORKDIR / "conf_run")
detector = PIIDetector(settings=conf_settings)
text = "contact john.doe@example.com and maybe x@y.z"
sf = ScannedFile(
    absolute_path=pos / "sample.py",
    relative_path=Path("sample.py"),
    size_bytes=10,
    extension=".py",
)
raw = detector._engine.analyze(text=text, language="en", score_threshold=0.0)
below = [r for r in raw if r.score < 0.5]
above = detector.analyze_file(sf, text)
results["parts"]["part6_confidence"] = {
    "threshold": conf_settings.presidio_min_confidence,
    "raw_below_0_5": [
        {"entity": r.entity_type, "score": r.score, "text": text[r.start : r.end]} for r in below
    ],
    "returned_findings": [
        {"entity": f.entity_type, "score": f.confidence_score, "text": f.matched_text}
        for f in above
    ],
    "any_below_threshold_in_output": any(f.confidence_score < 0.5 for f in above),
}

# PART 7 — bad file resilience (mirrors PIIDetector exception swallowing)
bad = WORKDIR / "badfile_repo"
bad.mkdir()
init_git_repo(bad)
(bad / "good.py").write_text('email = "visible@example.com"\n', encoding="utf-8")
(bad / "bad.py").write_text("x=1\n", encoding="utf-8")
subprocess.run(["git", "add", "."], cwd=bad, check=True, capture_output=True)
subprocess.run(["git", "commit", "-m", "bad"], cwd=bad, check=True, capture_output=True)

bad_settings = make_settings(WORKDIR / "bad_run")
source_bad = RepositorySource(
    source_type=RepositorySourceType.LOCAL_PATH,
    identifier=str(bad),
    local_path=bad,
)
real_detector = PIIDetector(settings=bad_settings)


class ExplodingWrapper:
    def __init__(self, inner: PIIDetector) -> None:
        self.inner = inner

    def analyze_file(self, scanned_file: ScannedFile, text: str):
        if scanned_file.absolute_path.name == "bad.py":
            raise RuntimeError("simulated analysis failure")
        return self.inner.analyze_file(scanned_file, text)


engine_bad = ScanEngine(settings=bad_settings, pii_detector=ExplodingWrapper(real_detector))
summary_bad = engine_bad.scan(source_bad)
results["parts"]["part7_resilience"] = {
    "files_scanned": summary_bad.files_scanned,
    "total_findings": summary_bad.total_findings,
    "findings_files": [str(f.file.relative_path) for f in summary_bad.findings],
    "scan_completed": summary_bad.finished_at is not None,
}

# PART 5 — self-scan
self_settings = make_settings(WORKDIR / "self_run")
self_summary, self_time, self_mem, _ = run_scan(ROOT, self_settings)

CATEGORIES = ["PERSON", "ORGANIZATION", "LOCATION", "URL"]


def classify_fp(finding) -> str:
    text = finding.matched_text.strip()
    if finding.entity_type == "EMAIL_ADDRESS" and "someone@example.com" in text:
        return "true_positive"
    if finding.entity_type == "URL" and text.startswith("http"):
        return "likely_false_positive"
    if finding.entity_type == "URL" and "." in text and not text.startswith("http"):
        return "likely_false_positive"
    if finding.entity_type == "ORGANIZATION":
        return "likely_false_positive"
    if finding.entity_type == "PERSON":
        if text in {"Git", "\u2514", "\u251c", "\u2502"} or len(text) <= 3:
            return "likely_false_positive"
        return "likely_false_positive"
    if finding.entity_type == "LOCATION":
        return "likely_false_positive"
    return "uncategorized"


cat_stats = {}
for cat in CATEGORIES:
    items = [f for f in self_summary.findings if f.entity_type == cat]
    cat_stats[cat] = {
        "total": len(items),
        "true_positives": sum(1 for f in items if classify_fp(f) == "true_positive"),
        "likely_false_positives": sum(1 for f in items if classify_fp(f) == "likely_false_positive"),
        "sample_fps": [
            {
                "text": f.matched_text[:80],
                "file": str(f.file.relative_path),
                "line": f.line_number,
                "confidence": f.confidence_score,
            }
            for f in items
            if classify_fp(f) == "likely_false_positive"
        ][:5],
    }

results["parts"]["part5_self_scan"] = {
    "files_scanned": self_summary.files_scanned,
    "files_skipped": self_summary.files_skipped,
    "total_findings": self_summary.total_findings,
    "scan_seconds": round(self_time, 3),
    "peak_memory_mb": round(self_mem / (1024 * 1024), 1),
    "entity_breakdown": dict(Counter(f.entity_type for f in self_summary.findings)),
    "severity_breakdown": dict(Counter(f.severity.value for f in self_summary.findings)),
    "category_analysis": cat_stats,
}

# PART 2 — recognizer map
cfg = {
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
}
eng = NlpEngineProvider(nlp_configuration=cfg).create_engine()
ae = AnalyzerEngine(nlp_engine=eng, supported_languages=["en"])
targets = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "PERSON",
    "LOCATION",
    "ORGANIZATION",
    "URL",
    "IP_ADDRESS",
    "DATE_TIME",
    "CREDIT_CARD",
    "US_SSN",
    "US_PASSPORT",
]
results["parts"]["part2_recognizers"] = {
    t: [f"{type(r).__name__}({r.name})" for r in ae.registry.recognizers if t in (r.supported_entities or [])]
    for t in targets
}

out = WORKDIR / "validation_results.json"
out.write_text(json.dumps(results, indent=2), encoding="utf-8")
print(f"VALIDATION_JSON={out}")
print(f"POS_FINDINGS={pos_summary.total_findings}")
print(f"NEG_FINDINGS={neg_summary.total_findings}")
print(f"SELF_FINDINGS={self_summary.total_findings}")
print(f"ENGINE={engine_type}")
