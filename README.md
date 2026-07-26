# GitLab PII Scanner

Identify PII (Personally Identifiable Information) at the code level in a
GitLab repository, using [Microsoft Presidio](https://github.com/microsoft/presidio)
as the detection engine.

> **Status**
>
> | Milestone | State |
> |-----------|--------|
> | **Task 1** — PII identification (Microsoft Presidio) | **Completed** |
> | **Task 2, Phase 1** — Deterministic risk engine + JSON reporting | **Completed** |
> | **Task 2, Phase 2** — AI Assistant (summaries from JSON only) | **Completed** |
> | **Task 2, Phase 3** — Azure DevOps pipeline integration | Not started |
>
> Task 1 delivers `RepositoryManager`, `FileScanner`, `PIIDetector`, and
> `ScanEngine`. Task 2, Phase 1 adds `RiskEngine` and `ReportGenerator`
> (versioned, redacted JSON). Task 2, Phase 2 adds `AIAssistant`, which
> consumes that JSON and writes a Markdown summary without changing
> findings, risk scores, or pipeline status. Azure DevOps integration
> follows in Phase 3.

---

## Project layout

```
gitlab-pii-scanner/
│
├── presidio/                  # Official Microsoft Presidio repo (reference only — DO NOT MODIFY)
│
├── main.py                    # CLI entry point
├── requirements.txt
├── README.md
├── .gitignore
├── tests/
│   ├── __init__.py
│   ├── test_main.py                     # CLI / pipeline integration tests
│   ├── test_repository_manager.py       # Task 1
│   ├── test_file_scanner.py             # Task 1
│   ├── test_pii_detector.py             # Task 1
│   ├── test_scan_engine.py              # Task 1
│   ├── test_risk_engine.py              # Task 2, Phase 1
│   ├── test_report_generator.py         # Task 2, Phase 1
│   ├── test_ai_assistant.py             # Task 2, Phase 2
│   ├── test_ai_providers.py             # Task 2, Phase 2
│   ├── test_ai_prompt_builder.py        # Task 2, Phase 2
│   ├── test_ai_markdown_generator.py    # Task 2, Phase 2
│   └── test_ai_recommendations.py       # Task 2, Phase 2
└── scanner/                   # Application package
    ├── __init__.py
    ├── config.py
    ├── logger.py
    ├── models.py
    ├── utils.py
    ├── repository_manager.py
    ├── file_scanner.py
    ├── pii_detector.py
    ├── scan_engine.py
    ├── risk_engine.py
    ├── report_generator.py
    └── ai/                      # Task 2, Phase 2 — AI Assistant layer
        ├── __init__.py
        ├── ai_assistant.py
        ├── providers.py
        ├── prompt_builder.py
        ├── markdown_generator.py
        └── recommendations.py
```

The `presidio/` folder at the repository root is the official upstream
repository, kept purely as a reference/dependency. It is never imported
by path and never modified — Presidio is consumed as an installed
package (`presidio-analyzer`), imported only from `scanner/pii_detector.py`.

## Requirements

- Python 3.12+
- pip

## Setup

```bash
cd gitlab-pii-scanner
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt

# Download the spaCy model Presidio uses by default (override with the
# PRESIDIO_SPACY_MODEL env var to use a different one, e.g. the
# smaller/faster en_core_web_sm):
python -m spacy download en_core_web_lg
```

## Configuration

Configuration is environment-variable driven (see `scanner/config.py`),
with sensible defaults for local development. To override any value,
either export environment variables or create a `.env` file in the
repository root (loaded automatically from the current working directory
if `python-dotenv` is installed):

| Variable                     | Default              | Description                                   |
|-------------------------------|-----------------------|------------------------------------------------|
| `SCANNER_APP_NAME`            | `gitlab-pii-scanner`  | Application name used in logs                  |
| `SCANNER_ENVIRONMENT`         | `local`               | Environment label (`local`, `ci`, `production`)|
| `SCANNER_LOG_LEVEL`           | `INFO`                | `DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL`     |
| `SCANNER_WORKING_DIR`         | current directory     | Base working directory                         |
| `SCANNER_OUTPUT_DIR`          | `<working_dir>/output`| Where logs/reports are written                 |
| `SCANNER_MAX_FILE_SIZE_BYTES` | `5242880` (5 MB)      | Skip files larger than this during scanning    |
| `PRESIDIO_LANGUAGE`           | `en`                  | Language passed to Presidio's analyzer         |
| `PRESIDIO_MIN_CONFIDENCE`     | `0.5`                 | Minimum confidence score to keep a finding      |
| `PRESIDIO_SPACY_MODEL`        | `en_core_web_lg`      | spaCy model Presidio's NLP engine loads         |
| `SCANNER_CLONE_BASE_DIR`      | `<output_dir>/cloned_repositories` | Where GitLab repositories are cloned into |
| `SCANNER_CLONE_SHALLOW_DEPTH` | `1`                   | Git clone depth (`0` = full clone, no `--depth`)|
| `RISK_WARNING_THRESHOLD`      | `20`                  | Weighted risk score at/above which status is `WARNING` |
| `RISK_FAIL_THRESHOLD`         | `50`                  | Weighted risk score at/above which status is `FAIL` (any CRITICAL finding also forces `FAIL`) |
| `REPORT_OUTPUT_DIR`           | `<output_dir>/reports` | Where JSON reports (`report_<timestamp>.json`, `latest.json`) are written |
| `REPORT_REDACTION_ENABLED`    | `true`                | Mask matched PII values in the JSON report (recommended: always `true` if the report may be published, e.g. as a pipeline artifact) |
| `AI_ENABLED`                  | `true`                | Enable the AI Assistant layer (Task 2, Phase 2). When `false`, or when AI fails for any reason, a deterministic fallback summary is written instead |
| `AI_PROVIDER`                 | `null`                | `null` (deterministic fallback, no network calls), `openai`, or `azure_openai` |
| `AI_API_KEY`                  | *(empty)*             | API key for the selected provider (`openai`/`azure_openai`) |
| `AI_MODEL`                    | `gpt-4o-mini`         | Chat completion model / Azure deployment name |
| `AI_TEMPERATURE`              | `0.2`                 | Sampling temperature (`0.0`-`2.0`) |
| `AI_TIMEOUT_SECONDS`          | `30`                  | Per-request timeout for the AI provider |
| `AI_AZURE_ENDPOINT`           | *(empty)*             | Azure OpenAI resource endpoint (required when `AI_PROVIDER=azure_openai`) |
| `AI_AZURE_API_VERSION`        | `2024-08-01-preview`  | Azure OpenAI API version |
| `AI_SUMMARY_FILENAME`         | `ai-summary.md`       | Filename for the AI-generated Markdown summary, written under `output_directory` |

## Running

Running the CLI obtains a real repository via `RepositoryManager`,
scans it with `ScanEngine` (`FileScanner` + `PIIDetector`), then:

1. `RiskEngine` deterministically scores the scan's severity counts
   into a `risk_score` and a `PASS`/`WARNING`/`FAIL` `pipeline_status`
   (any single `CRITICAL` finding forces `FAIL`, regardless of score).
2. `ReportGenerator` writes a versioned JSON report to
   `report_output_directory` (`report_<timestamp>.json` plus a
   `latest.json`), with every matched PII value **redacted by
   default** (e.g. `jo***@example.com`, `************1111`) so the
   report is safe to store or publish as a pipeline artifact.
3. `AIAssistant` (Task 2, Phase 2) consumes that JSON report and
   writes a developer/management-friendly Markdown summary to
   `<output_dir>/ai-summary.md` (see **AI Assistant (Task 2, Phase
   2)** below). This never overwrites the JSON report, and an AI
   failure of any kind never aborts the scan.

The console/log summary (counts by severity, then each finding) is
still printed as before, followed by the pipeline status and the
report's file path.

**Note:** the CLI's process exit code is unchanged by this phase — a
successful scan still exits `0` even if `pipeline_status` is `FAIL`,
to preserve existing CLI behavior. The Azure DevOps integration (Task
2, Phase 3) is expected to gate the build by reading
`summary.pipeline_status` from the JSON report, not the process exit
code.

Validate and scan a local Git repository:

```bash
python main.py local --path "D:\some\project"
```

Clone and scan a GitLab repository (default branch):

```bash
python main.py gitlab --url https://gitlab.com/group/project.git
```

Clone a specific branch:

```bash
python main.py gitlab --url https://gitlab.com/group/project.git --branch develop
```

Both commands print the resolved repository path and scan summary on
success, or a specific, meaningful error (see **Error handling**
below) with a distinct process exit code.

## AI Assistant (Task 2, Phase 2)

The AI Assistant is the final layer of the pipeline:

```
RepositoryManager -> ScanEngine -> RiskEngine -> ReportGenerator -> AIAssistant
```

It consumes **only** the JSON report produced by `ReportGenerator` —
it never imports Presidio, `RiskEngine`, or any other scanner
internals. It is implemented in `scanner/ai/`:

| Module                    | Responsibility                                                        |
|---------------------------|------------------------------------------------------------------------|
| `providers.py`            | Replaceable `AIProvider` abstraction (`NullAIProvider`, `OpenAIProvider`, `AzureOpenAIProvider`) plus the `get_provider()` factory |
| `prompt_builder.py`       | The single place prompts are constructed from a JSON report          |
| `recommendations.py`      | Deterministic entity-type -> remediation advice, derived only from entity types actually present in the findings |
| `markdown_generator.py`   | Builds the final Markdown document — only the Executive Summary paragraph may come from AI; every other fact (risk score, status, findings, recommendations) is taken directly from the JSON report |
| `ai_assistant.py`         | `AIAssistant`, the orchestrator `main.py` calls                      |

**Architecture rule: AI never makes security decisions.** Presidio
detects, `RiskEngine` decides, AI explains. Nothing in `scanner/ai/`
can change a finding, a severity, a risk score, or `pipeline_status`.

**AI failures never abort the scan.** Every failure mode — AI
disabled, a missing API key, a provider timeout, an invalid/empty
response, an unreachable provider, or an unknown provider name — is
caught and logged as a warning, and `AIAssistant` falls back to a
fully deterministic Markdown summary built straight from the JSON
report. The scan still exits `0`.

By default (`AI_PROVIDER=null`), no network calls are made at all and
the deterministic fallback summary is always used — the `openai`
package is not even imported. Set `AI_PROVIDER=openai` or
`AI_PROVIDER=azure_openai` (with `AI_API_KEY`, and for Azure also
`AI_AZURE_ENDPOINT`) to generate a real AI-written executive summary.

## Error handling

`repository_manager.py` and `pii_detector.py` raise specific exceptions
so callers (and the CLI) can react precisely rather than catching a
generic error:

| Exception               | Raised when                                                        | CLI exit code |
|--------------------------|---------------------------------------------------------------------|---------------|
| `RepositoryNotFound`     | A local path does not exist                                         | 3             |
| `InvalidRepository`      | A local path exists but isn't a directory, isn't a Git repo, or is bare | 4         |
| `InvalidRepositoryURL`   | A GitLab URL is empty, malformed, or uses an unsupported scheme     | 5             |
| `AuthenticationFailed`   | The remote rejected credentials (private repo, bad access)          | 6             |
| `BranchNotFound`         | The requested branch doesn't exist on the remote                    | 6             |
| `CloneFailed`            | Any other cloning failure (network error, repo doesn't exist, etc.) | 6             |
| `PIIDetectorError`       | Presidio/spaCy isn't installed, or its NLP model failed to load     | 7             |
| *(report I/O)*           | The JSON report could not be written (disk full, permissions, etc.) | 8             |

`scanner/ai/providers.py` also defines `AIProviderError`, but it is
deliberately **not** in this table: `AIAssistant` always catches it
internally and falls back to a deterministic summary rather than
letting it reach `main.py`, so it never affects the process exit code.

## Running the tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

Local-repository tests run fully offline. GitLab-clone tests use a
small public repository to exercise the real `git.Repo.clone_from()`
code path, and are automatically skipped if no outbound network
access is available.

## Roadmap

**Task 1 — Identify PII at code level from GitLab repositories (Microsoft Presidio)**
- [x] Project structure, config, logging, models, utils
- [x] Repository Manager (local validation + GitLab cloning)
- [x] File traversal + Microsoft Presidio integration

**Task 2 — AI-Assisted DevSecOps Pipeline on Azure DevOps**
- [x] **Phase 1** — Reporting foundation + deterministic risk engine (this phase)
- [x] **Phase 2** — AI assistant (explanations/remediation only; never detects PII or decides pipeline status)
- [ ] **Phase 3** — Azure DevOps pipeline integration (YAML, artifacts, build gating)

## Design principles

- **Single source of truth for configuration** — `scanner/config.py`
  exposes one validated, immutable `ScannerSettings` object.
- **No hidden globals** — settings and logging are explicitly requested
  (`get_settings()`, `get_logger(__name__)`), not silently imported as
  side effects.
- **Fail fast** — invalid configuration raises `ConfigError` immediately
  at startup rather than causing confusing failures mid-scan.
- **Presidio is a dependency, not a fork** — the official `presidio/`
  repository is never modified; it is consumed as an installed package
  (`presidio-analyzer`), imported only from `scanner/pii_detector.py`.
- **One bad file shouldn't abort a scan** — `FileScanner` and
  `PIIDetector` isolate per-file failures (unreadable files, analysis
  errors) as skips/log warnings rather than raising out of `ScanEngine`.
- **AI never makes security decisions** — `RiskEngine` is 100%
  deterministic (fixed severity weights, configurable thresholds); the
  same scan always produces the same `pipeline_status`. A future AI
  assistant (Task 2, Phase 2) may explain or summarize a report, but
  never overrides `RiskEngine`'s output.
- **Reports never leak raw PII by default** — `ReportGenerator`
  redacts every matched value before writing to disk
  (`report_redaction_enabled=True`), since a JSON report may be stored
  or published as a pipeline artifact that other people can access.
