# GitLab PII Scanner

Identify PII (Personally Identifiable Information) at the code level in a
GitLab repository, using [Microsoft Presidio](https://github.com/microsoft/presidio)
as the detection engine.

> **Status: Phase 3 — File Traversal + Presidio Integration.**
> Phase 1 (structure, config, logging, models, utils) is complete.
> Phase 2 (`RepositoryManager`: local validation + GitLab cloning) is
> complete. Phase 3 adds a `FileScanner` that walks the repository for
> in-scope files, a `PIIDetector` that runs Microsoft Presidio over
> each one, and a `ScanEngine` that ties the two together and reports
> a findings summary. Report generation (CSV/HTML) is **not yet
> implemented** — it arrives in Phase 4.

---

## Project layout

```
gitlab-pii-scanner/
│
├── presidio/                  # Official Microsoft Presidio repo (reference only — DO NOT MODIFY)
│
└── scanner/                   # This project
    ├── main.py                # CLI entry point
    ├── requirements.txt
    ├── README.md
    ├── .gitignore
    ├── tests/
    │   ├── __init__.py
    │   ├── test_repository_manager.py   # Phase 2 test suite
    │   ├── test_file_scanner.py         # Phase 3 test suite
    │   ├── test_pii_detector.py         # Phase 3 test suite
    │   └── test_scan_engine.py          # Phase 3 test suite
    └── scanner/                # Internal application package
        ├── __init__.py
        ├── config.py               # Centralized, typed, env-driven configuration
        ├── logger.py               # Application-wide logging setup
        ├── models.py               # Shared dataclasses (findings, scan results, etc.)
        ├── utils.py                # Small, dependency-free helper functions
        ├── repository_manager.py   # Phase 2: obtain a local or GitLab repository
        ├── file_scanner.py         # Phase 3: traverse a repository for scannable files
        ├── pii_detector.py         # Phase 3: Presidio-based PII detection
        └── scan_engine.py          # Phase 3: orchestrates traversal + detection
```

The `presidio/` folder alongside `scanner/` is the official upstream
repository, kept purely as a reference/dependency. It is never imported
by path and never modified — Presidio is consumed as an installed
package (`presidio-analyzer`), imported only from `scanner/pii_detector.py`.

## Requirements

- Python 3.12+
- pip

## Setup

```bash
cd scanner
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
either export environment variables or create a `.env` file inside
`scanner/` (loaded automatically if `python-dotenv` is installed):

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

## Running (Phase 3 behaviour)

Running the CLI now obtains a real repository via `RepositoryManager`,
then scans it with `ScanEngine`: `FileScanner` walks every in-scope
file (honoring `supported_extensions`, `excluded_directories`, and
`max_file_size_bytes`) and `PIIDetector` runs Microsoft Presidio over
each one. A findings summary (counts by severity, then each finding's
entity type, confidence, file, and line number) is printed to the
console/log. Report generation (CSV/HTML) is still **not
implemented**.

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

- [x] **Phase 1** — Project structure, config, logging, models, utils
- [x] **Phase 2** — Repository Manager (local validation + GitLab cloning)
- [x] **Phase 3** — File traversal + Microsoft Presidio integration
- [ ] **Phase 4** — Report generation (CSV/HTML)
- [ ] **Phase 5** — Azure DevOps pipeline integration
- [ ] **Phase 6** — AI-assisted summarization of findings

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
