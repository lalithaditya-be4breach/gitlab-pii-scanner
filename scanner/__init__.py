"""
scanner
=======

Internal package for the GitLab PII Scanner project.

Modules implemented so far:
    - config.py            : Centralized, typed application configuration
    - logger.py             : Application-wide logging setup
    - models.py              : Typed dataclasses shared across the project
    - utils.py                : Small, dependency-free helper functions
    - repository_manager.py   : Phase 2 - obtain a local or GitLab repository
    - file_scanner.py         : Phase 3 - traverse a repository for scannable files
    - pii_detector.py         : Phase 3 - Presidio-based PII detection
    - scan_engine.py          : Phase 3 - orchestrates traversal + detection

Later phases will add:
    - report.py     : Report generation (CSV/HTML/JSON)

Nothing in this package touches the third-party `presidio` repository;
it is consumed strictly as the installed `presidio-analyzer` package.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
