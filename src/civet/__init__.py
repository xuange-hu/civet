"""civet — deterministic security auditor for GitHub Actions workflows.

Zero third-party dependencies in the core: no PyYAML, no requests, no LLM.
A scan is a pure function of the bytes on disk, which is what makes it
usable as a CI gate on air-gapped runners.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
