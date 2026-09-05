"""Validate the Reasoning repository's security and dependency boundaries."""

import re
import tomllib
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = frozenset(
    {
        ".gitattributes",
        ".github/workflows/ci.yml",
        ".gitignore",
        "AGENTS.md",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "README.md",
        "SECURITY.md",
        "docs/ARCHITECTURE.md",
        "pyproject.toml",
        "scripts/validate_repository.py",
        "scripts/verify_distribution.py",
        "src/cybersecgpt/reasoning/__init__.py",
        "src/cybersecgpt/reasoning/errors.py",
        "src/cybersecgpt/reasoning/routing.py",
        "tests/__init__.py",
        "tests/test_public_api.py",
        "tests/test_routing.py",
    }
)

SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
)

TEXT_SUFFIXES = frozenset({".md", ".py", ".toml", ".txt", ".yml", ".yaml"})
PROVIDER_DEPENDENCY_MARKERS = (
    "openai",
    "anthropic",
    "google-generativeai",
    "google-genai",
    "cohere",
)


class RepositoryValidationError(RuntimeError):
    """Report a repository policy violation."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RepositoryValidationError(message)


def _project_dependencies() -> list[str]:
    with (ROOT / "pyproject.toml").open("rb") as stream:
        parsed = cast(dict[str, object], tomllib.load(stream))

    project = parsed.get("project")
    _require(isinstance(project, dict), "pyproject project table is missing")
    project_table = cast(dict[str, object], project)
    dependencies = project_table.get("dependencies")
    _require(isinstance(dependencies, list), "project dependencies must be a list")
    dependency_list = cast(list[object], dependencies)
    _require(
        all(isinstance(item, str) for item in dependency_list),
        "project dependencies must contain strings",
    )
    return [cast(str, item) for item in dependency_list]


def _text_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part.startswith(".") and part not in {".github"} for part in path.parts):
            continue
        if any(part in {"build", "dist", "__pycache__"} for part in path.parts):
            continue
        if path.suffix in TEXT_SUFFIXES or path.name in {"LICENSE", ".gitattributes", ".gitignore"}:
            files.append(path)
    return files


def main() -> None:
    missing = sorted(path for path in REQUIRED_FILES if not (ROOT / path).is_file())
    _require(not missing, f"required repository files are missing: {missing}")

    dependencies = _project_dependencies()
    _require(
        dependencies == ["cybersecgpt-foundation>=0.1.0,<0.2"],
        f"runtime dependency boundary changed unexpectedly: {dependencies}",
    )
    normalized_dependencies = "\n".join(dependencies).lower()
    _require(
        not any(marker in normalized_dependencies for marker in PROVIDER_DEPENDENCY_MARKERS),
        "provider SDK dependency detected in core runtime dependencies",
    )

    for path in _text_files():
        text = path.read_text(encoding="utf-8")
        for pattern in SECRET_PATTERNS:
            _require(
                pattern.search(text) is None,
                f"sensitive material pattern detected in {path.relative_to(ROOT)}",
            )

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    _require("Accepted ADR-0011" in readme, "README must reference Accepted ADR-0011")
    _require("not" in readme.lower() and "authorization grant" in readme.lower(), "README must preserve the non-authorizing routing boundary")

    print("Reasoning repository validation passed.")


if __name__ == "__main__":
    main()
