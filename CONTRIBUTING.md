# Contributing to cybersecgpt-reasoning

## Architecture governance

Changes must conform to Accepted ADR-0011 and the Native Brain conformance profile. Public-contract or ownership changes require coordinated architecture review in `CyberSecGPT/cybersecgpt-docs`.

## Development setup

CI uses the verified typed and split-package-compatible Foundation baseline at commit `4d534c0142ab3198078dd96a95d310a298165c5c`.

For local development, install that Foundation revision first, then install this repository with its `dev` extra. Foundation publishes the PEP 561 `py.typed` marker and extends the Foundation-owned top-level `cybersecgpt` package path so separately distributed `cybersecgpt.*` subpackages remain discoverable. Strict downstream type checking must remain enabled rather than suppressing `import-untyped` diagnostics.

## Required checks

```text
python -m ruff check .
python -m black --check .
python -m mypy src scripts
python scripts/validate_repository.py
python -m pip check
python -m pytest --cov=cybersecgpt.reasoning --cov-report=term-missing --cov-fail-under=100
python -m build
python scripts/verify_distribution.py dist
```

Do not merge while any required check is failing. Tests must exercise negative security paths as well as successful behavior.
