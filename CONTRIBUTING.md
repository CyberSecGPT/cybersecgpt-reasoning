# Contributing to cybersecgpt-reasoning

## Architecture governance

Changes must conform to Accepted ADR-0011 and the Native Brain conformance profile. Public-contract or ownership changes require coordinated architecture review in `CyberSecGPT/cybersecgpt-docs`.

## Development setup

CI uses the verified typed Foundation baseline at commit `30a5c23f47b63ab0196fb4c40378b127d51acf36`.

For local development, install that Foundation revision first, then install this repository with its `dev` extra. The Foundation distribution publishes the PEP 561 `py.typed` marker, so strict downstream type checking must remain enabled rather than suppressing `import-untyped` diagnostics.

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
