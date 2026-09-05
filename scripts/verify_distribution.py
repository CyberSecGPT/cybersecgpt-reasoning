"""Verify Reasoning wheel ownership and dependency boundaries."""

import argparse
import zipfile
from email.parser import Parser
from pathlib import Path

EXPECTED_SOURCE_MEMBERS = frozenset(
    {
        "cybersecgpt/reasoning/__init__.py",
        "cybersecgpt/reasoning/errors.py",
        "cybersecgpt/reasoning/routing.py",
    }
)
PROVIDER_MARKERS = (
    "openai",
    "anthropic",
    "cohere",
    "google-generativeai",
    "google-genai",
)


class DistributionVerificationError(RuntimeError):
    """Report a distribution boundary violation."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DistributionVerificationError(message)


def verify_wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        source_members = {
            name for name in names if name.startswith("cybersecgpt/")
        }
        _require(
            source_members == EXPECTED_SOURCE_MEMBERS,
            f"wheel source members are incorrect: {sorted(source_members)}",
        )
        _require(
            "cybersecgpt/__init__.py" not in names,
            "reasoning wheel must not overwrite the Foundation-owned "
            "top-level package",
        )
        _require(
            not any(
                name.startswith("cybersecgpt/foundation/") for name in names
            ),
            "reasoning wheel must not bundle Foundation implementation",
        )

        metadata_names = [
            name for name in names if name.endswith(".dist-info/METADATA")
        ]
        _require(
            len(metadata_names) == 1,
            "wheel must contain exactly one METADATA file",
        )
        metadata_content = archive.read(metadata_names[0]).decode("utf-8")
        metadata = Parser().parsestr(metadata_content)
        _require(
            metadata.get("Name") == "cybersecgpt-reasoning",
            "wheel Name is incorrect",
        )
        _require(
            metadata.get("Version") == "0.1.0",
            "wheel Version is incorrect",
        )
        requirements = [
            str(item) for item in metadata.get_all("Requires-Dist", [])
        ]
        foundation_requirements = [
            item
            for item in requirements
            if item.lower().startswith("cybersecgpt-foundation")
        ]
        _require(
            len(foundation_requirements) == 1,
            "wheel must declare one Foundation runtime dependency: "
            f"{requirements}",
        )
        runtime_requirement = foundation_requirements[0].replace(" ", "")
        _require(
            runtime_requirement.startswith(
                "cybersecgpt-foundation<0.2,>=0.1.0"
            )
            or runtime_requirement.startswith(
                "cybersecgpt-foundation>=0.1.0,<0.2"
            ),
            "Foundation dependency range is incorrect: "
            f"{foundation_requirements[0]}",
        )
        normalized = "\n".join(requirements).lower()
        _require(
            not any(marker in normalized for marker in PROVIDER_MARKERS),
            "provider SDK dependency detected in wheel metadata",
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    directory: Path = args.directory
    wheels = sorted(directory.glob("*.whl"))
    _require(len(wheels) == 1, f"expected one wheel, found {len(wheels)}")
    verify_wheel(wheels[0])
    print("Reasoning distribution verification passed.")


if __name__ == "__main__":
    main()
