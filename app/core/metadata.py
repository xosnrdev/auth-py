"""Project metadata management."""

from pathlib import Path
from typing import TypedDict

import tomli


class ProjectMetadata(TypedDict):
    """Type-safe project metadata."""
    name: str
    version: str
    description: str


def load_project_metadata() -> ProjectMetadata:
    """Load project metadata from pyproject.toml.

    Returns:
        ProjectMetadata: Project name, version and description.

    Raises:
        FileNotFoundError: If pyproject.toml doesn't exist
        KeyError: If required metadata is missing
        tomli.TOMLDecodeError: If TOML is invalid
    """
    # Get project root (2 levels up from this file)
    project_root = Path(__file__).parent.parent.parent
    toml_path = project_root / "pyproject.toml"

    # Validate file exists
    if not toml_path.exists():
        raise FileNotFoundError("pyproject.toml not found")

    # Read and parse TOML
    with open(toml_path, "rb") as f:
        pyproject = tomli.load(f)

    # Extract required fields
    try:
        project = pyproject["project"]
        metadata: ProjectMetadata = {
            "name": project["name"],
            "version": project["version"],
            "description": project["description"],
        }
        return metadata
    except KeyError as e:
        raise KeyError(f"Missing required field in pyproject.toml: {e}")
