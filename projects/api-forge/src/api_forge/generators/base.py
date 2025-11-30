"""Base generator class."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class BaseGenerator(ABC):
    """Base class for code generators."""

    @abstractmethod
    def generate(
        self,
        config: dict[str, Any],
        openapi_spec: dict[str, Any],
        output_dir: Path,
        dry_run: bool = False,
    ) -> list[str]:
        """Generate code files.

        Args:
            config: API configuration
            openapi_spec: Generated OpenAPI specification
            output_dir: Output directory
            dry_run: If True, don't write files

        Returns:
            List of generated file paths
        """
        pass

    def write_file(
        self,
        path: Path,
        content: str,
        dry_run: bool = False,
    ) -> None:
        """Write content to file."""
        if dry_run:
            return

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
