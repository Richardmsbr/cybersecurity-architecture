"""Core engine for API generation."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .generators.openapi import OpenAPIGenerator
from .generators.fastapi import FastAPIGenerator
from .llm import LLMClient


@dataclass
class GenerationResult:
    """Result of API generation."""
    files: list[str] = field(default_factory=list)
    openapi_spec: dict | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class ForgeEngine:
    """Main engine for API generation."""

    def __init__(
        self,
        model: str = "llama3.2",
        output_dir: Path = Path("./generated"),
        dry_run: bool = False,
    ):
        self.model = model
        self.output_dir = output_dir
        self.dry_run = dry_run
        self.llm = LLMClient(model=model)

    def generate(self, config: dict[str, Any]) -> GenerationResult:
        """Generate API from configuration."""
        result = GenerationResult()

        # Step 1: If description provided, extract entities using LLM
        if "description" in config and "entities" not in config:
            entities = self._extract_entities(config["description"])
            config["entities"] = entities

        # Step 2: Generate OpenAPI specification
        openapi_gen = OpenAPIGenerator()
        openapi_spec = openapi_gen.generate(config)
        result.openapi_spec = openapi_spec

        # Step 3: Generate code based on framework
        framework = config.get("settings", {}).get("framework", "fastapi")
        generator = self._get_generator(framework)

        files = generator.generate(
            config=config,
            openapi_spec=openapi_spec,
            output_dir=self.output_dir,
            dry_run=self.dry_run,
        )
        result.files = files

        return result

    def _extract_entities(self, description: str) -> dict[str, Any]:
        """Extract entities from natural language description using LLM."""
        prompt = f"""Analyze this API description and extract entities with their fields and relationships.

Description: {description}

Return a YAML structure like this:
```yaml
User:
  fields:
    - name: string, required
    - email: email, required, unique
  relations:
    - has_many: posts
```

Only return the YAML, no explanations."""

        response = self.llm.generate(prompt)
        # Parse YAML from response
        import yaml
        try:
            # Extract YAML from markdown code block if present
            if "```yaml" in response:
                yaml_start = response.index("```yaml") + 7
                yaml_end = response.index("```", yaml_start)
                yaml_content = response[yaml_start:yaml_end]
            elif "```" in response:
                yaml_start = response.index("```") + 3
                yaml_end = response.index("```", yaml_start)
                yaml_content = response[yaml_start:yaml_end]
            else:
                yaml_content = response

            return yaml.safe_load(yaml_content)
        except Exception:
            return {}

    def _get_generator(self, framework: str):
        """Get the appropriate code generator for the framework."""
        generators = {
            "fastapi": FastAPIGenerator,
            # "express": ExpressGenerator,
            # "gin": GinGenerator,
        }

        generator_class = generators.get(framework)
        if not generator_class:
            raise ValueError(f"Unsupported framework: {framework}")

        return generator_class()
