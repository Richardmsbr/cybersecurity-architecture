"""Configuration loading and validation for API Forge."""

from pathlib import Path
from typing import Any
import yaml

from pydantic import BaseModel, Field


class FieldConfig(BaseModel):
    """Configuration for an entity field."""
    name: str
    type: str
    required: bool = False
    unique: bool = False
    default: Any = None
    min_length: int | None = None
    max_length: int | None = None
    min_value: float | None = None
    max_value: float | None = None


class RelationConfig(BaseModel):
    """Configuration for an entity relationship."""
    type: str  # belongs_to, has_many, has_one, many_to_many
    target: str
    through: str | None = None


class EntityConfig(BaseModel):
    """Configuration for a data entity."""
    name: str
    fields: list[FieldConfig] = Field(default_factory=list)
    relations: list[RelationConfig] = Field(default_factory=list)


class AuthConfig(BaseModel):
    """Authentication configuration."""
    type: str = "jwt"  # jwt, oauth2, apikey, none
    expiry: str = "24h"
    refresh: bool = True
    secret_env: str = "JWT_SECRET"


class RateLimitConfig(BaseModel):
    """Rate limiting configuration."""
    default: str = "100/minute"
    auth: str = "20/minute"
    per_user: bool = True


class PaginationConfig(BaseModel):
    """Pagination configuration."""
    default_size: int = 20
    max_size: int = 100


class CIConfig(BaseModel):
    """CI/CD configuration."""
    provider: str = "github-actions"
    tests: bool = True
    lint: bool = True
    security_scan: bool = True


class OutputConfig(BaseModel):
    """Output configuration."""
    path: str = "./generated"
    docker: bool = True
    kubernetes: bool = False
    ci: CIConfig = Field(default_factory=CIConfig)


class SettingsConfig(BaseModel):
    """API settings configuration."""
    framework: str = "fastapi"
    database: str = "postgresql"
    cache: str | None = None
    auth: AuthConfig = Field(default_factory=AuthConfig)
    rate_limiting: RateLimitConfig = Field(default_factory=RateLimitConfig)
    pagination: PaginationConfig = Field(default_factory=PaginationConfig)


class APIConfig(BaseModel):
    """Main API configuration."""
    name: str
    version: str = "1.0.0"
    description: str = ""
    entities: dict[str, dict] = Field(default_factory=dict)
    settings: SettingsConfig = Field(default_factory=SettingsConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)


def parse_field_definition(field_def: str) -> FieldConfig:
    """Parse a field definition string into FieldConfig.

    Examples:
        - "name: string, required"
        - "email: email, required, unique"
        - "age: integer, min=0, max=150"
    """
    parts = [p.strip() for p in field_def.split(",")]

    # First part is "name: type"
    name_type = parts[0].split(":")
    name = name_type[0].strip()
    field_type = name_type[1].strip() if len(name_type) > 1 else "string"

    config = FieldConfig(name=name, type=field_type)

    # Parse remaining parts
    for part in parts[1:]:
        part = part.strip().lower()

        if part == "required":
            config.required = True
        elif part == "unique":
            config.unique = True
        elif part.startswith("min="):
            value = part.split("=")[1]
            if field_type in ["string", "text", "password"]:
                config.min_length = int(value)
            else:
                config.min_value = float(value)
        elif part.startswith("max="):
            value = part.split("=")[1]
            if field_type in ["string", "text", "password"]:
                config.max_length = int(value)
            else:
                config.max_value = float(value)
        elif part.startswith("default="):
            config.default = part.split("=")[1]

    return config


def parse_relation_definition(relation_def: str) -> RelationConfig:
    """Parse a relation definition string into RelationConfig.

    Examples:
        - "has_many: posts"
        - "belongs_to: author (User)"
        - "many_to_many: tags through post_tags"
    """
    parts = relation_def.split(":")
    rel_type = parts[0].strip()
    target_part = parts[1].strip() if len(parts) > 1 else ""

    # Check for (TargetEntity) syntax
    if "(" in target_part:
        target_name = target_part.split("(")[0].strip()
        target_entity = target_part.split("(")[1].rstrip(")").strip()
    else:
        target_name = target_part.split()[0] if target_part else ""
        target_entity = target_name.title()

    # Check for "through" table
    through = None
    if "through" in target_part.lower():
        through_idx = target_part.lower().index("through")
        through = target_part[through_idx + 7:].strip()

    return RelationConfig(
        type=rel_type,
        target=target_entity,
        through=through,
    )


def load_config(path: Path) -> dict[str, Any]:
    """Load and parse a YAML configuration file."""
    with open(path) as f:
        raw_config = yaml.safe_load(f)

    # Parse entities
    if "entities" in raw_config:
        parsed_entities = {}
        for entity_name, entity_def in raw_config["entities"].items():
            parsed_entity = {"name": entity_name, "fields": [], "relations": []}

            if "fields" in entity_def:
                for field_def in entity_def["fields"]:
                    parsed_entity["fields"].append(
                        parse_field_definition(field_def).model_dump()
                    )

            if "relations" in entity_def:
                for rel_def in entity_def["relations"]:
                    parsed_entity["relations"].append(
                        parse_relation_definition(rel_def).model_dump()
                    )

            parsed_entities[entity_name] = parsed_entity

        raw_config["entities"] = parsed_entities

    return raw_config
