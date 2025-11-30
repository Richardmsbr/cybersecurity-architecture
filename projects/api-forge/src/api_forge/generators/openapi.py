"""OpenAPI specification generator."""

from typing import Any


class OpenAPIGenerator:
    """Generator for OpenAPI 3.1 specifications."""

    TYPE_MAPPING = {
        "string": {"type": "string"},
        "text": {"type": "string"},
        "integer": {"type": "integer"},
        "int": {"type": "integer"},
        "float": {"type": "number", "format": "float"},
        "number": {"type": "number"},
        "boolean": {"type": "boolean"},
        "bool": {"type": "boolean"},
        "datetime": {"type": "string", "format": "date-time"},
        "date": {"type": "string", "format": "date"},
        "time": {"type": "string", "format": "time"},
        "email": {"type": "string", "format": "email"},
        "url": {"type": "string", "format": "uri"},
        "uuid": {"type": "string", "format": "uuid"},
        "password": {"type": "string", "format": "password"},
        "markdown": {"type": "string"},
    }

    def generate(self, config: dict[str, Any]) -> dict[str, Any]:
        """Generate OpenAPI 3.1 specification from config."""
        name = config.get("name", "API")
        version = config.get("version", "1.0.0")
        description = config.get("description", "")

        spec = {
            "openapi": "3.1.0",
            "info": {
                "title": name,
                "version": version,
                "description": description,
            },
            "servers": [
                {"url": "http://localhost:8000", "description": "Development"},
            ],
            "paths": {},
            "components": {
                "schemas": {},
                "securitySchemes": {},
            },
        }

        # Add security scheme
        auth_config = config.get("settings", {}).get("auth", {})
        if auth_config.get("type") == "jwt":
            spec["components"]["securitySchemes"]["bearerAuth"] = {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
            }
            spec["security"] = [{"bearerAuth": []}]

        # Generate schemas and paths for each entity
        entities = config.get("entities", {})
        for entity_name, entity_config in entities.items():
            # Generate schema
            schema = self._generate_schema(entity_name, entity_config)
            spec["components"]["schemas"][entity_name] = schema

            # Generate request/response schemas
            spec["components"]["schemas"][f"{entity_name}Create"] = self._generate_create_schema(
                entity_name, entity_config
            )
            spec["components"]["schemas"][f"{entity_name}Update"] = self._generate_update_schema(
                entity_name, entity_config
            )
            spec["components"]["schemas"][f"{entity_name}List"] = self._generate_list_schema(
                entity_name
            )

            # Generate paths
            paths = self._generate_paths(entity_name, entity_config)
            spec["paths"].update(paths)

        return spec

    def _generate_schema(
        self,
        entity_name: str,
        entity_config: dict[str, Any],
    ) -> dict[str, Any]:
        """Generate JSON Schema for an entity."""
        properties = {
            "id": {"type": "integer", "description": "Unique identifier"},
            "created_at": {"type": "string", "format": "date-time"},
            "updated_at": {"type": "string", "format": "date-time"},
        }
        required = ["id"]

        for field in entity_config.get("fields", []):
            field_name = field["name"]
            field_type = field.get("type", "string")

            prop = self.TYPE_MAPPING.get(field_type, {"type": "string"}).copy()

            # Add constraints
            if field.get("min_length"):
                prop["minLength"] = field["min_length"]
            if field.get("max_length"):
                prop["maxLength"] = field["max_length"]
            if field.get("min_value") is not None:
                prop["minimum"] = field["min_value"]
            if field.get("max_value") is not None:
                prop["maximum"] = field["max_value"]
            if field.get("default") is not None:
                prop["default"] = field["default"]

            properties[field_name] = prop

            if field.get("required"):
                required.append(field_name)

        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }

    def _generate_create_schema(
        self,
        entity_name: str,
        entity_config: dict[str, Any],
    ) -> dict[str, Any]:
        """Generate schema for create requests (no id, timestamps)."""
        properties = {}
        required = []

        for field in entity_config.get("fields", []):
            field_name = field["name"]
            field_type = field.get("type", "string")

            prop = self.TYPE_MAPPING.get(field_type, {"type": "string"}).copy()

            if field.get("min_length"):
                prop["minLength"] = field["min_length"]
            if field.get("max_length"):
                prop["maxLength"] = field["max_length"]

            properties[field_name] = prop

            if field.get("required"):
                required.append(field_name)

        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }

    def _generate_update_schema(
        self,
        entity_name: str,
        entity_config: dict[str, Any],
    ) -> dict[str, Any]:
        """Generate schema for update requests (all optional)."""
        properties = {}

        for field in entity_config.get("fields", []):
            field_name = field["name"]
            field_type = field.get("type", "string")

            prop = self.TYPE_MAPPING.get(field_type, {"type": "string"}).copy()
            properties[field_name] = prop

        return {
            "type": "object",
            "properties": properties,
        }

    def _generate_list_schema(self, entity_name: str) -> dict[str, Any]:
        """Generate paginated list response schema."""
        return {
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {"$ref": f"#/components/schemas/{entity_name}"},
                },
                "total": {"type": "integer"},
                "page": {"type": "integer"},
                "size": {"type": "integer"},
                "pages": {"type": "integer"},
            },
            "required": ["items", "total", "page", "size", "pages"],
        }

    def _generate_paths(
        self,
        entity_name: str,
        entity_config: dict[str, Any],
    ) -> dict[str, Any]:
        """Generate CRUD paths for an entity."""
        path_name = entity_name.lower() + "s"  # Simple pluralization
        tag = entity_name

        paths = {}

        # Collection endpoints: GET (list), POST (create)
        paths[f"/{path_name}"] = {
            "get": {
                "summary": f"List {path_name}",
                "tags": [tag],
                "parameters": [
                    {
                        "name": "page",
                        "in": "query",
                        "schema": {"type": "integer", "default": 1},
                    },
                    {
                        "name": "size",
                        "in": "query",
                        "schema": {"type": "integer", "default": 20},
                    },
                ],
                "responses": {
                    "200": {
                        "description": "Successful response",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": f"#/components/schemas/{entity_name}List"
                                }
                            }
                        },
                    }
                },
            },
            "post": {
                "summary": f"Create {entity_name.lower()}",
                "tags": [tag],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": f"#/components/schemas/{entity_name}Create"
                            }
                        }
                    },
                },
                "responses": {
                    "201": {
                        "description": "Created",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": f"#/components/schemas/{entity_name}"}
                            }
                        },
                    },
                    "422": {"description": "Validation Error"},
                },
            },
        }

        # Item endpoints: GET (read), PUT (update), DELETE
        paths[f"/{path_name}/{{id}}"] = {
            "get": {
                "summary": f"Get {entity_name.lower()}",
                "tags": [tag],
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Successful response",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": f"#/components/schemas/{entity_name}"}
                            }
                        },
                    },
                    "404": {"description": "Not Found"},
                },
            },
            "put": {
                "summary": f"Update {entity_name.lower()}",
                "tags": [tag],
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": f"#/components/schemas/{entity_name}Update"
                            }
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Updated",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": f"#/components/schemas/{entity_name}"}
                            }
                        },
                    },
                    "404": {"description": "Not Found"},
                    "422": {"description": "Validation Error"},
                },
            },
            "delete": {
                "summary": f"Delete {entity_name.lower()}",
                "tags": [tag],
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
                "responses": {
                    "204": {"description": "Deleted"},
                    "404": {"description": "Not Found"},
                },
            },
        }

        return paths
