"""LLM client for natural language processing."""

import os
from typing import Any


class LLMClient:
    """Client for interacting with LLM models."""

    def __init__(self, model: str = "llama3.2"):
        self.model = model
        self._client = None

    def _get_client(self):
        """Lazy initialization of LLM client."""
        if self._client is not None:
            return self._client

        if self.model.startswith("gpt"):
            # OpenAI
            from openai import OpenAI
            self._client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            self._provider = "openai"
        else:
            # Ollama (local)
            try:
                import ollama
                self._client = ollama
                self._provider = "ollama"
            except ImportError:
                raise RuntimeError(
                    "Ollama not installed. Install with: pip install ollama"
                )

        return self._client

    def generate(self, prompt: str, **kwargs: Any) -> str:
        """Generate text from prompt."""
        client = self._get_client()

        if self._provider == "openai":
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert API architect."},
                    {"role": "user", "content": prompt},
                ],
                temperature=kwargs.get("temperature", 0.7),
                max_tokens=kwargs.get("max_tokens", 4096),
            )
            return response.choices[0].message.content

        elif self._provider == "ollama":
            response = client.generate(
                model=self.model,
                prompt=prompt,
                options={
                    "temperature": kwargs.get("temperature", 0.7),
                },
            )
            return response["response"]

        raise RuntimeError(f"Unknown provider: {self._provider}")

    def extract_entities(self, description: str) -> dict[str, Any]:
        """Extract entities from natural language description."""
        prompt = f"""You are an expert API designer. Analyze this description and extract data entities.

Description: {description}

For each entity, identify:
1. Entity name (singular, PascalCase)
2. Fields with types (string, integer, boolean, datetime, email, url, text, password)
3. Field constraints (required, unique, min/max length)
4. Relationships (belongs_to, has_many, has_one, many_to_many)

Return ONLY valid YAML in this exact format:

```yaml
EntityName:
  fields:
    - field_name: type, constraints
  relations:
    - relationship_type: target_entity
```

Example output for "blog with users and posts":
```yaml
User:
  fields:
    - name: string, required, min=2, max=50
    - email: email, required, unique
    - password: password, required, min=8
  relations:
    - has_many: posts

Post:
  fields:
    - title: string, required, max=200
    - content: text, required
    - published: boolean, default=false
  relations:
    - belongs_to: author (User)
```

Now analyze: {description}"""

        response = self.generate(prompt, temperature=0.3)
        return self._parse_yaml_response(response)

    def _parse_yaml_response(self, response: str) -> dict[str, Any]:
        """Parse YAML from LLM response."""
        import yaml

        # Extract YAML from markdown code blocks
        content = response
        if "```yaml" in response:
            start = response.index("```yaml") + 7
            end = response.index("```", start)
            content = response[start:end]
        elif "```" in response:
            start = response.index("```") + 3
            end = response.index("```", start)
            content = response[start:end]

        try:
            return yaml.safe_load(content.strip())
        except yaml.YAMLError:
            return {}
