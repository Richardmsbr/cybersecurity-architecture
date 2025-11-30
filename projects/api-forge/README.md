# API Forge

> AI-powered API generation from natural language descriptions

## Problem Statement

Developers spend 40-60% of their time writing boilerplate code for APIs. Current tools require manually writing OpenAPI specs before generating code. No open-source solution generates production-ready APIs from natural language.

## Solution

API Forge uses LLMs to generate complete, production-ready APIs from simple descriptions:

```bash
api-forge generate --input "Create an order management API with products, orders, and customers"
```

Output:
- OpenAPI 3.1 specification
- Production-ready code (FastAPI, Express, Go)
- Database models and migrations
- Authentication (JWT/OAuth2)
- Unit and integration tests
- Docker and Kubernetes manifests
- CI/CD pipeline

## Quick Start

```bash
# Install
pip install api-forge

# Generate from description
api-forge generate \
  --description "REST API for blog with posts, comments, and users" \
  --framework fastapi \
  --database postgresql \
  --auth jwt \
  --output ./my-blog-api

# Or use YAML config
api-forge generate --config api.yaml
```

## Configuration

```yaml
# api.yaml
name: blog-api
version: 1.0.0

description: |
  A blog API with user authentication, posts with markdown support,
  and nested comments. Users can like posts and follow other users.

entities:
  User:
    fields:
      - name: string, required, min=2, max=50
      - email: email, required, unique
      - password: password, required, min=8
      - bio: text, optional
      - avatar_url: url, optional
    relations:
      - has_many: posts
      - has_many: comments
      - many_to_many: followers (User)

  Post:
    fields:
      - title: string, required, max=200
      - slug: string, unique, auto_generate
      - content: markdown, required
      - published: boolean, default=false
      - published_at: datetime, optional
    relations:
      - belongs_to: author (User)
      - has_many: comments
      - many_to_many: liked_by (User)

  Comment:
    fields:
      - content: text, required, max=1000
    relations:
      - belongs_to: author (User)
      - belongs_to: post
      - belongs_to: parent (Comment), optional  # nested comments

settings:
  framework: fastapi
  database: postgresql
  cache: redis
  auth:
    type: jwt
    expiry: 24h
    refresh: true
  rate_limiting:
    default: 100/minute
    auth: 20/minute
  pagination:
    default_size: 20
    max_size: 100

output:
  path: ./generated
  docker: true
  kubernetes: true
  ci:
    provider: github-actions
    tests: true
    lint: true
    security_scan: true
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      API Forge Engine                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐                                           │
│  │    Input     │  YAML config, natural language,           │
│  │    Parser    │  or interactive CLI                       │
│  └──────┬───────┘                                           │
│         │                                                    │
│         v                                                    │
│  ┌──────────────┐                                           │
│  │  LLM Engine  │  Llama 3.2 / Mistral / GPT-4             │
│  │              │  - Entity extraction                      │
│  │              │  - Relationship inference                 │
│  │              │  - Business logic detection               │
│  └──────┬───────┘                                           │
│         │                                                    │
│         v                                                    │
│  ┌──────────────┐                                           │
│  │   Schema     │  - OpenAPI 3.1 generation                │
│  │   Generator  │  - JSON Schema for entities              │
│  │              │  - Database schema (SQL)                  │
│  └──────┬───────┘                                           │
│         │                                                    │
│         v                                                    │
│  ┌──────────────┐                                           │
│  │    Code      │  Framework-specific generators:           │
│  │   Generator  │  - FastAPI (Python)                       │
│  │              │  - Express/NestJS (Node.js)               │
│  │              │  - Gin/Echo (Go)                          │
│  │              │  - Axum (Rust)                            │
│  └──────┬───────┘                                           │
│         │                                                    │
│         v                                                    │
│  ┌──────────────┐                                           │
│  │   Output     │  Complete project structure               │
│  │   Writer     │  with all files                           │
│  └──────────────┘                                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Generated Output Structure

```
my-blog-api/
├── openapi.yaml                 # OpenAPI 3.1 specification
├── README.md                    # Auto-generated documentation
│
├── src/
│   ├── main.py                  # Application entry point
│   ├── config.py                # Configuration management
│   │
│   ├── models/                  # Database models
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── post.py
│   │   └── comment.py
│   │
│   ├── schemas/                 # Pydantic schemas
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── post.py
│   │   └── comment.py
│   │
│   ├── routers/                 # API endpoints
│   │   ├── __init__.py
│   │   ├── users.py
│   │   ├── posts.py
│   │   ├── comments.py
│   │   └── auth.py
│   │
│   ├── services/                # Business logic
│   │   ├── __init__.py
│   │   ├── user_service.py
│   │   ├── post_service.py
│   │   └── auth_service.py
│   │
│   ├── auth/                    # Authentication
│   │   ├── __init__.py
│   │   ├── jwt.py
│   │   └── dependencies.py
│   │
│   └── utils/                   # Utilities
│       ├── __init__.py
│       ├── pagination.py
│       └── security.py
│
├── tests/
│   ├── conftest.py              # Test fixtures
│   ├── test_users.py
│   ├── test_posts.py
│   ├── test_comments.py
│   └── test_auth.py
│
├── migrations/                  # Alembic migrations
│   ├── env.py
│   └── versions/
│       └── 001_initial.py
│
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
│
├── k8s/
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── ingress.yaml
│   └── configmap.yaml
│
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── deploy.yml
│
├── pyproject.toml               # Dependencies
├── .env.example                 # Environment template
└── .gitignore
```

## Features

### Entity Detection
```
Input: "API for e-commerce with products, categories, and shopping cart"

Detected Entities:
- Product (name, price, description, stock)
- Category (name, slug, parent_category)
- Cart (user, items, total)
- CartItem (product, quantity, price)
```

### Relationship Inference
```
Inferred Relationships:
- Product belongs_to Category
- Category has_many Products
- Category belongs_to parent Category (self-referential)
- Cart belongs_to User
- Cart has_many CartItems
- CartItem belongs_to Product
```

### Security by Default
- Input validation on all fields
- SQL injection prevention (ORM)
- XSS protection
- Rate limiting
- JWT with refresh tokens
- Password hashing (Argon2)
- CORS configuration
- Security headers

## Supported Frameworks

| Framework | Language | Status |
|-----------|----------|--------|
| FastAPI | Python | Stable |
| Flask | Python | Stable |
| Django REST | Python | Beta |
| Express | Node.js | Stable |
| NestJS | Node.js | Beta |
| Gin | Go | Beta |
| Echo | Go | Planned |
| Axum | Rust | Planned |
| Spring Boot | Java | Planned |

## Supported Databases

| Database | ORM | Status |
|----------|-----|--------|
| PostgreSQL | SQLAlchemy | Stable |
| MySQL | SQLAlchemy | Stable |
| SQLite | SQLAlchemy | Stable |
| MongoDB | Motor | Beta |
| Redis | aioredis | Cache only |

## Roadmap

### v0.1 (MVP)
- [ ] YAML config parser
- [ ] OpenAPI 3.1 generation
- [ ] FastAPI code generation
- [ ] PostgreSQL support
- [ ] JWT authentication
- [ ] Basic tests

### v0.2
- [ ] Natural language input
- [ ] Express.js support
- [ ] MongoDB support
- [ ] OAuth2 support
- [ ] Docker generation

### v0.3
- [ ] Go support (Gin)
- [ ] GraphQL generation
- [ ] Kubernetes manifests
- [ ] CI/CD pipelines
- [ ] OpenTelemetry instrumentation

### v1.0
- [ ] All major frameworks
- [ ] Plugin system
- [ ] Web UI
- [ ] VS Code extension
- [ ] Cloud deployment

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0
