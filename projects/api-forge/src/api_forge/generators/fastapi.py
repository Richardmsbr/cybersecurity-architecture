"""FastAPI code generator."""

from pathlib import Path
from typing import Any
import yaml

from .base import BaseGenerator


class FastAPIGenerator(BaseGenerator):
    """Generator for FastAPI applications."""

    PYTHON_TYPE_MAPPING = {
        "string": "str",
        "text": "str",
        "integer": "int",
        "int": "int",
        "float": "float",
        "number": "float",
        "boolean": "bool",
        "bool": "bool",
        "datetime": "datetime",
        "date": "date",
        "email": "EmailStr",
        "url": "HttpUrl",
        "uuid": "UUID",
        "password": "str",
        "markdown": "str",
    }

    SQLALCHEMY_TYPE_MAPPING = {
        "string": "String(255)",
        "text": "Text",
        "integer": "Integer",
        "int": "Integer",
        "float": "Float",
        "number": "Float",
        "boolean": "Boolean",
        "bool": "Boolean",
        "datetime": "DateTime",
        "date": "Date",
        "email": "String(255)",
        "url": "String(500)",
        "uuid": "UUID(as_uuid=True)",
        "password": "String(255)",
        "markdown": "Text",
    }

    def generate(
        self,
        config: dict[str, Any],
        openapi_spec: dict[str, Any],
        output_dir: Path,
        dry_run: bool = False,
    ) -> list[str]:
        """Generate FastAPI application."""
        files = []

        # Create directory structure
        src_dir = output_dir / "src"
        tests_dir = output_dir / "tests"

        # Generate files
        files.extend(self._generate_main(src_dir, config, dry_run))
        files.extend(self._generate_config(src_dir, config, dry_run))
        files.extend(self._generate_database(src_dir, config, dry_run))
        files.extend(self._generate_models(src_dir, config, dry_run))
        files.extend(self._generate_schemas(src_dir, config, dry_run))
        files.extend(self._generate_routers(src_dir, config, dry_run))
        files.extend(self._generate_auth(src_dir, config, dry_run))
        files.extend(self._generate_tests(tests_dir, config, dry_run))
        files.extend(self._generate_project_files(output_dir, config, openapi_spec, dry_run))

        return files

    def _generate_main(
        self,
        src_dir: Path,
        config: dict[str, Any],
        dry_run: bool,
    ) -> list[str]:
        """Generate main.py."""
        entities = list(config.get("entities", {}).keys())
        router_imports = "\n".join(
            f"from .routers import {e.lower()}s" for e in entities
        )
        router_includes = "\n".join(
            f'app.include_router({e.lower()}s.router, prefix="/{e.lower()}s", tags=["{e}"])'
            for e in entities
        )

        content = f'''"""FastAPI application."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import engine, Base
{router_imports}
from .routers import auth


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    # Shutdown
    await engine.dispose()


app = FastAPI(
    title="{config.get("name", "API")}",
    version="{config.get("version", "1.0.0")}",
    description="""{config.get("description", "")}""",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
{router_includes}


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {{"status": "healthy"}}
'''

        path = src_dir / "main.py"
        self.write_file(path, content, dry_run)
        return [str(path)]

    def _generate_config(
        self,
        src_dir: Path,
        config: dict[str, Any],
        dry_run: bool,
    ) -> list[str]:
        """Generate config.py."""
        settings = config.get("settings", {})
        db_type = settings.get("database", "postgresql")

        content = '''"""Application configuration."""

from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings."""

    # Database
    database_url: str = "''' + self._get_default_db_url(db_type) + '''"

    # JWT
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = ''' + str(self._parse_expiry(settings.get("auth", {}).get("expiry", "24h"))) + '''

    # CORS
    cors_origins: list[str] = ["http://localhost:3000"]

    # Rate limiting
    rate_limit_per_minute: int = ''' + str(self._parse_rate_limit(settings.get("rate_limiting", {}).get("default", "100/minute"))) + '''

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings."""
    return Settings()


settings = get_settings()
'''

        path = src_dir / "config.py"
        self.write_file(path, content, dry_run)

        # Also create __init__.py
        init_path = src_dir / "__init__.py"
        self.write_file(init_path, '"""API package."""\n', dry_run)

        return [str(path), str(init_path)]

    def _generate_database(
        self,
        src_dir: Path,
        config: dict[str, Any],
        dry_run: bool,
    ) -> list[str]:
        """Generate database.py."""
        content = '''"""Database configuration."""

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from .config import settings


# Create async engine
engine = create_async_engine(
    settings.database_url,
    echo=False,
    future=True,
)

# Session factory
async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Base class for models."""
    pass


async def get_db() -> AsyncSession:
    """Dependency for database session."""
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
'''

        path = src_dir / "database.py"
        self.write_file(path, content, dry_run)
        return [str(path)]

    def _generate_models(
        self,
        src_dir: Path,
        config: dict[str, Any],
        dry_run: bool,
    ) -> list[str]:
        """Generate SQLAlchemy models."""
        files = []
        models_dir = src_dir / "models"

        # Create __init__.py
        entities = list(config.get("entities", {}).keys())
        init_content = '"""Database models."""\n\n'
        init_content += "\n".join(
            f"from .{e.lower()} import {e}" for e in entities
        )
        init_content += "\n\n__all__ = [" + ", ".join(f'"{e}"' for e in entities) + "]\n"

        init_path = models_dir / "__init__.py"
        self.write_file(init_path, init_content, dry_run)
        files.append(str(init_path))

        # Generate model for each entity
        for entity_name, entity_config in config.get("entities", {}).items():
            content = self._generate_model_file(entity_name, entity_config)
            path = models_dir / f"{entity_name.lower()}.py"
            self.write_file(path, content, dry_run)
            files.append(str(path))

        return files

    def _generate_model_file(
        self,
        entity_name: str,
        entity_config: dict[str, Any],
    ) -> str:
        """Generate a single model file."""
        imports = {
            "from datetime import datetime",
            "from sqlalchemy import Column, Integer, String, DateTime",
            "from ..database import Base",
        }

        columns = [
            "    id = Column(Integer, primary_key=True, index=True)",
        ]

        for field in entity_config.get("fields", []):
            field_name = field["name"]
            field_type = field.get("type", "string")
            sa_type = self.SQLALCHEMY_TYPE_MAPPING.get(field_type, "String(255)")

            # Add necessary imports
            if "Boolean" in sa_type:
                imports.add("from sqlalchemy import Boolean")
            if "Text" in sa_type:
                imports.add("from sqlalchemy import Text")
            if "Float" in sa_type:
                imports.add("from sqlalchemy import Float")
            if "Date" in sa_type and "DateTime" not in sa_type:
                imports.add("from sqlalchemy import Date")
            if "UUID" in sa_type:
                imports.add("from sqlalchemy.dialects.postgresql import UUID")
                imports.add("import uuid")

            constraints = []
            if field.get("unique"):
                constraints.append("unique=True")
            if not field.get("required"):
                constraints.append("nullable=True")
            if field.get("default") is not None:
                default_val = field["default"]
                if isinstance(default_val, bool):
                    constraints.append(f"default={default_val}")
                elif isinstance(default_val, (int, float)):
                    constraints.append(f"default={default_val}")
                else:
                    constraints.append(f'default="{default_val}"')

            constraint_str = ", ".join(constraints)
            if constraint_str:
                columns.append(f"    {field_name} = Column({sa_type}, {constraint_str})")
            else:
                columns.append(f"    {field_name} = Column({sa_type})")

        # Add timestamps
        columns.append("    created_at = Column(DateTime, default=datetime.utcnow)")
        columns.append("    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)")

        return f'''"""{entity_name} model."""

{chr(10).join(sorted(imports))}


class {entity_name}(Base):
    """SQLAlchemy model for {entity_name}."""

    __tablename__ = "{entity_name.lower()}s"

{chr(10).join(columns)}

    def __repr__(self) -> str:
        return f"<{entity_name}(id={{self.id}})>"
'''

    def _generate_schemas(
        self,
        src_dir: Path,
        config: dict[str, Any],
        dry_run: bool,
    ) -> list[str]:
        """Generate Pydantic schemas."""
        files = []
        schemas_dir = src_dir / "schemas"

        # Create __init__.py
        entities = list(config.get("entities", {}).keys())
        init_content = '"""Pydantic schemas."""\n\n'
        for e in entities:
            init_content += f"from .{e.lower()} import {e}Base, {e}Create, {e}Update, {e}Response\n"
        init_path = schemas_dir / "__init__.py"
        self.write_file(init_path, init_content, dry_run)
        files.append(str(init_path))

        # Generate schema for each entity
        for entity_name, entity_config in config.get("entities", {}).items():
            content = self._generate_schema_file(entity_name, entity_config)
            path = schemas_dir / f"{entity_name.lower()}.py"
            self.write_file(path, content, dry_run)
            files.append(str(path))

        return files

    def _generate_schema_file(
        self,
        entity_name: str,
        entity_config: dict[str, Any],
    ) -> str:
        """Generate a single schema file."""
        imports = {
            "from datetime import datetime",
            "from pydantic import BaseModel, ConfigDict",
        }

        base_fields = []
        for field in entity_config.get("fields", []):
            field_name = field["name"]
            field_type = field.get("type", "string")
            py_type = self.PYTHON_TYPE_MAPPING.get(field_type, "str")

            if py_type == "EmailStr":
                imports.add("from pydantic import EmailStr")
            elif py_type == "HttpUrl":
                imports.add("from pydantic import HttpUrl")
            elif py_type == "UUID":
                imports.add("from uuid import UUID")
            elif py_type in ("datetime", "date"):
                imports.add(f"from datetime import {py_type}")

            if field.get("required"):
                base_fields.append(f"    {field_name}: {py_type}")
            else:
                default = field.get("default")
                if default is None:
                    base_fields.append(f"    {field_name}: {py_type} | None = None")
                else:
                    base_fields.append(f"    {field_name}: {py_type} = {repr(default)}")

        return f'''"""{entity_name} schemas."""

{chr(10).join(sorted(imports))}


class {entity_name}Base(BaseModel):
    """Base schema for {entity_name}."""

{chr(10).join(base_fields) if base_fields else "    pass"}


class {entity_name}Create({entity_name}Base):
    """Schema for creating {entity_name}."""
    pass


class {entity_name}Update(BaseModel):
    """Schema for updating {entity_name}."""

{chr(10).join(f.replace(": ", ": ", 1).replace(f.split(":")[1].strip().split()[0], f.split(":")[1].strip().split()[0] + " | None = None") if ": " in f and "None" not in f else f for f in base_fields) if base_fields else "    pass"}


class {entity_name}Response({entity_name}Base):
    """Schema for {entity_name} response."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime
'''

    def _generate_routers(
        self,
        src_dir: Path,
        config: dict[str, Any],
        dry_run: bool,
    ) -> list[str]:
        """Generate API routers."""
        files = []
        routers_dir = src_dir / "routers"

        # Create __init__.py
        init_path = routers_dir / "__init__.py"
        self.write_file(init_path, '"""API routers."""\n', dry_run)
        files.append(str(init_path))

        # Generate router for each entity
        for entity_name in config.get("entities", {}).keys():
            content = self._generate_router_file(entity_name)
            path = routers_dir / f"{entity_name.lower()}s.py"
            self.write_file(path, content, dry_run)
            files.append(str(path))

        return files

    def _generate_router_file(self, entity_name: str) -> str:
        """Generate a single router file."""
        lower = entity_name.lower()
        return f'''"""{entity_name} router."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models.{lower} import {entity_name}
from ..schemas.{lower} import {entity_name}Create, {entity_name}Update, {entity_name}Response
from ..auth.dependencies import get_current_user

router = APIRouter()


@router.get("/", response_model=dict)
async def list_{lower}s(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """List all {lower}s with pagination."""
    offset = (page - 1) * size

    # Get total count
    count_query = select(func.count()).select_from({entity_name})
    total = await db.scalar(count_query)

    # Get items
    query = select({entity_name}).offset(offset).limit(size)
    result = await db.execute(query)
    items = result.scalars().all()

    return {{
        "items": [{entity_name}Response.model_validate(item) for item in items],
        "total": total,
        "page": page,
        "size": size,
        "pages": (total + size - 1) // size if total else 0,
    }}


@router.post("/", response_model={entity_name}Response, status_code=201)
async def create_{lower}(
    data: {entity_name}Create,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Create a new {lower}."""
    item = {entity_name}(**data.model_dump())
    db.add(item)
    await db.flush()
    await db.refresh(item)
    return item


@router.get("/{{id}}", response_model={entity_name}Response)
async def get_{lower}(
    id: int,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Get a {lower} by ID."""
    query = select({entity_name}).where({entity_name}.id == id)
    result = await db.execute(query)
    item = result.scalar_one_or_none()

    if not item:
        raise HTTPException(status_code=404, detail="{entity_name} not found")

    return item


@router.put("/{{id}}", response_model={entity_name}Response)
async def update_{lower}(
    id: int,
    data: {entity_name}Update,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Update a {lower}."""
    query = select({entity_name}).where({entity_name}.id == id)
    result = await db.execute(query)
    item = result.scalar_one_or_none()

    if not item:
        raise HTTPException(status_code=404, detail="{entity_name} not found")

    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(item, field, value)

    await db.flush()
    await db.refresh(item)
    return item


@router.delete("/{{id}}", status_code=204)
async def delete_{lower}(
    id: int,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Delete a {lower}."""
    query = select({entity_name}).where({entity_name}.id == id)
    result = await db.execute(query)
    item = result.scalar_one_or_none()

    if not item:
        raise HTTPException(status_code=404, detail="{entity_name} not found")

    await db.delete(item)
    return None
'''

    def _generate_auth(
        self,
        src_dir: Path,
        config: dict[str, Any],
        dry_run: bool,
    ) -> list[str]:
        """Generate authentication module."""
        files = []
        auth_dir = src_dir / "auth"

        # __init__.py
        init_path = auth_dir / "__init__.py"
        self.write_file(init_path, '"""Authentication module."""\n', dry_run)
        files.append(str(init_path))

        # jwt.py
        jwt_content = '''"""JWT token handling."""

from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

from ..config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash."""
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.jwt_expire_minutes))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict | None:
    """Decode a JWT token."""
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        return payload
    except JWTError:
        return None
'''
        jwt_path = auth_dir / "jwt.py"
        self.write_file(jwt_path, jwt_content, dry_run)
        files.append(str(jwt_path))

        # dependencies.py
        deps_content = '''"""Authentication dependencies."""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .jwt import decode_token

security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    """Get the current authenticated user."""
    token = credentials.credentials
    payload = decode_token(token)

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload
'''
        deps_path = auth_dir / "dependencies.py"
        self.write_file(deps_path, deps_content, dry_run)
        files.append(str(deps_path))

        # router for auth
        auth_router_content = '''"""Authentication router."""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr

from .jwt import hash_password, verify_password, create_access_token

router = APIRouter()


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.post("/login", response_model=TokenResponse)
async def login(data: LoginRequest):
    """Login and get access token."""
    # TODO: Implement actual user lookup
    # This is a placeholder - implement your user verification logic
    if data.email == "admin@example.com" and data.password == "password":
        token = create_access_token({"sub": data.email, "user_id": 1})
        return TokenResponse(access_token=token)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
    )
'''
        auth_router_path = src_dir / "routers" / "auth.py"
        self.write_file(auth_router_path, auth_router_content, dry_run)
        files.append(str(auth_router_path))

        return files

    def _generate_tests(
        self,
        tests_dir: Path,
        config: dict[str, Any],
        dry_run: bool,
    ) -> list[str]:
        """Generate test files."""
        files = []

        # conftest.py
        conftest_content = '''"""Test configuration."""

import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from src.main import app
from src.database import Base, get_db


# Test database
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"
engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def override_get_db():
    async with TestSessionLocal() as session:
        yield session


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="function")
async def client():
    """Create test client."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
def auth_headers():
    """Get auth headers for testing."""
    from src.auth.jwt import create_access_token
    token = create_access_token({"sub": "test@example.com", "user_id": 1})
    return {"Authorization": f"Bearer {token}"}
'''
        conftest_path = tests_dir / "conftest.py"
        self.write_file(conftest_path, conftest_content, dry_run)
        files.append(str(conftest_path))

        # __init__.py
        init_path = tests_dir / "__init__.py"
        self.write_file(init_path, '"""Tests package."""\n', dry_run)
        files.append(str(init_path))

        # test_health.py
        health_test = '''"""Health check tests."""

import pytest


@pytest.mark.asyncio
async def test_health_check(client):
    """Test health endpoint."""
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}
'''
        health_path = tests_dir / "test_health.py"
        self.write_file(health_path, health_test, dry_run)
        files.append(str(health_path))

        return files

    def _generate_project_files(
        self,
        output_dir: Path,
        config: dict[str, Any],
        openapi_spec: dict[str, Any],
        dry_run: bool,
    ) -> list[str]:
        """Generate project configuration files."""
        files = []

        # requirements.txt
        requirements = '''fastapi>=0.109.0
uvicorn[standard]>=0.27.0
sqlalchemy[asyncio]>=2.0.0
asyncpg>=0.29.0
aiosqlite>=0.19.0
pydantic>=2.0.0
pydantic-settings>=2.0.0
python-jose[cryptography]>=3.3.0
passlib[bcrypt]>=1.7.4
python-multipart>=0.0.6
httpx>=0.26.0
'''
        req_path = output_dir / "requirements.txt"
        self.write_file(req_path, requirements, dry_run)
        files.append(str(req_path))

        # .env.example
        env_example = '''# Database
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/dbname

# JWT
JWT_SECRET=change-me-in-production

# CORS
CORS_ORIGINS=["http://localhost:3000"]
'''
        env_path = output_dir / ".env.example"
        self.write_file(env_path, env_example, dry_run)
        files.append(str(env_path))

        # openapi.yaml
        openapi_path = output_dir / "openapi.yaml"
        self.write_file(openapi_path, yaml.dump(openapi_spec, default_flow_style=False), dry_run)
        files.append(str(openapi_path))

        # Dockerfile
        dockerfile = '''FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
'''
        dockerfile_path = output_dir / "Dockerfile"
        self.write_file(dockerfile_path, dockerfile, dry_run)
        files.append(str(dockerfile_path))

        # docker-compose.yml
        compose = '''version: "3.8"

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql+asyncpg://postgres:postgres@db:5432/app
      - JWT_SECRET=${JWT_SECRET:-change-me}
    depends_on:
      - db

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=app
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

volumes:
  postgres_data:
'''
        compose_path = output_dir / "docker-compose.yml"
        self.write_file(compose_path, compose, dry_run)
        files.append(str(compose_path))

        # .gitignore
        gitignore = '''__pycache__/
*.py[cod]
*$py.class
.env
.venv/
venv/
*.db
.pytest_cache/
.coverage
htmlcov/
dist/
*.egg-info/
'''
        gitignore_path = output_dir / ".gitignore"
        self.write_file(gitignore_path, gitignore, dry_run)
        files.append(str(gitignore_path))

        return files

    def _get_default_db_url(self, db_type: str) -> str:
        """Get default database URL."""
        urls = {
            "postgresql": "postgresql+asyncpg://user:password@localhost:5432/dbname",
            "mysql": "mysql+aiomysql://user:password@localhost:3306/dbname",
            "sqlite": "sqlite+aiosqlite:///./app.db",
        }
        return urls.get(db_type, urls["postgresql"])

    def _parse_expiry(self, expiry: str) -> int:
        """Parse expiry string to minutes."""
        if expiry.endswith("h"):
            return int(expiry[:-1]) * 60
        elif expiry.endswith("m"):
            return int(expiry[:-1])
        elif expiry.endswith("d"):
            return int(expiry[:-1]) * 60 * 24
        return 60 * 24  # default 24h

    def _parse_rate_limit(self, rate: str) -> int:
        """Parse rate limit string."""
        if "/" in rate:
            return int(rate.split("/")[0])
        return 100
