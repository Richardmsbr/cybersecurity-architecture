# API Security Architecture

## Executive Summary

This document provides comprehensive security guidelines for API development and deployment. It covers authentication, authorization, input validation, rate limiting, and protection against OWASP API Security Top 10 vulnerabilities.

---

## Table of Contents

1. [OWASP API Security Top 10](#owasp-api-security-top-10)
2. [Authentication Mechanisms](#authentication-mechanisms)
3. [Authorization Patterns](#authorization-patterns)
4. [Input Validation](#input-validation)
5. [Rate Limiting and Throttling](#rate-limiting-and-throttling)
6. [API Gateway Security](#api-gateway-security)
7. [Transport Security](#transport-security)
8. [Logging and Monitoring](#logging-and-monitoring)
9. [API Versioning Security](#api-versioning-security)
10. [Implementation Examples](#implementation-examples)

---

## OWASP API Security Top 10

### API1:2023 - Broken Object Level Authorization (BOLA)

**Description**: APIs expose endpoints that handle object identifiers, creating a wide attack surface for Object Level Access Control issues. Authorization checks should validate that the logged-in user has permission to perform the requested action on the requested object.

**Attack Scenarios**:
```http
# Attacker modifies order_id to access other users' orders
GET /api/orders/12345
Authorization: Bearer <attacker_token>

# Original request was for order 99999, but attacker changes to 12345
```

**Prevention**:

```python
# Python/FastAPI Example
from fastapi import Depends, HTTPException, status

async def get_order(order_id: int, current_user: User = Depends(get_current_user)):
    order = await Order.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    # BOLA Prevention: Verify ownership
    if order.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=403,
            detail="Not authorized to access this resource"
        )
    return order
```

```javascript
// Node.js/Express Example
const getOrder = async (req, res, next) => {
    const order = await Order.findById(req.params.orderId);

    // BOLA Prevention
    if (!order) {
        return res.status(404).json({ error: 'Order not found' });
    }

    if (order.userId.toString() !== req.user.id && !req.user.isAdmin) {
        return res.status(403).json({ error: 'Access denied' });
    }

    res.json(order);
};
```

**Security Controls**:
- Implement authorization checks at every object access
- Use random, unpredictable identifiers (UUIDs) instead of sequential IDs
- Write unit tests specifically for authorization logic
- Implement row-level security at the database level

---

### API2:2023 - Broken Authentication

**Description**: Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or exploit implementation flaws to assume other users' identities.

**Attack Scenarios**:
```http
# Credential stuffing attack
POST /api/login
Content-Type: application/json

{"email": "user@example.com", "password": "password123"}
# Attacker tries thousands of credential pairs
```

**Prevention**:

```python
# Secure authentication implementation
from passlib.context import CryptContext
from datetime import datetime, timedelta
import secrets

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

class AuthService:
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = timedelta(minutes=15)

    async def authenticate(self, email: str, password: str, ip: str) -> Token:
        # Check for account lockout
        if await self.is_locked_out(email):
            raise AuthException("Account temporarily locked")

        user = await User.get_by_email(email)

        if not user or not pwd_context.verify(password, user.hashed_password):
            await self.record_failed_attempt(email, ip)
            # Use generic message to prevent user enumeration
            raise AuthException("Invalid credentials")

        # Clear failed attempts on success
        await self.clear_failed_attempts(email)

        # Generate secure token
        return self.create_access_token(user)

    def create_access_token(self, user: User) -> Token:
        token = secrets.token_urlsafe(32)
        expires = datetime.utcnow() + timedelta(hours=1)

        return Token(
            access_token=token,
            token_type="bearer",
            expires_at=expires,
            user_id=user.id
        )
```

**Security Controls**:
- Use strong password hashing (Argon2, bcrypt)
- Implement account lockout after failed attempts
- Use secure, random tokens (minimum 128 bits entropy)
- Implement token rotation and expiration
- Require MFA for sensitive operations

---

### API3:2023 - Broken Object Property Level Authorization

**Description**: APIs may expose object properties that users should not be able to access or modify. This includes mass assignment vulnerabilities and excessive data exposure.

**Attack Scenarios**:
```http
# Mass assignment attack
PUT /api/users/123
Content-Type: application/json

{
    "name": "John Doe",
    "email": "john@example.com",
    "role": "admin",          # Attacker adds admin role
    "account_balance": 999999  # Attacker modifies balance
}
```

**Prevention**:

```python
# Use explicit field allowlists
from pydantic import BaseModel
from typing import Optional

# Define separate models for input vs output
class UserUpdateRequest(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    # role and account_balance NOT included - cannot be modified

class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    # Sensitive fields excluded from response

    class Config:
        # Only include explicitly defined fields
        extra = "forbid"

@app.put("/users/{user_id}")
async def update_user(
    user_id: int,
    update: UserUpdateRequest,  # Only allows name and email
    current_user: User = Depends(get_current_user)
):
    # Verify user can only update their own profile
    if user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403)

    # Update only allowed fields
    await User.filter(id=user_id).update(**update.dict(exclude_unset=True))
```

```javascript
// Node.js - Field allowlist approach
const allowedFields = ['name', 'email', 'phone'];

const updateUser = async (req, res) => {
    // Filter request body to only allowed fields
    const updates = {};
    allowedFields.forEach(field => {
        if (req.body[field] !== undefined) {
            updates[field] = req.body[field];
        }
    });

    // Apply updates
    await User.findByIdAndUpdate(req.params.id, updates);
    res.json({ message: 'Updated successfully' });
};
```

**Security Controls**:
- Define explicit input schemas with allowlists
- Use separate DTOs for read/write operations
- Never expose internal object properties
- Implement field-level access control

---

### API4:2023 - Unrestricted Resource Consumption

**Description**: APIs often don't impose restrictions on the size or number of resources that can be requested, leading to DoS vulnerabilities.

**Attack Scenarios**:
```http
# Request causes expensive database query
GET /api/users?limit=1000000

# Request large file upload
POST /api/upload
Content-Length: 10737418240  # 10GB file

# GraphQL batching attack
POST /api/graphql
{
    "query": "{ user(id: 1) { orders { items { product { reviews }}}}}",
    "variables": {}
}
# Deep nested query causing N+1 queries
```

**Prevention**:

```python
# Rate limiting and resource constraints
from fastapi import Query, UploadFile
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

# Pagination limits
MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 20

@app.get("/users")
@limiter.limit("100/minute")
async def list_users(
    request: Request,
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE)
):
    offset = (page - 1) * limit
    users = await User.all().offset(offset).limit(limit)
    return users

# File upload limits
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

@app.post("/upload")
async def upload_file(file: UploadFile):
    # Check file size before reading
    file.file.seek(0, 2)  # Seek to end
    size = file.file.tell()
    file.file.seek(0)  # Reset

    if size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size: {MAX_FILE_SIZE} bytes"
        )

    content = await file.read()
    # Process file...
```

```python
# GraphQL query complexity limiting
from graphql import GraphQLError

class ComplexityAnalyzer:
    MAX_COMPLEXITY = 1000
    MAX_DEPTH = 10

    def analyze(self, query, variables):
        complexity = self.calculate_complexity(query)
        depth = self.calculate_depth(query)

        if complexity > self.MAX_COMPLEXITY:
            raise GraphQLError(
                f"Query too complex: {complexity} > {self.MAX_COMPLEXITY}"
            )

        if depth > self.MAX_DEPTH:
            raise GraphQLError(
                f"Query too deep: {depth} > {self.MAX_DEPTH}"
            )
```

**Security Controls**:
- Implement rate limiting per user/IP
- Set maximum pagination limits
- Limit file upload sizes
- Implement query complexity analysis for GraphQL
- Set timeouts for all operations

---

### API5:2023 - Broken Function Level Authorization

**Description**: APIs with complex access control policies can have flaws in function-level authorization, allowing users to access administrative functions.

**Attack Scenarios**:
```http
# Regular user tries to access admin endpoint
DELETE /api/admin/users/123
Authorization: Bearer <regular_user_token>

# Accessing hidden admin functions
POST /api/users/123/promote
Authorization: Bearer <regular_user_token>
```

**Prevention**:

```python
# Role-based access control implementation
from enum import Enum
from functools import wraps

class Role(Enum):
    USER = "user"
    MODERATOR = "moderator"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"

# Role hierarchy
ROLE_HIERARCHY = {
    Role.USER: [Role.USER],
    Role.MODERATOR: [Role.USER, Role.MODERATOR],
    Role.ADMIN: [Role.USER, Role.MODERATOR, Role.ADMIN],
    Role.SUPER_ADMIN: [Role.USER, Role.MODERATOR, Role.ADMIN, Role.SUPER_ADMIN]
}

def require_role(required_role: Role):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get current user from request context
            current_user = kwargs.get('current_user')

            if not current_user:
                raise HTTPException(status_code=401)

            user_role = Role(current_user.role)
            allowed_roles = ROLE_HIERARCHY.get(user_role, [])

            if required_role not in allowed_roles:
                # Log unauthorized access attempt
                logger.warning(
                    f"Unauthorized access attempt: user={current_user.id}, "
                    f"required_role={required_role}, user_role={user_role}"
                )
                raise HTTPException(status_code=403)

            return await func(*args, **kwargs)
        return wrapper
    return decorator

# Usage
@app.delete("/admin/users/{user_id}")
@require_role(Role.ADMIN)
async def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_user)
):
    await User.filter(id=user_id).delete()
    return {"message": "User deleted"}
```

**Security Controls**:
- Implement centralized authorization middleware
- Deny by default, explicitly allow
- Audit all authorization decisions
- Separate admin APIs from user APIs
- Use role-based or attribute-based access control

---

### API6:2023 - Unrestricted Access to Sensitive Business Flows

**Description**: APIs may expose business flows that can be exploited when accessed in an automated manner, such as purchasing items in bulk or creating fake accounts.

**Attack Scenarios**:
```http
# Automated ticket scalping
POST /api/tickets/purchase
# Bot purchases all available tickets instantly

# Coupon abuse
POST /api/coupons/redeem
# Automated redemption across multiple accounts
```

**Prevention**:

```python
# Business flow protection
import hashlib
import time
from typing import Optional

class BusinessFlowProtection:
    def __init__(self, redis_client):
        self.redis = redis_client

    async def check_purchase_velocity(
        self,
        user_id: int,
        product_id: int,
        max_purchases: int = 2,
        window_seconds: int = 3600
    ) -> bool:
        key = f"purchase:{user_id}:{product_id}"
        current = await self.redis.incr(key)

        if current == 1:
            await self.redis.expire(key, window_seconds)

        return current <= max_purchases

    async def require_human_verification(
        self,
        user_id: int,
        action: str
    ) -> bool:
        # Check if user behavior is suspicious
        risk_score = await self.calculate_risk_score(user_id, action)

        if risk_score > 0.7:
            # Require CAPTCHA or additional verification
            return True
        return False

    async def calculate_risk_score(
        self,
        user_id: int,
        action: str
    ) -> float:
        # Factors: request velocity, account age, behavior patterns
        factors = []

        # Request velocity
        velocity = await self.get_request_velocity(user_id)
        factors.append(min(velocity / 100, 1.0))

        # Account age (newer accounts are riskier)
        account_age = await self.get_account_age_days(user_id)
        factors.append(max(0, 1 - (account_age / 30)))

        # Historical behavior
        abuse_history = await self.get_abuse_history(user_id)
        factors.append(abuse_history)

        return sum(factors) / len(factors)

# Usage in endpoint
@app.post("/tickets/purchase")
async def purchase_ticket(
    ticket_id: int,
    current_user: User = Depends(get_current_user),
    protection: BusinessFlowProtection = Depends()
):
    # Check velocity limits
    if not await protection.check_purchase_velocity(
        current_user.id,
        ticket_id
    ):
        raise HTTPException(
            status_code=429,
            detail="Purchase limit exceeded"
        )

    # Check if verification required
    if await protection.require_human_verification(
        current_user.id,
        "ticket_purchase"
    ):
        raise HTTPException(
            status_code=428,
            detail="Human verification required",
            headers={"X-Verify-URL": "/verify/captcha"}
        )

    # Process purchase
    return await process_purchase(ticket_id, current_user)
```

**Security Controls**:
- Implement velocity checks per user/action
- Use CAPTCHA for suspicious behavior
- Implement device fingerprinting
- Monitor for bot behavior patterns
- Add checkout friction for high-value items

---

### API7:2023 - Server Side Request Forgery (SSRF)

**Description**: SSRF flaws occur when an API fetches a remote resource without validating the user-supplied URL. This allows attackers to access internal services.

**Attack Scenarios**:
```http
# SSRF to access internal metadata
POST /api/fetch-url
Content-Type: application/json

{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

# SSRF to internal services
{"url": "http://internal-api.local:8080/admin/users"}
```

**Prevention**:

```python
import ipaddress
import socket
from urllib.parse import urlparse

class SSRFProtection:
    # Blocked IP ranges
    BLOCKED_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),  # AWS metadata
        ipaddress.ip_network('::1/128'),
        ipaddress.ip_network('fc00::/7'),
    ]

    ALLOWED_SCHEMES = ['http', 'https']
    ALLOWED_PORTS = [80, 443, 8080, 8443]

    @classmethod
    def validate_url(cls, url: str) -> bool:
        try:
            parsed = urlparse(url)

            # Check scheme
            if parsed.scheme not in cls.ALLOWED_SCHEMES:
                raise ValueError(f"Invalid scheme: {parsed.scheme}")

            # Check port
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            if port not in cls.ALLOWED_PORTS:
                raise ValueError(f"Invalid port: {port}")

            # Resolve hostname and check IP
            hostname = parsed.hostname
            if not hostname:
                raise ValueError("No hostname provided")

            # Resolve DNS to get IP
            ip_str = socket.gethostbyname(hostname)
            ip = ipaddress.ip_address(ip_str)

            # Check against blocked ranges
            for blocked in cls.BLOCKED_RANGES:
                if ip in blocked:
                    raise ValueError(f"IP {ip} is in blocked range")

            return True

        except socket.gaierror:
            raise ValueError(f"Cannot resolve hostname: {hostname}")
        except Exception as e:
            raise ValueError(f"URL validation failed: {str(e)}")

# Usage
@app.post("/fetch-url")
async def fetch_url(request: URLFetchRequest):
    # Validate URL before fetching
    try:
        SSRFProtection.validate_url(request.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Use timeout and size limits
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            request.url,
            follow_redirects=False  # Don't follow redirects
        )

        # Validate redirect URL if needed
        if response.is_redirect:
            redirect_url = response.headers.get('location')
            SSRFProtection.validate_url(redirect_url)

    return response.json()
```

**Security Controls**:
- Validate and sanitize all user-supplied URLs
- Block requests to private IP ranges
- Use allowlists for permitted domains
- Disable redirects or validate redirect targets
- Use separate network for outbound requests

---

### API8:2023 - Security Misconfiguration

**Description**: APIs and supporting systems may contain misconfigurations that can be exploited, including verbose error messages, unnecessary HTTP methods, and insecure defaults.

**Prevention**:

```python
# Secure FastAPI configuration
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

app = FastAPI(
    title="Secure API",
    docs_url=None if PRODUCTION else "/docs",  # Disable in production
    redoc_url=None if PRODUCTION else "/redoc",
    openapi_url=None if PRODUCTION else "/openapi.json",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com"],  # Specific origins only
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=["X-Request-ID"],
    max_age=600,
)

# Trusted hosts
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["api.example.com", "*.example.com"]
)

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response

# Error handling - never expose stack traces
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Log full error internally
    logger.exception(f"Unhandled exception: {exc}")

    # Return generic message to client
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )
```

**Security Headers Checklist**:

| Header | Value | Purpose |
|--------|-------|---------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Force HTTPS |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `Content-Security-Policy` | `default-src 'self'` | Prevent XSS |
| `Cache-Control` | `no-store` | Prevent caching sensitive data |
| `X-Request-ID` | `<uuid>` | Request tracing |

---

### API9:2023 - Improper Inventory Management

**Description**: APIs tend to expose more endpoints than traditional web applications. Proper documentation and inventory of hosts and API versions is important.

**Prevention**:

```yaml
# API inventory documentation (OpenAPI 3.0)
openapi: 3.0.3
info:
  title: Production API
  version: 2.0.0
  description: |
    ## API Lifecycle Status
    - **v1**: Deprecated (sunset: 2024-06-01)
    - **v2**: Current stable version
    - **v3-beta**: Preview (not for production)

  x-api-status: stable
  x-deprecation-date: null

servers:
  - url: https://api.example.com/v2
    description: Production
  - url: https://api-staging.example.com/v2
    description: Staging (internal only)

paths:
  /users:
    get:
      summary: List users
      x-internal: false
      x-rate-limit: 100/minute
```

```python
# API versioning implementation
from fastapi import APIRouter, Header

# Version routers
v1_router = APIRouter(prefix="/v1", deprecated=True)
v2_router = APIRouter(prefix="/v2")

# Version detection middleware
@app.middleware("http")
async def version_check(request: Request, call_next):
    # Warn about deprecated versions
    if request.url.path.startswith("/v1"):
        response = await call_next(request)
        response.headers["Deprecation"] = "true"
        response.headers["Sunset"] = "Sat, 01 Jun 2024 00:00:00 GMT"
        response.headers["Link"] = '</v2>; rel="successor-version"'
        return response

    return await call_next(request)
```

**Security Controls**:
- Maintain complete API inventory
- Document API lifecycle status
- Implement version deprecation headers
- Remove unused endpoints
- Separate internal and external APIs

---

### API10:2023 - Unsafe Consumption of APIs

**Description**: APIs may trust data from third-party APIs without proper validation, leading to security vulnerabilities when consuming external data.

**Prevention**:

```python
# Safe third-party API consumption
import httpx
from pydantic import BaseModel, validator
from typing import List

# Define expected response schema
class ThirdPartyUserResponse(BaseModel):
    id: int
    name: str
    email: str

    @validator('email')
    def validate_email(cls, v):
        if not '@' in v or len(v) > 254:
            raise ValueError('Invalid email format')
        return v

    @validator('name')
    def validate_name(cls, v):
        # Sanitize for XSS
        if any(char in v for char in ['<', '>', '"', "'"]):
            raise ValueError('Invalid characters in name')
        return v

class ThirdPartyClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.api_key = api_key
        self.client = httpx.AsyncClient(
            timeout=10.0,
            verify=True,  # Always verify SSL
            headers={
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "MyApp/1.0"
            }
        )

    async def get_users(self) -> List[ThirdPartyUserResponse]:
        try:
            response = await self.client.get(f"{self.base_url}/users")
            response.raise_for_status()

            data = response.json()

            # Validate each response item
            validated_users = []
            for user_data in data:
                try:
                    user = ThirdPartyUserResponse(**user_data)
                    validated_users.append(user)
                except ValidationError as e:
                    logger.warning(f"Invalid user data from API: {e}")
                    continue

            return validated_users

        except httpx.HTTPError as e:
            logger.error(f"Third-party API error: {e}")
            raise ExternalAPIError("Failed to fetch users")

# Usage
@app.get("/sync-users")
async def sync_users():
    client = ThirdPartyClient(
        base_url=settings.THIRD_PARTY_URL,
        api_key=settings.THIRD_PARTY_KEY
    )

    users = await client.get_users()  # Returns validated data

    for user in users:
        await User.update_or_create(
            external_id=user.id,
            defaults={
                "name": html.escape(user.name),  # Additional sanitization
                "email": user.email
            }
        )

    return {"synced": len(users)}
```

**Security Controls**:
- Validate all third-party API responses
- Use strict type checking
- Implement circuit breakers for external calls
- Log and monitor external API interactions
- Use HTTPS for all external communications

---

## Authentication Mechanisms

### JWT Implementation

```python
from datetime import datetime, timedelta
from jose import JWTError, jwt
from pydantic import BaseModel

class JWTConfig:
    SECRET_KEY: str = os.getenv("JWT_SECRET")  # Minimum 256 bits
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

class TokenPayload(BaseModel):
    sub: str  # Subject (user ID)
    exp: datetime
    iat: datetime
    jti: str  # JWT ID for revocation
    type: str  # "access" or "refresh"

def create_tokens(user_id: str) -> dict:
    now = datetime.utcnow()

    # Access token
    access_payload = {
        "sub": user_id,
        "exp": now + timedelta(minutes=JWTConfig.ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": now,
        "jti": str(uuid.uuid4()),
        "type": "access"
    }
    access_token = jwt.encode(
        access_payload,
        JWTConfig.SECRET_KEY,
        algorithm=JWTConfig.ALGORITHM
    )

    # Refresh token
    refresh_payload = {
        "sub": user_id,
        "exp": now + timedelta(days=JWTConfig.REFRESH_TOKEN_EXPIRE_DAYS),
        "iat": now,
        "jti": str(uuid.uuid4()),
        "type": "refresh"
    }
    refresh_token = jwt.encode(
        refresh_payload,
        JWTConfig.SECRET_KEY,
        algorithm=JWTConfig.ALGORITHM
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

async def verify_token(token: str, expected_type: str = "access") -> TokenPayload:
    try:
        payload = jwt.decode(
            token,
            JWTConfig.SECRET_KEY,
            algorithms=[JWTConfig.ALGORITHM]
        )

        token_data = TokenPayload(**payload)

        # Verify token type
        if token_data.type != expected_type:
            raise JWTError("Invalid token type")

        # Check if token is revoked
        if await is_token_revoked(token_data.jti):
            raise JWTError("Token has been revoked")

        return token_data

    except JWTError as e:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )
```

### OAuth 2.0 / OpenID Connect

```python
from authlib.integrations.starlette_client import OAuth

oauth = OAuth()

oauth.register(
    name='google',
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'prompt': 'consent',
    }
)

@app.get('/auth/google')
async def google_login(request: Request):
    redirect_uri = request.url_for('google_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get('/auth/google/callback')
async def google_callback(request: Request):
    token = await oauth.google.authorize_access_token(request)

    # Verify ID token
    user_info = token.get('userinfo')
    if not user_info:
        raise HTTPException(status_code=400, detail="Failed to get user info")

    # Create or update user
    user = await User.get_or_create(
        email=user_info['email'],
        defaults={
            'name': user_info.get('name'),
            'picture': user_info.get('picture'),
            'oauth_provider': 'google'
        }
    )

    # Generate our own tokens
    return create_tokens(str(user.id))
```

### API Key Authentication

```python
from hashlib import sha256
from secrets import compare_digest

class APIKeyAuth:
    async def authenticate(self, api_key: str) -> Optional[APIClient]:
        # Hash the provided key
        key_hash = sha256(api_key.encode()).hexdigest()

        # Look up by hash (never store plain keys)
        client = await APIClient.get_by_key_hash(key_hash)

        if not client:
            return None

        # Check if key is active
        if not client.is_active:
            return None

        # Check expiration
        if client.expires_at and client.expires_at < datetime.utcnow():
            return None

        # Update last used
        await client.update(last_used_at=datetime.utcnow())

        return client

# API key generation
def generate_api_key(client_id: str) -> tuple[str, str]:
    """Returns (plain_key, hashed_key)"""
    # Generate secure random key
    plain_key = f"sk_{client_id}_{secrets.token_urlsafe(32)}"
    hashed_key = sha256(plain_key.encode()).hexdigest()

    return plain_key, hashed_key
```

---

## Rate Limiting and Throttling

### Sliding Window Rate Limiter

```python
import time
from redis import Redis

class SlidingWindowRateLimiter:
    def __init__(self, redis: Redis, window_size: int = 60):
        self.redis = redis
        self.window_size = window_size

    async def is_allowed(
        self,
        key: str,
        limit: int
    ) -> tuple[bool, dict]:
        now = time.time()
        window_start = now - self.window_size

        pipe = self.redis.pipeline()

        # Remove old entries
        pipe.zremrangebyscore(key, 0, window_start)

        # Count current entries
        pipe.zcard(key)

        # Add current request
        pipe.zadd(key, {str(now): now})

        # Set expiration
        pipe.expire(key, self.window_size)

        results = await pipe.execute()
        current_count = results[1]

        allowed = current_count < limit

        headers = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(max(0, limit - current_count - 1)),
            "X-RateLimit-Reset": str(int(now + self.window_size))
        }

        if not allowed:
            headers["Retry-After"] = str(self.window_size)

        return allowed, headers

# Usage
rate_limiter = SlidingWindowRateLimiter(redis_client)

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # Different limits for different endpoints
    if request.url.path.startswith("/api/public"):
        limit = 100
    else:
        limit = 1000

    key = f"ratelimit:{request.client.host}:{request.url.path}"
    allowed, headers = await rate_limiter.is_allowed(key, limit)

    if not allowed:
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many requests"},
            headers=headers
        )

    response = await call_next(request)
    for header, value in headers.items():
        response.headers[header] = value

    return response
```

---

## Logging and Monitoring

### Security Event Logging

```python
import structlog
from datetime import datetime

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
)

logger = structlog.get_logger()

class SecurityEventLogger:
    @staticmethod
    def log_auth_success(user_id: str, ip: str, user_agent: str):
        logger.info(
            "authentication_success",
            event_type="auth.success",
            user_id=user_id,
            ip_address=ip,
            user_agent=user_agent,
            timestamp=datetime.utcnow().isoformat()
        )

    @staticmethod
    def log_auth_failure(email: str, ip: str, reason: str):
        logger.warning(
            "authentication_failure",
            event_type="auth.failure",
            email_hash=sha256(email.encode()).hexdigest()[:16],
            ip_address=ip,
            failure_reason=reason,
            timestamp=datetime.utcnow().isoformat()
        )

    @staticmethod
    def log_authorization_failure(
        user_id: str,
        resource: str,
        action: str,
        ip: str
    ):
        logger.warning(
            "authorization_failure",
            event_type="authz.failure",
            user_id=user_id,
            resource=resource,
            action=action,
            ip_address=ip,
            timestamp=datetime.utcnow().isoformat()
        )

    @staticmethod
    def log_suspicious_activity(
        user_id: str,
        activity_type: str,
        details: dict,
        ip: str
    ):
        logger.error(
            "suspicious_activity",
            event_type="security.suspicious",
            user_id=user_id,
            activity_type=activity_type,
            details=details,
            ip_address=ip,
            timestamp=datetime.utcnow().isoformat()
        )
```

### Monitoring Metrics

```python
from prometheus_client import Counter, Histogram, Gauge

# Request metrics
request_count = Counter(
    'api_requests_total',
    'Total API requests',
    ['method', 'endpoint', 'status']
)

request_latency = Histogram(
    'api_request_latency_seconds',
    'API request latency',
    ['method', 'endpoint'],
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
)

# Security metrics
auth_failures = Counter(
    'api_auth_failures_total',
    'Authentication failures',
    ['reason']
)

rate_limit_hits = Counter(
    'api_rate_limit_hits_total',
    'Rate limit hits',
    ['endpoint']
)

active_sessions = Gauge(
    'api_active_sessions',
    'Currently active sessions'
)

# Middleware to collect metrics
@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start_time = time.time()

    response = await call_next(request)

    duration = time.time() - start_time

    request_count.labels(
        method=request.method,
        endpoint=request.url.path,
        status=response.status_code
    ).inc()

    request_latency.labels(
        method=request.method,
        endpoint=request.url.path
    ).observe(duration)

    return response
```

---

## Implementation Checklist

### Pre-Production Security Review

- [ ] All endpoints require authentication (unless public)
- [ ] Object-level authorization implemented for all resources
- [ ] Field-level authorization for sensitive properties
- [ ] Input validation on all endpoints
- [ ] Rate limiting configured
- [ ] HTTPS enforced
- [ ] Security headers configured
- [ ] Error messages don't leak information
- [ ] Logging captures security events
- [ ] API documentation is current
- [ ] Deprecated endpoints have sunset dates
- [ ] Third-party API integrations validated

### Security Testing

- [ ] Authentication bypass testing
- [ ] BOLA/IDOR testing on all object endpoints
- [ ] Mass assignment testing
- [ ] Rate limit bypass testing
- [ ] SSRF testing on URL inputs
- [ ] SQL injection testing
- [ ] XSS testing on reflected content
- [ ] Business logic abuse testing

---

## References

- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [NIST SP 800-204 Security Strategies for Microservices](https://csrc.nist.gov/publications/detail/sp/800-204/final)
- [RFC 6749 - OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7519 - JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- [CWE API Security](https://cwe.mitre.org/data/definitions/1352.html)
