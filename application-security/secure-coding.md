# Secure Coding Guidelines

## Executive Summary

This document provides comprehensive secure coding guidelines for application development. It covers common vulnerabilities, prevention techniques, and best practices across multiple programming languages and frameworks.

---

## Table of Contents

1. [Input Validation](#input-validation)
2. [Output Encoding](#output-encoding)
3. [Authentication Security](#authentication-security)
4. [Session Management](#session-management)
5. [Access Control](#access-control)
6. [Cryptographic Practices](#cryptographic-practices)
7. [Error Handling and Logging](#error-handling-and-logging)
8. [Data Protection](#data-protection)
9. [File Operations](#file-operations)
10. [Database Security](#database-security)

---

## Input Validation

### Principles

1. **Validate all input** - Never trust client-side validation
2. **Whitelist over blacklist** - Define what is allowed, not what is forbidden
3. **Validate on server side** - Client validation is for UX only
4. **Fail securely** - Reject invalid input by default

### Implementation

```python
# Python - Using Pydantic for validation
from pydantic import BaseModel, validator, Field
from typing import Optional
import re

class UserRegistration(BaseModel):
    username: str = Field(..., min_length=3, max_length=30)
    email: str
    password: str = Field(..., min_length=12)
    phone: Optional[str] = None

    @validator('username')
    def username_alphanumeric(cls, v):
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Username must be alphanumeric')
        return v

    @validator('email')
    def email_valid(cls, v):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, v):
            raise ValueError('Invalid email format')
        if len(v) > 254:
            raise ValueError('Email too long')
        return v.lower()

    @validator('password')
    def password_strength(cls, v):
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain uppercase')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain lowercase')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain special character')
        return v

    @validator('phone')
    def phone_format(cls, v):
        if v is None:
            return v
        cleaned = re.sub(r'[\s\-\(\)]', '', v)
        if not re.match(r'^\+?[0-9]{10,15}$', cleaned):
            raise ValueError('Invalid phone number')
        return cleaned
```

```javascript
// JavaScript - Input sanitization
const sanitizeHtml = require('sanitize-html');
const validator = require('validator');

const sanitizeInput = {
    // Remove all HTML tags
    stripHtml: (input) => {
        return sanitizeHtml(input, {
            allowedTags: [],
            allowedAttributes: {}
        });
    },

    // Allow only specific HTML tags
    sanitizeRichText: (input) => {
        return sanitizeHtml(input, {
            allowedTags: ['b', 'i', 'em', 'strong', 'p', 'br'],
            allowedAttributes: {},
            disallowedTagsMode: 'discard'
        });
    },

    // Validate and sanitize email
    email: (input) => {
        if (!validator.isEmail(input)) {
            throw new Error('Invalid email');
        }
        return validator.normalizeEmail(input);
    },

    // Validate integer
    integer: (input, min = 0, max = Number.MAX_SAFE_INTEGER) => {
        const num = parseInt(input, 10);
        if (isNaN(num) || num < min || num > max) {
            throw new Error(`Invalid integer: must be between ${min} and ${max}`);
        }
        return num;
    },

    // Validate UUID
    uuid: (input) => {
        if (!validator.isUUID(input)) {
            throw new Error('Invalid UUID');
        }
        return input.toLowerCase();
    }
};
```

### Validation Patterns

| Data Type | Validation Rule | Example Regex |
|-----------|-----------------|---------------|
| Username | Alphanumeric, 3-30 chars | `^[a-zA-Z0-9_]{3,30}$` |
| Email | RFC 5322 format | Use library |
| Phone | E.164 format | `^\+?[0-9]{10,15}$` |
| URL | Valid URL format | Use library |
| UUID | UUID v4 format | `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$` |
| Date | ISO 8601 | `^\d{4}-\d{2}-\d{2}$` |
| Credit Card | Luhn algorithm | Use library |

---

## Output Encoding

### Context-Specific Encoding

```python
# HTML encoding
import html

def safe_html_output(user_input: str) -> str:
    return html.escape(user_input)

# For HTML attributes
def safe_attribute(user_input: str) -> str:
    return html.escape(user_input, quote=True)
```

```javascript
// JavaScript - Context-aware encoding
const encode = {
    // HTML body context
    html: (str) => {
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;');
    },

    // URL parameter context
    url: (str) => {
        return encodeURIComponent(str);
    },

    // JavaScript string context
    js: (str) => {
        return str
            .replace(/\\/g, '\\\\')
            .replace(/'/g, "\\'")
            .replace(/"/g, '\\"')
            .replace(/\n/g, '\\n')
            .replace(/\r/g, '\\r');
    },

    // CSS context
    css: (str) => {
        return str.replace(/[^a-zA-Z0-9]/g, (char) => {
            return '\\' + char.charCodeAt(0).toString(16) + ' ';
        });
    }
};
```

### Framework Examples

```python
# Django - Auto-escaping
from django.utils.html import escape, mark_safe

# Template: {{ user_input }} - Auto-escaped
# Template: {{ user_input|safe }} - Only when you trust the input

# Flask/Jinja2 - Auto-escaping enabled
from markupsafe import escape
@app.route('/user/<name>')
def user(name):
    return f"Hello, {escape(name)}"
```

---

## Authentication Security

### Password Storage

```python
# Python - Argon2 password hashing
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

class SecurePasswordHandler:
    def __init__(self):
        self.hasher = PasswordHasher(
            time_cost=3,        # Number of iterations
            memory_cost=65536,  # 64 MB
            parallelism=4,      # Parallel threads
            hash_len=32,        # Output length
            salt_len=16         # Salt length
        )

    def hash_password(self, password: str) -> str:
        return self.hasher.hash(password)

    def verify_password(self, stored_hash: str, password: str) -> bool:
        try:
            self.hasher.verify(stored_hash, password)
            # Check if rehash is needed (params changed)
            if self.hasher.check_needs_rehash(stored_hash):
                return True, self.hash_password(password)
            return True, None
        except VerifyMismatchError:
            return False, None
```

```python
# Python - bcrypt alternative
import bcrypt

def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed)
```

### Multi-Factor Authentication

```python
import pyotp
import qrcode
from io import BytesIO

class TOTPHandler:
    def __init__(self, issuer: str = "MyApp"):
        self.issuer = issuer

    def generate_secret(self) -> str:
        return pyotp.random_base32()

    def get_provisioning_uri(self, secret: str, email: str) -> str:
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=email,
            issuer_name=self.issuer
        )

    def generate_qr_code(self, secret: str, email: str) -> bytes:
        uri = self.get_provisioning_uri(secret, email)
        qr = qrcode.make(uri)
        buffer = BytesIO()
        qr.save(buffer, format='PNG')
        return buffer.getvalue()

    def verify_token(self, secret: str, token: str) -> bool:
        totp = pyotp.TOTP(secret)
        # Valid for current and previous time window
        return totp.verify(token, valid_window=1)
```

---

## Session Management

### Secure Session Configuration

```python
# Flask session security
from flask import Flask, session
from datetime import timedelta

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.urandom(32),
    SESSION_COOKIE_SECURE=True,      # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,    # No JavaScript access
    SESSION_COOKIE_SAMESITE='Lax',   # CSRF protection
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    SESSION_REFRESH_EACH_REQUEST=True
)
```

```javascript
// Express session security
const session = require('express-session');
const RedisStore = require('connect-redis').default;

app.use(session({
    store: new RedisStore({ client: redisClient }),
    secret: process.env.SESSION_SECRET,
    name: '__Host-session',  // Cookie prefix for extra security
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,        // HTTPS only
        httpOnly: true,      // No JavaScript access
        sameSite: 'lax',     // CSRF protection
        maxAge: 3600000,     // 1 hour
        path: '/',
        domain: undefined    // Current domain only
    }
}));
```

### Session Fixation Prevention

```python
from flask import session
from uuid import uuid4

def regenerate_session():
    """Regenerate session ID after authentication"""
    old_data = dict(session)
    session.clear()
    session.update(old_data)
    session['_id'] = str(uuid4())  # Force new session ID
    session.modified = True

@app.route('/login', methods=['POST'])
def login():
    if authenticate_user(request.form):
        regenerate_session()  # Prevent session fixation
        session['user_id'] = user.id
        session['authenticated_at'] = datetime.utcnow().isoformat()
        return redirect('/dashboard')
```

---

## Access Control

### Role-Based Access Control (RBAC)

```python
from functools import wraps
from enum import Enum, auto
from typing import Set

class Permission(Enum):
    READ_USERS = auto()
    WRITE_USERS = auto()
    DELETE_USERS = auto()
    READ_REPORTS = auto()
    ADMIN_ACCESS = auto()

class Role(Enum):
    USER = {Permission.READ_USERS}
    MANAGER = {Permission.READ_USERS, Permission.READ_REPORTS}
    ADMIN = {
        Permission.READ_USERS,
        Permission.WRITE_USERS,
        Permission.DELETE_USERS,
        Permission.READ_REPORTS,
        Permission.ADMIN_ACCESS
    }

def require_permission(*permissions: Permission):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                raise UnauthorizedException("Authentication required")

            user_permissions = Role[user.role].value
            required = set(permissions)

            if not required.issubset(user_permissions):
                raise ForbiddenException("Insufficient permissions")

            return func(*args, **kwargs)
        return wrapper
    return decorator

# Usage
@app.route('/admin/users', methods=['DELETE'])
@require_permission(Permission.DELETE_USERS)
def delete_user(user_id: int):
    # User already verified to have DELETE_USERS permission
    pass
```

### Attribute-Based Access Control (ABAC)

```python
from dataclasses import dataclass
from typing import Any, Callable

@dataclass
class Policy:
    name: str
    condition: Callable[[dict, dict, dict], bool]

class ABACEngine:
    def __init__(self):
        self.policies: list[Policy] = []

    def add_policy(self, name: str, condition: Callable):
        self.policies.append(Policy(name, condition))

    def check_access(
        self,
        subject: dict,   # User attributes
        resource: dict,  # Resource attributes
        action: dict     # Action being performed
    ) -> bool:
        for policy in self.policies:
            if policy.condition(subject, resource, action):
                return True
        return False

# Example policies
engine = ABACEngine()

# Users can read their own records
engine.add_policy(
    "own_records",
    lambda s, r, a: (
        a['type'] == 'read' and
        r.get('owner_id') == s.get('user_id')
    )
)

# Managers can read reports in their department
engine.add_policy(
    "department_reports",
    lambda s, r, a: (
        a['type'] == 'read' and
        r['type'] == 'report' and
        s.get('role') == 'manager' and
        r.get('department') == s.get('department')
    )
)

# Admins can do anything
engine.add_policy(
    "admin_access",
    lambda s, r, a: s.get('role') == 'admin'
)
```

---

## Cryptographic Practices

### Encryption

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Symmetric encryption with Fernet (AES-128-CBC + HMAC)
class FernetEncryption:
    def __init__(self, key: bytes = None):
        self.key = key or Fernet.generate_key()
        self.fernet = Fernet(self.key)

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.fernet.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.fernet.decrypt(ciphertext)

# AES-GCM for authenticated encryption
class AESGCMEncryption:
    def __init__(self, key: bytes = None):
        self.key = key or AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.key)

    def encrypt(self, plaintext: bytes, associated_data: bytes = b'') -> bytes:
        nonce = os.urandom(12)  # 96-bit nonce
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext

    def decrypt(self, data: bytes, associated_data: bytes = b'') -> bytes:
        nonce = data[:12]
        ciphertext = data[12:]
        return self.aesgcm.decrypt(nonce, ciphertext, associated_data)
```

### Secure Random Generation

```python
import secrets
import os

# Secure token generation
def generate_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)

# Secure password generation
def generate_password(length: int = 16) -> str:
    alphabet = (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*"
    )
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# Secure comparison (timing-safe)
def secure_compare(a: str, b: str) -> bool:
    return secrets.compare_digest(a, b)
```

### Key Management

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

class KeyDerivation:
    """Derive encryption keys from passwords"""

    @staticmethod
    def derive_key(
        password: str,
        salt: bytes = None,
        length: int = 32,
        iterations: int = 600000
    ) -> tuple[bytes, bytes]:
        salt = salt or os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=iterations,
        )

        key = kdf.derive(password.encode())
        return key, salt
```

---

## Error Handling and Logging

### Secure Error Handling

```python
import logging
from functools import wraps

logger = logging.getLogger(__name__)

class ApplicationError(Exception):
    """Base exception with safe message"""
    def __init__(self, message: str, internal_message: str = None):
        self.message = message  # Safe for users
        self.internal_message = internal_message or message  # For logs
        super().__init__(self.message)

class ValidationError(ApplicationError):
    pass

class AuthenticationError(ApplicationError):
    pass

def handle_errors(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ApplicationError as e:
            logger.warning(f"Application error: {e.internal_message}")
            return {"error": e.message}, 400
        except Exception as e:
            # Log full error internally
            logger.exception(f"Unexpected error: {e}")
            # Return generic message to user
            return {"error": "An unexpected error occurred"}, 500
    return wrapper
```

### Security Logging

```python
import structlog
from datetime import datetime

# Configure structured logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer()
    ]
)

log = structlog.get_logger()

class SecurityLogger:
    @staticmethod
    def authentication_attempt(
        email: str,
        success: bool,
        ip: str,
        user_agent: str
    ):
        log.info(
            "authentication_attempt",
            email_hash=hash(email),  # Don't log actual email
            success=success,
            ip_address=ip,
            user_agent=user_agent[:100],  # Truncate
            timestamp=datetime.utcnow().isoformat()
        )

    @staticmethod
    def sensitive_data_access(
        user_id: int,
        resource_type: str,
        resource_id: int,
        action: str
    ):
        log.info(
            "sensitive_data_access",
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            timestamp=datetime.utcnow().isoformat()
        )

    @staticmethod
    def security_violation(
        user_id: int,
        violation_type: str,
        details: dict
    ):
        log.error(
            "security_violation",
            user_id=user_id,
            violation_type=violation_type,
            details=details,
            timestamp=datetime.utcnow().isoformat()
        )
```

---

## Database Security

### SQL Injection Prevention

```python
# SQLAlchemy - Parameterized queries
from sqlalchemy import text

# NEVER do this:
# query = f"SELECT * FROM users WHERE email = '{email}'"

# Do this instead:
def get_user_by_email(email: str):
    query = text("SELECT * FROM users WHERE email = :email")
    result = db.execute(query, {"email": email})
    return result.fetchone()

# ORM approach (preferred)
def get_user_by_email_orm(email: str):
    return User.query.filter_by(email=email).first()
```

```python
# Django ORM - Safe by default
from django.db.models import Q

# Safe - uses parameterized queries
User.objects.filter(email=user_input)
User.objects.filter(Q(email=user_input) | Q(username=user_input))

# For raw queries, use params
User.objects.raw(
    "SELECT * FROM users WHERE email = %s",
    [user_input]
)

# NEVER use string formatting in raw queries
# User.objects.raw(f"SELECT * FROM users WHERE email = '{user_input}'")  # DANGEROUS
```

### Connection Security

```python
# PostgreSQL connection with SSL
import psycopg2

conn = psycopg2.connect(
    host="db.example.com",
    database="myapp",
    user="app_user",
    password=os.environ["DB_PASSWORD"],
    sslmode="verify-full",
    sslrootcert="/path/to/ca.crt"
)
```

---

## File Operations

### Secure File Upload

```python
import os
import hashlib
import magic
from pathlib import Path
from werkzeug.utils import secure_filename

class SecureFileUpload:
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
    ALLOWED_MIMES = {
        'image/png', 'image/jpeg', 'image/gif', 'application/pdf'
    }
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
    UPLOAD_DIR = Path("/var/uploads")

    @classmethod
    def validate_and_save(cls, file) -> str:
        # Check file size
        file.seek(0, 2)
        size = file.tell()
        file.seek(0)

        if size > cls.MAX_FILE_SIZE:
            raise ValueError(f"File too large (max {cls.MAX_FILE_SIZE} bytes)")

        # Secure the filename
        filename = secure_filename(file.filename)
        if not filename:
            raise ValueError("Invalid filename")

        # Check extension
        ext = filename.rsplit('.', 1)[-1].lower()
        if ext not in cls.ALLOWED_EXTENSIONS:
            raise ValueError(f"Extension not allowed: {ext}")

        # Check MIME type using file content
        content = file.read()
        file.seek(0)

        mime = magic.from_buffer(content, mime=True)
        if mime not in cls.ALLOWED_MIMES:
            raise ValueError(f"File type not allowed: {mime}")

        # Generate unique filename
        hash_name = hashlib.sha256(content).hexdigest()[:16]
        safe_name = f"{hash_name}.{ext}"

        # Save to isolated directory
        save_path = cls.UPLOAD_DIR / safe_name
        with open(save_path, 'wb') as f:
            f.write(content)

        return safe_name
```

### Path Traversal Prevention

```python
from pathlib import Path

class SecurePath:
    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir).resolve()

    def safe_join(self, user_path: str) -> Path:
        """Safely join user input to base directory"""
        # Normalize and resolve the full path
        full_path = (self.base_dir / user_path).resolve()

        # Verify it's still under base directory
        if not str(full_path).startswith(str(self.base_dir)):
            raise ValueError("Path traversal attempt detected")

        return full_path

    def read_file(self, user_path: str) -> bytes:
        safe_path = self.safe_join(user_path)
        if not safe_path.is_file():
            raise FileNotFoundError("File not found")
        return safe_path.read_bytes()

# Usage
secure_path = SecurePath("/var/app/data")
content = secure_path.read_file("reports/2024/report.pdf")  # OK
content = secure_path.read_file("../../../etc/passwd")  # Raises ValueError
```

---

## Security Checklist

### Code Review

- [ ] All user input is validated
- [ ] Output is properly encoded for context
- [ ] Parameterized queries for all database operations
- [ ] Secure password hashing (Argon2/bcrypt)
- [ ] Session management follows best practices
- [ ] Access control checks on all sensitive operations
- [ ] Cryptographic functions use secure algorithms
- [ ] Error messages don't leak sensitive information
- [ ] File operations prevent path traversal
- [ ] Sensitive data is encrypted at rest

### Testing

- [ ] SQL injection testing on all input points
- [ ] XSS testing on all output points
- [ ] Authentication bypass attempts
- [ ] Authorization boundary testing
- [ ] Path traversal testing on file operations
- [ ] Session fixation testing
- [ ] CSRF protection verification

---

## References

- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/Projects/ssdf)
- [SANS Secure Coding Guidelines](https://www.sans.org/top25-software-errors/)
