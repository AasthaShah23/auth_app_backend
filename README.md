# AuthApp Backend API

A production-ready REST API built with **FastAPI**, **SQLAlchemy 2**, and **PostgreSQL** — structured for scalability, testability, security, and clean code architecture.

---

## 🛠 Tech Stack

| Layer            | Technology                                  |
| :--------------- | :------------------------------------------ |
| Framework        | [FastAPI](https://fastapi.tiangolo.com/)    |
| Server           | [Uvicorn](https://www.uvicorn.org/)         |
| ORM              | [SQLAlchemy 2](https://www.sqlalchemy.org/) |
| Migrations       | [Alembic](https://alembic.sqlalchemy.org/)  |
| Database         | [PostgreSQL](https://www.postgresql.org/)   |
| DB Driver        | `psycopg2-binary`                           |
| Password Hashing | `argon2-cffi`                               |
| Validation       | [Pydantic v2](https://docs.pydantic.dev/)   |
| Rate Limiting    | `slowapi`                                   |
| Testing          | `pytest`                                    |
| Linter / Format  | `ruff`                                      |
| Config           | `python-dotenv`                             |

---

## 📁 Project Structure

```text
fullstack_backend/
│
├── alembic/                          # Database migration engine
│   ├── versions/                     # Auto-generated + manual migration files
│   │   ├── 958da1df6fcd_create_users_table.py
│   │   ├── 645261d1df41_seed_new_user_as_admin_role.py
│   │   ├── 36f3bc6327cc_create_refresh_token_table.py
│   │   ├── e465d1c1f4de_create_password_resets_table.py
│   │   └── 5c9781e69475_create_email_verifications_table.py
│   ├── env.py                        # Alembic runtime — wires SQLAlchemy models
│   └── script.py.mako                # Migration file template
│
├── app/
│   ├── api/                          # HTTP layer — routers only (thin controllers)
│   │   ├── __init__.py               # Aggregates all feature routers → api_router
│   │   ├── admin/                    # Admin endpoints (GET /api/admin/users)
│   │   ├── auth/                     # Auth endpoints (signup, login, refresh, logout, reset, verify)
│   │   └── profile/                  # User profile endpoints (GET /api/profile/me)
│   │
│   ├── core/                         # Shared infrastructure — no business logic here
│   │   ├── config.py                 # Settings loaded from .env (single source of truth)
│   │   ├── database.py               # SQLAlchemy engine, SessionLocal, Base
│   │   ├── deps.py                   # FastAPI dependencies (get_db, get_current_user, require_verified_user)
│   │   ├── logging.py                # setup_logging() + get_logger() factory
│   │   ├── rate_limiter.py           # SlowAPI Limiter instance
│   │   ├── security.py              # Argon2 password hashing, JWT creation & token helpers
│   │   └── security_middleware.py   # Security headers & middleware helpers
│   │
│   ├── features/                     # Feature-slice modules (co-locate by feature)
│   │   ├── admin/                    # Admin repository & service logic
│   │   ├── auth/                     # Auth repository, schema & service business logic
│   │   └── profile/                  # Profile repository & service logic
│   │
│   ├── models/                       # SQLAlchemy ORM table definitions
│   │   ├── __init__.py               # Exports User, RefreshToken, PasswordResetToken, EmailVerificationToken
│   │   ├── users.py                  # users table
│   │   ├── refresh_tokens.py         # refresh_tokens table
│   │   ├── password_resets.py        # password_resets table
│   │   ├── email_verifications.py    # email_verifications table
│   │   └── seed_admin.py            # Standalone script to seed the admin user
│   │
│   └── main.py                       # App entry point — logging bootstrap, middleware, CORS, routers
│
├── tests/                            # Automated Pytest test suite
│   ├── conftest.py                   # Shared pytest fixtures (TestClient, DB session)
│   ├── test_auth_routes.py           # Integration tests for Auth & Profile HTTP endpoints
│   └── test_auth_service.py          # Unit tests for security & validation logic
│
├── .env                              # Your local secrets (git-ignored)
├── .env.example                      # Template — copy this to .env
├── .gitignore
├── alembic.ini                       # Alembic config (DB URL read from .env)
├── pyproject.toml                    # Ruff & Pytest configuration
├── requirements.txt                  # Pinned dependencies
└── README.md
```

---

## 🗄️ Database Schema

### 1. `users`

| Column              | Type           | Constraints                         | Description                |
| :------------------ | :------------- | :---------------------------------- | :------------------------- |
| `id`                | `Integer`      | PK, Indexed                         | Auto-increment identifier  |
| `name`              | `String`       | `NOT NULL`                          | Full display name          |
| `email`             | `String`       | Unique, Indexed, `NOT NULL`         | Login email address        |
| `password`          | `String`       | `NOT NULL`                          | Argon2 password hash       |
| `role`              | `String`       | `default='user'`, `NOT NULL`        | `admin` or `user`          |
| `is_email_verified` | `Boolean`      | `default=False`, `NOT NULL`         | Email verification flag    |
| `is_active`         | `Boolean`      | `default=True`, `NOT NULL`          | Account status flag        |
| `created_at`        | `DateTime(tz)` | `server_default=now()`              | Account creation timestamp |
| `updated_at`        | `DateTime(tz)` | `server_default=now()`, auto-update | Last modified timestamp    |

### 2. `refresh_tokens`

| Column       | Type           | Constraints                         | Description                       |
| :----------- | :------------- | :---------------------------------- | :-------------------------------- |
| `id`         | `Integer`      | PK, Indexed                         | Auto-increment identifier         |
| `user_id`    | `Integer`      | FK → `users.id` CASCADE, `NOT NULL` | Owner user reference              |
| `token_hash` | `String`       | Unique, Indexed, `NOT NULL`         | SHA-256 hash of refresh token     |
| `expires_at` | `DateTime(tz)` | `NOT NULL`                          | 7-day token expiry                |
| `revoked_at` | `DateTime(tz)` | Nullable                            | Null if active, set on revocation |
| `created_at` | `DateTime(tz)` | `server_default=now()`              | Issuance timestamp                |
| `updated_at` | `DateTime(tz)` | `server_default=now()`, auto-update | Last modified timestamp           |

### 3. `password_resets`

| Column       | Type           | Constraints                         | Description                       |
| :----------- | :------------- | :---------------------------------- | :-------------------------------- |
| `id`         | `Integer`      | PK, Indexed                         | Auto-increment identifier         |
| `user_id`    | `Integer`      | FK → `users.id` CASCADE, `NOT NULL` | Owner user reference              |
| `token_hash` | `String`       | Unique, Indexed, `NOT NULL`         | SHA-256 hash of reset token       |
| `expires_at` | `DateTime(tz)` | `NOT NULL`                          | 15-minute token expiry            |
| `used_at`    | `DateTime(tz)` | Nullable                            | Null until single-use consumption |
| `created_at` | `DateTime(tz)` | `server_default=now()`              | Token request timestamp           |

### 4. `email_verifications`

| Column       | Type           | Constraints                         | Description                        |
| :----------- | :------------- | :---------------------------------- | :--------------------------------- |
| `id`         | `Integer`      | PK, Indexed                         | Auto-increment identifier          |
| `user_id`    | `Integer`      | FK → `users.id` CASCADE, `NOT NULL` | Owner user reference               |
| `token_hash` | `String`       | Unique, Indexed, `NOT NULL`         | SHA-256 hash of verification token |
| `expires_at` | `DateTime(tz)` | `NOT NULL`                          | 24-hour token expiry               |
| `used_at`    | `DateTime(tz)` | Nullable                            | Null until single-use verification |
| `created_at` | `DateTime(tz)` | `server_default=now()`              | Token creation timestamp           |

---

## ⚙️ Environment Variables Guide

When cloning the repository, copy `.env.example` to create your local `.env` file:

```bash
# macOS / Linux
cp .env.example .env

# Windows (PowerShell)
Copy-Item .env.example .env
```

### `.env` File Configuration Details

| Variable                      | Required | Default / Recommended Value                                         | Description                                                                                  |
| :---------------------------- | :------- | :------------------------------------------------------------------ | :------------------------------------------------------------------------------------------- |
| `DATABASE_URL`                | **Yes**  | `postgresql://postgres:your_password@localhost:5432/fullstack_task` | PostgreSQL connection string format: `postgresql://<user>:<password>@<host>:<port>/<dbname>` |
| `SECRET_KEY`                  | **Yes**  | _(32+ random secret chars)_                                         | Secret key used to sign JWT access tokens. Generate via `openssl rand -hex 32`               |
| `ALGORITHM`                   | **Yes**  | `HS256`                                                             | Cryptographic algorithm for JWT encoding/decoding                                            |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | **Yes**  | `15`                                                                | Lifetime of short-lived JWT access tokens in minutes                                         |
| `REFRESH_TOKEN_EXPIRE_DAYS`   | **Yes**  | `7`                                                                 | Lifetime of persistent opaque refresh tokens in days                                         |
| `LOG_LEVEL`                   | **Yes**  | `DEBUG`                                                             | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`                           |
| `CORS_ORIGINS`                | **Yes**  | `http://localhost:3000,http://127.0.0.1:3000`                       | Comma-separated list of allowed frontend origins for CORS preflight                          |
| `FRONTEND_URL`                | **Yes**  | `http://localhost:3000`                                             | Base URL used to log mock email verification & password reset links                          |

---

## 🚀 Local Setup Guide

### Prerequisites

Make sure you have installed:

- **Python 3.11+**
- **PostgreSQL 14+** (and pgAdmin or psql)
- **Git**

---

### Step 1 — Clone the Repository

```bash
git clone <your-repository-url>
cd auth_app_backend
```

---

### Step 2 — Create PostgreSQL Database

Open **pgAdmin** (or terminal `psql`) and create a local database named:

```sql
CREATE DATABASE auth_app;
```

---

### Step 3 — Create and Activate Virtual Environment

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell):**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

---

### Step 4 — Install Dependencies

```bash
pip install -r requirements.txt
```

---

### Step 5 — Set Up Environment Variables

Copy `.env.example` to `.env` and fill in your database credentials:

```env
DATABASE_URL=postgresql://postgres:your_password@localhost:5432/auth_app
SECRET_KEY=put_your_secret_key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

LOG_LEVEL=DEBUG
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
FRONTEND_URL=http://localhost:3000
```

---

### Step 6 — Run Database Migrations & Seed Admin User

Run Alembic migrations to build tables and seed the default admin account:

```bash
alembic upgrade head
```

Verify migration status:

```bash
alembic current
```

---

### Step 7 — Start the Development Server

```bash
uvicorn app.main:app --reload
```

The server is running at:

- **Health Check**: [http://localhost:8000](http://localhost:8000)
- **Swagger Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc Reference**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

## 🔑 Default Admin Account Credentials

Running `alembic upgrade head` automatically seeds an admin user idempotently:

| Field        | Credential Value   |
| :----------- | :----------------- |
| **Name**     | Aastha Shah        |
| **Email**    | `aastha@gmail.com` |
| **Password** | **`Admin@123`**    |
| **Role**     | `admin`            |

---

## 📡 API Endpoints Overview

### Auth Summary

| Method | Endpoint                        | Description                                   | Auth / Limit           |
| :----- | :------------------------------ | :-------------------------------------------- | :--------------------- |
| `POST` | `/api/auth/signup`              | Register user & log verification link         | Public                 |
| `POST` | `/api/auth/login`               | Authenticate user & issue httpOnly cookies    | Public (5 req/min)     |
| `POST` | `/api/auth/refresh`             | Rotate refresh token & issue new access token | Public                 |
| `POST` | `/api/auth/logout`              | Revoke refresh token & clear cookies          | Public                 |
| `POST` | `/api/auth/forgot-password`     | Request 15-min password reset link            | Public (3 req/min)     |
| `POST` | `/api/auth/reset-password`      | Reset password using token                    | Public (5 req/min)     |
| `GET`  | `/api/auth/verify-email`        | Verify email with 24h token                   | Public                 |
| `POST` | `/api/auth/resend-verification` | Resend verification email link                | Public (3 req/min)     |
| `GET`  | `/api/profile/me`               | Get current user profile details              | Protected (User/Admin) |
| `GET`  | `/api/admin/users`              | List all registered users (Paginated)         | Protected (Admin)      |

## 🏗 Architectural & Design Decisions Made & Why

### 1. Clean Feature-Slice Layered Architecture

- **Structure**: HTTP Routers (`app/api`), Business Logic Services (`app/features/*/service.py`), Database Queries (`app/features/*/repository.py`), and ORM Models (`app/models`).
- **Why**: Keeps route controllers thin, prevents tight coupling between HTTP framework and business rules, simplifies unit/integration testing, and avoids circular dependency issues as the codebase grows.

### 2. Argon2 Password Hashing (`argon2-cffi`)

- **Choice**: Argon2id password hashing algorithm.
- **Why**: Argon2 is the winner of the Password Hashing Competition (PHC). It provides superior memory-hard and time-hard resistance against GPU/ASIC hardware brute-force attacks compared to legacy algorithms like MD5, SHA256, or bcrypt.

### 3. SHA-256 Hashed Opaque Tokens in Database

- **Choice**: Storing SHA-256 hashes of refresh tokens, password reset tokens, and email verification tokens in PostgreSQL rather than raw token strings.
- **Why**: Protects user security. If the database is leaked or accessed by an unauthorized entity, raw tokens cannot be retrieved from `token_hash` columns to hijack active user sessions or perform unauthorized password resets.

### 4. `httpOnly` Cookies vs `localStorage` for JWT Storage

- **Choice**: Tokens (`access_token` & `refresh_token`) are issued as `httpOnly`, `SameSite=Lax` cookies upon login/signup, while maintaining dual-resolution fallback to `Authorization: Bearer <token>` headers.
- **Why**: Tokens stored in `localStorage` are vulnerable to Cross-Site Scripting (XSS) attacks. `httpOnly` cookies cannot be read by JavaScript (`document.cookie`), eliminating token theft via XSS while allowing API testing tools (Swagger UI, Postman) to use Bearer headers.

### 5. Single-Use and Expiring Tokens

- **Choice**: Password reset tokens expire in 15 minutes; email verification tokens expire in 24 hours. Once used, `used_at = now()` is set.
- **Why**: Enforces strict token lifecycles and prevents replay attacks. Resetting a password also invalidates all active user refresh tokens to secure compromised accounts.

### 6. IP-Based Rate Limiting (`slowapi`)

- **Choice**: IP-based rate limits on security-sensitive endpoints (`/login`: 5/min, `/forgot-password`: 3/min, `/reset-password`: 5/min, `/resend-verification`: 3/min).
- **Why**: Prevents brute-force credential stuffing and Denial of Service (DoS) attacks while avoiding user account lockouts caused by malicious third parties.

### 7. User Enumeration Prevention

- **Choice**: Endpoints like `forgot-password` and `resend-verification` return generic success responses regardless of whether the submitted email address exists in the database.
- **Why**: Prevents malicious actors from probing the API to discover which email addresses have registered accounts.

### 8. Automated Testing Suite with `pytest`

- **Choice**: Isolated test suite in `tests/` utilizing `pytest` and `fastapi.testclient.TestClient`.
- **Why**: Ensures 100% confidence across authentication flows, password validation rules, token rotation, and route protection before deploying code changes.

### 9. Code Quality & Formatting with Ruff

- **Choice**: `ruff` configuration in `pyproject.toml`.
- **Why**: Extremely fast linting and code formatting, maintaining PEP 8 standards and consistent imports (`isort`) across contributors.

---

## 🛠 Common Development Commands

| Action                     | Command                           |
| :------------------------- | :-------------------------------- |
| **Start Server**           | `uvicorn app.main:app --reload`   |
| **Run Migrations**         | `alembic upgrade head`            |
| **Rollback Migration**     | `alembic downgrade -1`            |
| **Check Migration Status** | `alembic current`                 |
| **Run Test Suite**         | `pytest -v`                       |
| **Run Linter (Auto-fix)**  | `ruff check --fix .`              |
| **Format Codebase**        | `ruff format .`                   |
| **Seed Admin User**        | `python -m app.models.seed_admin` |

---

## 🪵 Logging

Logs are formatted and written to **stdout**:

```text
2026-10-10 12:00:00 | INFO     | app.api.auth.router | signup:53 | Signup request received for email=jane@example.com
2026-10-10 12:00:00 | DEBUG    | app.features.auth.service | signup_user:80 | Creating user record for email=jane@example.com
2026-10-10 12:00:00 | INFO     | app.main | log_requests:55 | RESPONSE [a1b2c3d4] status=201  duration=42.15ms
```

Control verbosity in `.env`:

```env
LOG_LEVEL=DEBUG    # Development (detailed debug output)
LOG_LEVEL=INFO     # Staging / Production (business events & errors)
```
