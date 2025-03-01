# Auth-Py

A proof of concept authentication service built with FastAPI, demonstrating modern authentication patterns and best practices.

## Features

- [x] JWT Authentication
  - [x] Access & Refresh tokens
  - [x] Token revocation
  - [x] Secure cookie handling

- [x] OAuth2 Integration
  - [x] Google Sign-In
  - [x] Apple Sign-In
  - [x] Account linking

- [x] Security
  - [x] Rate limiting
  - [x] Audit logging
  - [x] CORS & Security headers
  - [x] Password reset flow
  - [x] Email verification

## Quick Start

### Prerequisites
- Python 3.11+
- Docker & Docker Compose
- uv package manager

### Development Commands
```bash
# Setup development environment
make dev

# Run the server
make run

# Code quality
make check  # Run linting and type checks
make fix    # Auto-fix code style issues

# Database
make migrate        # Generate migration
make migrate-apply  # Apply migration

# Cleanup
make stop   # Stop services
make clean  # Full cleanup
```

### Environment Setup
```bash
# Copy example env file
cp .env.example .env

# Edit .env with your settings:
# - Database connection
# - Redis connection
# - JWT settings
# - OAuth2 credentials
# - SMTP settings
```

## API Documentation

- Interactive API docs: `/docs`
- API reference: `/redoc`
- OpenAPI schema: `/api/openapi.json`

## License

[MIT](./LICENSE)