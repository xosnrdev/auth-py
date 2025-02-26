# Auth-Py

A proof of concept authentication service built with FastAPI, implementing modern authentication patterns and RFC standards with a focus on security best practices.

For a simplified Rust implementation, see [auth-rs](https://github.com/xosnrdev/auth-rs.git).

[![Python Version](https://img.shields.io/badge/python-3.13%2B-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109.0-green.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)

## Overview

Auth-Py provides a comprehensive authentication and authorization solution, implementing industry standards and security best practices. This project serves as both a Proof of concept service and a reference implementation for modern authentication patterns.

## Features

### Core Authentication
- Email/Password authentication with bcrypt hashing
- OAuth2 with JWT tokens
- Social authentication support (Google OAuth2)
- Account linking and profile synchronization

### Security Features
- Rate limiting and brute force protection
- Comprehensive audit logging
- Role-Based Access Control (RBAC)
- Security headers and CSP implementation

### System Features
- Async support with FastAPI
- PostgreSQL for persistent storage
- Redis for caching and rate limiting
- Docker-ready deployment

## Technical Requirements

| Component     | Version | Purpose |
|--------------|---------|---------|
| Python       | ≥3.13   | Runtime |
| PostgreSQL   | ≥15     | Database |
| Redis        | ≥7.2    | Cache |
| Docker       | ≥24.0.0 | Deployment |

## Quick Start

### Docker Deployment
```bash
docker compose up -d
```

### Local Development
```bash
# Setup development environment
./x

# Run tests
pytest

# Run linters
ruff check .
mypy .
```

## API Documentation

- Interactive API documentation: `/docs`
- API reference: `/redoc`
- OpenAPI schema: `/api/openapi.json`

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/).

## Security

Report security issues to [hello@xosnrdev.tech](mailto:hello@xosnrdev.tech).

## License

Available under [MIT](./LICENSE) at your option.