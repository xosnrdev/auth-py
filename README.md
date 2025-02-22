# Authentication Service

A secure, RFC-compliant authentication service built with FastAPI, providing both traditional and social authentication methods.

## Features

- 🔐 **Secure Authentication**
  - JWT-based authentication with access and refresh tokens
  - Password hashing with bcrypt
  - CSRF protection and secure session management

- 🌐 **Social Authentication**
  - Google OAuth2 integration
  - Apple Sign In with PKCE
  - Extensible provider framework

- 👥 **User Management**
  - Email verification
  - Role-based access control (RBAC)
  - Session management across devices

- 📊 **Audit & Monitoring**
  - Comprehensive audit logging
  - Rate limiting
  - Activity tracking

## Quick Start

### Prerequisites

- Python 3.13+
- PostgreSQL
- Redis