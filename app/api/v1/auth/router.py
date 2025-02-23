"""Main router for authentication endpoints.

This module implements a comprehensive authentication router following RFC standards:
- OAuth2 Authentication (RFC 6749)
- Bearer Token Usage (RFC 6750)
- Token Introspection (RFC 7662)
- Token Revocation (RFC 7009)
- Problem Details (RFC 7807)

The router integrates multiple authentication flows:
1. Email/Password Authentication
   - Registration and verification
   - Login and token management
   - Password reset functionality

2. Social Authentication
   - OAuth2 providers (Google, Apple)
   - Account linking
   - Token management

3. User Management
   - Profile management
   - Session control
   - Account settings

4. Administrative Functions
   - User administration
   - Role management (RBAC)
   - System monitoring

5. Audit Logging
   - Activity tracking
   - Security monitoring
   - Compliance logging

Security Features:
- Rate limiting on all endpoints
- RBAC implementation
- Audit logging
- Session management
- Token security
"""

from fastapi import APIRouter

from app.api.v1.auth import admin, audit, auth, social, users

# Main authentication router with versioning
router = APIRouter(prefix="/auth", tags=["auth"])

# Include sub-routers with specific functionality
router.include_router(auth.router)      # Core authentication
router.include_router(users.router)     # User management
router.include_router(admin.router)     # Administrative functions
router.include_router(audit.router)     # Audit logging
router.include_router(social.router)    # Social authentication
