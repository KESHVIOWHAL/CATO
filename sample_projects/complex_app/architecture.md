# Complex App Architecture

## Overview
Multi-tier Python application demonstrating CATO analysis across multiple files and modules.

## Structure
- `app/auth/` — Authentication and session management
- `app/database/` — Database access layer
- `app/api/` — HTTP route handlers
- `app/services/` — Business logic (payments, etc.)
- `app/models/` — Data models
- `app/utils/` — Shared utilities
- `tests/` — Functional test suite

## Security Policy
All credentials must be loaded from environment variables.
No hardcoded secrets in source code.
All SQL queries must use parameterized statements.
subprocess calls must use shell=False with allowlists.
