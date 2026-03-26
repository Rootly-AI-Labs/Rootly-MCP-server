# Changelog

All notable changes to the Rootly MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.2.13] - 2026-03-26

### Changed
- Simplified the README quick start and added clearer hosted remote configuration examples for HTTP streamable, SSE, and Code Mode
- Upgraded `fastmcp[code-mode]` to `3.1.1` and refreshed CI dependencies

### Fixed
- Validate hosted `Authorization` headers earlier and log auth header state to make malformed token issues easier to diagnose
- Hardened Code Mode `execute` by normalizing common client-prefixed tool names and returning clearer parser, import, and runtime errors

### Security
- Patched vulnerable `authlib` and `requests` dependencies

## [2.2.12] - 2026-03-18

### Added
- Added MCP-level pagination to `list_shifts`, including pagination metadata and validation for invalid page numbers

### Changed
- Slimmed heavy collection payloads for generated tools such as `listUsers`, `listServices`, and `listShifts`
- Clarified Code Mode tool discovery and pagination guidance for paginated calls
- Added and simplified Claude Code setup examples in the documentation

### Fixed
- Trimmed `get_shift_incidents` results to avoid oversized responses
- Preserved incidents that started before a shift but were resolved during it

## [2.2.11] - 2026-03-16

### Added
- Added `updateIncident` for scoped incident updates in the PIR lifecycle
- Added `getIncident` and incident readback support for PIR verification

### Changed
- Updated `search_incidents` to include retrospective progress status in readback results
- Scoped GitHub Actions workflow permissions more tightly

### Fixed
- Made Code Mode `execute` compatible with older Monty runtimes
- Patched vulnerable `black` and `PyJWT` dependencies
- Fixed CI usage of `actions/upload-artifact`

## [2.2.10] - 2026-03-12

### Added
- Added a hosted Code Mode endpoint and enabled Code Mode by default in hosted dual-mode deployments
- Added streamable HTTP and SSE dual-transport support in a single hosted process
- Added screenshot coverage, escalation APIs, and tighter allowlist path matching
- Added structured tool-usage telemetry for Datadog, including transport-aware metrics and hashed identity context
- Added Gemini CLI extension support and editor-specific setup documentation
- Added branch-based staging deployment pipeline support

### Changed
- Reorganized Quick Start documentation by editor and added Rootly CLI guidance
- Refreshed vulnerable runtime dependencies and normalized log severity handling

### Fixed
- Restored legacy server parity while preserving compatibility with FastMCP 3.x `list_tools()` and `send()` behavior
- Forwarded auth tokens correctly in hosted SSE and streamable HTTP paths
- Reduced hosted auth noise, improved graceful shutdown behavior, and preserved error context across multi-call tools
- Fixed non-string incident severity handling in `shift_incidents`

## [2.2.9] - 2026-02-24

### Fixed
- Added an auth header event hook for hosted mode so downstream API requests consistently carry the caller's bearer token

## [2.2.8] - 2026-02-24

### Added
- Added filter parameters to `listAlerts`
- Added transport and hosting mode to the Rootly `User-Agent`

### Security
- Hardened the Dockerfile and added `.dockerignore`

## [2.2.6] - 2026-02-19

### Added
- Added `get_alert_by_short_id` so alerts can be fetched by short ID or full alert URL

### Changed
- Reduced alert API response payload size significantly and added User-Agent tracking

### Fixed
- Included alert `url` and `created_at` in alert field selection
- Removed the `timeout` parameter from `FastMCP.from_openapi()` for FastMCP 3.0 compatibility

## [2.2.4] - 2026-02-18

### Added
- Added MCP registry metadata

### Fixed
- Enforced JSON:API headers through an `httpx` event hook to resolve hosted `415` errors more reliably

## [2.2.3] - 2026-02-05

### Added
- Added debug logging for HTTP requests and headers

## [2.2.2] - 2026-02-05

### Fixed
- Removed existing content-type headers case-insensitively before setting JSON:API headers

## [2.2.1] - 2026-02-05

### Fixed
- Always set JSON:API headers regardless of request kwargs to prevent hosted `415` failures

## [2.2.0] - 2026-02-05

### Changed
- Replaced `burnout` terminology with `health risk` across the On-Call Health feature set

## [2.1.4] - 2026-02-05

### Fixed
- Resolved hosted MCP `415 Unsupported Media Type` errors

## [2.1.3] - 2026-02-05

### Added
- Added the On-Call Health integration for burnout-risk detection
- Added unit tests for the On-Call Health integration

### Changed
- Streamlined the README and moved development setup details into `CONTRIBUTING.md`

### Fixed
- Added proper type hints to `och_client.py`

## [2.1.2] - 2026-02-05

### Added
- Added on-call AI workflow tools

## [2.1.1] - 2026-02-04

### Fixed
- Fixed parameter transformation bug where filter parameters (e.g., `filter_status`, `filter_services`) were not being transformed back to their API format (`filter[status]`, `filter[services]`) when making requests to the Rootly API
- Root cause: The inner httpx client was being passed to FastMCP instead of the AuthenticatedHTTPXClient wrapper, bypassing the `_transform_params` method
- Thanks to @smoya for reporting this issue in PR #29

## [2.1.0] - 2026-01-27

### Added

#### Security Improvements
- Comprehensive security module (`security.py`) with:
  - API token validation (prevents invalid/short tokens)
  - HTTPS enforcement for all API calls (rejects HTTP URLs)
  - Input sanitization (SQL injection and XSS prevention)
  - Rate limiting using token bucket algorithm (default: 100 req/min)
  - Error message sanitization (removes stack traces and file paths)
  - Sensitive data masking for logs (tokens, passwords, secrets)
  - URL validation with allowed domain checking

#### Exception Handling
- Custom exception hierarchy (`exceptions.py`) with 11 specific exception types:
  - `RootlyAuthenticationError` - 401 authentication failures
  - `RootlyAuthorizationError` - 403 access denied
  - `RootlyNetworkError` - Network/connection issues
  - `RootlyTimeoutError` - Request timeouts
  - `RootlyValidationError` - Input validation failures
  - `RootlyRateLimitError` - Rate limit exceeded (with retry_after)
  - `RootlyAPIError` - Generic API errors
  - `RootlyServerError` - 5xx server errors
  - `RootlyClientError` - 4xx client errors
  - `RootlyConfigurationError` - Missing/invalid configuration
  - `RootlyResourceNotFoundError` - 404 not found
- Automatic exception categorization with `categorize_exception()`

#### Input Validation
- Input validation utilities (`validators.py`) with:
  - Positive integer validation
  - String validation with length and pattern checks
  - Dictionary validation with required keys
  - Enum value validation
  - Pagination parameter validation

#### Monitoring & Observability
- Structured JSON logging with correlation IDs (`monitoring.py`)
- Request metrics tracking:
  - Request counts by endpoint and status code
  - Response latency percentiles (p50, p95, p99)
  - Error rate tracking by type
  - Active connection monitoring
- Health check support with `get_health_status()`
- Request/response logging decorator (automatically sanitizes sensitive data)
- Context manager for tracking request metrics

#### Helper Utilities
- Pagination helpers (`pagination.py`):
  - Async pagination across multiple pages
  - Pagination parameter building for Rootly API
  - Pagination metadata extraction

#### Testing Infrastructure
- 66 comprehensive unit tests (100% passing)
- Test coverage >90% for all new modules
- Security-focused tests:
  - SQL injection prevention
  - XSS prevention
  - Rate limiting behavior
  - Token validation
  - HTTPS enforcement
  - Error message sanitization

#### CI/CD Pipeline
- GitHub Actions workflow (`.github/workflows/ci.yml`) with:
  - Automated testing on Python 3.10, 3.11, 3.12
  - Code coverage reporting (Codecov integration)
  - Automated linting (ruff, black, isort, mypy)
  - Security scanning (bandit, safety)
  - Automated package building
  - Runs on every push and pull request

### Changed

#### Security Enhancements
- **BREAKING SECURITY FIX**: Removed all API token logging from `__main__.py` (line 100, 116)
  - Changed from: `logger.debug(f"Token starts with: {api_token[:5]}...")`
  - Changed to: `logger.info("ROOTLY_API_TOKEN is configured")`
- **SECURITY**: Updated `client.py` to use structured logging without exposing tokens
- **SECURITY**: All error messages now sanitized to remove stack traces
- Replaced generic `except Exception` with specific exception types in:
  - `__main__.py` - Now catches `RootlyConfigurationError`, `RootlyMCPError`
  - `client.py` - Now catches specific HTTP errors and categorizes them

#### API Client Improvements
- `RootlyClient.make_request()` now raises specific exceptions instead of returning JSON errors
- Added HTTPS enforcement to base URL validation
- Added 30-second timeout to all requests (already existed, now enforced everywhere)
- Better error categorization for HTTP status codes (401, 403, 404, 429, 4xx, 5xx)

#### Configuration Validation
- API token now validated on startup with `validate_api_token()`
- Better error messages for missing or invalid configuration

### Fixed

- Security vulnerability: API tokens no longer logged (even partially)
- Security vulnerability: Stack traces no longer exposed in error responses
- Security vulnerability: HTTP URLs now rejected (HTTPS enforced)
- Generic exception handling replaced with specific exception types
- Error messages now user-friendly (sanitized of internal details)

### Documentation

- Added `IMPLEMENTATION_REPORT.md` - Detailed implementation summary
- Added `GPT4O_REVIEW.md` - External review of improvements
- Added `IMPLEMENTATION_CHECKLIST.md` - Implementation progress tracking
- Updated `IMPROVEMENT_PLAN.md` with GPT-4o recommendations
- All new modules have comprehensive docstrings
- Updated package docstring with new features

### Technical Details

- **Lines of Code Added**: ~1,500 lines production code, ~500 lines test code
- **Test Coverage**: >90% for new modules
- **Tests Passing**: 66/66 (100%)
- **Security Issues Fixed**: 6 critical vulnerabilities
- **Breaking Changes**: 0 (fully backward compatible)

### Backward Compatibility

All changes are backward compatible:
- Existing API unchanged
- New modules are additive
- Exception hierarchy maintains base `Exception` compatibility
- Client behavior unchanged from external perspective
- No migration required for existing users

## [2.0.15] - Previous Release

(Previous changelog entries would go here)
