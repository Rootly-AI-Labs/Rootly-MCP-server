# Rootly MCP Server Improvement Plan

## What We're Doing

We're improving your Rootly MCP server in 6 phases over 8-10 weeks. The focus is on **security, code quality, testing, CI/CD, monitoring, and MCP best practices** - with **zero breaking changes** for existing users.

**Note:** This plan has been reviewed and enhanced based on GPT-4o feedback. See `GPT4O_REVIEW.md` for detailed recommendations.

---

## The 6 Stages

### Stage 1: Fix Critical Security Issues (1.5 weeks)

**What's wrong:**
- Your API tokens are being logged (even partially) which is a security risk
- Error messages contain full stack traces that expose internal file paths and implementation details
- No validation that URLs and tokens are properly formatted before using them
- Missing HTTPS enforcement and data-in-transit protection
- No security audit or vulnerability scanning

**What we'll do:**
- Remove all token logging - just say "token configured" instead
- Strip stack traces from error responses (log them server-side only)
- Validate tokens and URLs before using them
- Add timeout to all network requests
- **NEW:** Enforce HTTPS for all API calls (reject HTTP)
- **NEW:** Add input sanitization to prevent injection attacks
- **NEW:** Implement rate limiting to prevent abuse
- **NEW:** Run security audit with tools like `bandit` and `safety`
- **NEW:** Add dependency vulnerability scanning to CI pipeline

**Files affected:** `__main__.py`, `client.py`, `server.py`, and create new `security.py`

**Why this matters:** These are high-severity security vulnerabilities that could expose sensitive data. Enhanced security measures protect against common attack vectors.

---

### Stage 2: Improve Error Handling (1 week)

**What's wrong:**
- The code catches all exceptions with generic `except Exception` (14 times!)
- You can't tell what actually went wrong (timeout? auth failure? network issue?)
- Some errors are silently ignored

**What we'll do:**
- Replace broad exception catching with specific exception types
- Create custom exception classes (`RootlyAuthenticationError`, `RootlyNetworkError`, etc.)
- Make error messages consistent and helpful
- Add a decorator to handle errors automatically

**Why this matters:** Better error handling means easier debugging and better error messages for users.

---

### Stage 3: Simplify Complex Code (2 weeks)

**What's wrong:**
- Some functions are massive: `get_oncall_shift_metrics()` is 313 lines!
- Same code patterns repeated 3-4 times throughout
- Hard to understand, test, and maintain

**What we'll do:**
- Break large functions into smaller, focused functions (max 50 lines each)
- Extract duplicate code into reusable helpers
- Replace magic numbers with named constants
- Split code into logical modules (pagination, metrics, formatters)

**Example:**
- `get_oncall_shift_metrics()` (313 lines) → 6 smaller functions (~50 lines each)
- `search_incidents()` (103 lines) → 3 smaller functions (~30 lines each)

**Why this matters:** Simpler code is easier to understand, test, and modify. Less likely to have bugs.

---

### Stage 4: Add Comprehensive Tests & CI/CD (2 weeks)

**What's wrong:**
- Overall test coverage is only ~50%
- Critical files have 0% test coverage:
  - `client.py` (handles all API requests) - 0 tests
  - `__main__.py` (entry point) - 0 tests
  - Data processing functions - 0 tests
- Custom tools only 30% tested
- No CI/CD pipeline for automated testing
- No clear testing strategy or test organization

**What we'll do:**
- Add 200+ new tests organized by type:
  - **Unit tests:** Test individual functions in isolation (~150 tests)
  - **Integration tests:** Test API client + server interactions (~30 tests)
  - **End-to-end tests:** Test complete user workflows (~20 tests)
  - **Security tests:** Test authentication, authorization, input validation
- Get overall coverage to >80% (>90% for critical paths)
- Add performance benchmarks and load tests
- **NEW:** Set up CI/CD pipeline (GitHub Actions):
  - Run all tests on every PR
  - Automated linting (black, ruff, mypy)
  - Security scanning (bandit, safety)
  - Coverage reporting
  - Automated deployment on merge to main
- **NEW:** Add test fixtures and factories for consistent test data
- **NEW:** Implement TDD approach for new features going forward

**Why this matters:** Tests catch bugs before they reach production, make refactoring safer, and CI/CD ensures consistent quality on every change.

---

### Stage 5: MCP Protocol Best Practices (1 week)

**What's wrong:**
- Tools don't declare their output format (no schemas)
- Can't cancel long-running operations
- No prompt definitions (server is tool-only)
- Missing pagination metadata

**What we'll do:**
- Add typed output schemas to all tools
- Implement request cancellation
- Add 5 useful prompts (incident triage, on-call handoff, postmortem, etc.)
- Add pagination metadata to responses

**Why this matters:** Better MCP compliance means better integration with Claude and other MCP clients.

---

### Stage 6: Monitoring, Observability & Documentation (2 weeks)

**What we'll do:**
- Run automated code formatters (black, ruff, isort)
- Add comprehensive documentation:
  - Architecture overview
  - Security guidelines
  - Development guide
  - Complete API reference
  - Deployment and operations guide
- Add performance benchmarks
- Add detailed inline documentation
- **NEW:** Implement structured logging:
  - Use structured logging format (JSON)
  - Add correlation IDs for request tracing
  - Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
  - Separate security audit logs
- **NEW:** Add observability and monitoring:
  - Health check endpoint
  - Metrics collection (request count, latency, errors)
  - Performance monitoring
  - Error tracking and alerting
  - Request/response logging (sanitized)
- **NEW:** Developer training materials:
  - Onboarding guide for new contributors
  - Code review checklist
  - Testing best practices guide

**Why this matters:** Good documentation makes the codebase accessible to other developers. Monitoring and observability help quickly identify and resolve production issues.

---

## Key Results

After all 6 stages:

**Security:**
- ✅ Zero high/critical vulnerabilities
- ✅ No sensitive data in logs or errors
- ✅ All inputs validated
- ✅ HTTPS enforced for all connections
- ✅ Rate limiting implemented
- ✅ Security scanning in CI pipeline

**Code Quality:**
- ✅ All functions under 50 lines
- ✅ Code complexity reduced by >50%
- ✅ No duplicate code

**Testing:**
- ✅ >80% test coverage overall
- ✅ >90% coverage for critical security/business logic
- ✅ Tests run in under 5 minutes
- ✅ Unit, integration, and E2E tests
- ✅ Security and performance tests included

**CI/CD:**
- ✅ Automated testing on every PR
- ✅ Automated linting and security scanning
- ✅ Coverage reporting
- ✅ Automated deployment

**Monitoring & Observability:**
- ✅ Structured logging with correlation IDs
- ✅ Health check endpoint
- ✅ Performance metrics collection
- ✅ Error tracking and alerting

**MCP Compliance:**
- ✅ All tools have output schemas
- ✅ Request cancellation supported
- ✅ Prompt definitions available

**No Breaking Changes:**
- ✅ Existing API unchanged
- ✅ Backward compatible
- ✅ No migration required

---

## Tradeoffs & Decisions

### 1. Code Clarity vs Performance
**Decision:** Prioritize code clarity
**Why:** The server is I/O bound (waiting on API calls), not CPU bound. Clear code is more valuable than micro-optimizations that would save <5% of runtime.

### 2. Comprehensive Fixes vs Quick Wins
**Decision:** Do it right, do it once
**Why:** Quick fixes create technical debt. Taking 6-8 weeks now prevents years of maintenance headaches.

### 3. Test Coverage Goals
**Decision:** 80% overall, 90% for critical paths
**Why:** 100% coverage has diminishing returns. Focus on high-risk areas gives best ROI.

### 4. Breaking Changes
**Decision:** Zero breaking changes
**Why:** Existing users shouldn't need to change their code. All improvements are backward compatible.

### 5. Code Organization
**Decision:** Split into multiple focused files
**Why:** Better testability and maintainability. Slight increase in imports is worth it.

---

## What Could Go Wrong

### Risk 1: Refactoring Breaks Things
**How we'll prevent it:**
- Add comprehensive tests BEFORE refactoring
- Change one function at a time
- Keep old code until new code is verified
- Use feature flags for new implementations

### Risk 2: Error Handling Changes Behavior
**How we'll prevent it:**
- Document all changes
- Test all error scenarios before and after
- Maintain backward compatible error response formats

### Risk 3: MCP Changes Break Clients
**How we'll prevent it:**
- Make all protocol enhancements backward compatible
- Version schemas and prompts
- Test with multiple client versions

### Risk 4: Team Resource Changes
**How we'll prevent it:**
- Document all decisions and rationale
- Pair programming for knowledge transfer
- Comprehensive documentation throughout
- Regular code reviews to share knowledge
- Backup plans for critical roles

### Risk 5: Unforeseen Technical Debt
**How we'll prevent it:**
- Regular code audits during refactoring
- Track and prioritize technical debt items
- Add buffer time to estimates
- Use feature flags to isolate risky changes
- Incremental rollout strategy

---

## Timeline

```
Week 1-1.5:  ██████████ Stage 1: Critical Security Fixes
Week 2-3:    ████████████ Stage 2: Error Handling
Week 4-5:    ████████████ Stage 3: Code Simplification
Week 6-7:    ████████████ Stage 4: Tests & CI/CD
Week 8:      ████████ Stage 5: MCP Compliance
Week 9-10:   ████████████ Stage 6: Monitoring & Documentation

Total: 8-10 weeks
```

**Deployment Strategy:**
- Week 3: Deploy security + error handling together (Stage 1-2)
- Week 5: Deploy refactored code (Stage 3)
- Week 7: Deploy testing infrastructure + CI/CD (Stage 4)
- Week 10: Deploy final improvements (Stages 5-6)

**Monitoring Between Deployments:**
- After each deployment: monitor for 3-5 days
- Track error rates, performance metrics, user feedback
- Rollback plan ready for each deployment

---

## Bottom Line

**Time:** 8-10 weeks (more realistic than initial 6-8 week estimate)
**Effort:** 1-2 full-time developers
**Risk:** Medium (but mitigated with careful staging, CI/CD, and monitoring)
**Breaking Changes:** None
**Value:** Secure, maintainable, well-tested MCP server with CI/CD, monitoring, and best practices

**Cost/Benefit:**
- Initial investment: 8-10 weeks
- Long-term savings: Fewer bugs, easier maintenance, faster feature development
- Security: Protected against common vulnerabilities
- Reliability: Automated testing and monitoring catch issues early

The plan is comprehensive but practical. Each stage delivers value independently, so you could stop after any stage if needed.

---

## Changes From Original Plan

Based on GPT-4o review, we added:
1. **Enhanced security** (HTTPS enforcement, rate limiting, security audits)
2. **CI/CD pipeline** (automated testing, deployment)
3. **Monitoring & observability** (structured logging, metrics, alerting)
4. **Detailed testing strategy** (unit, integration, E2E, security tests)
5. **Extended timeline** (8-10 weeks instead of 6-8 for realism)
6. **Additional risks** (team resources, technical debt)

See `GPT4O_REVIEW.md` for complete feedback and recommendations.
