# SentinelForge AI — Code Review Fixes

All original files are backed up in `backup/` with a `.bak` extension.  
Changes are grouped by priority.

---

## High Priority — Security Fixes

### 1. IP address regex validates octets correctly
**File:** `enrichment/ioc_classifier.py`  
**Problem:** The old regex `^\d{1,3}(\.\d{1,3}){3}$` accepted invalid IPs like `999.999.999.999`.  
**Fix:** Replaced with an RFC-compliant regex that validates each octet is 0–255.  
Also pre-compiled all regexes as module-level constants for efficiency, and replaced the overly broad domain check (`"." in ioc`) with a proper regex `^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$` that rejects filenames like `malware.exe`.

---

### 2. Prompt injection mitigation
**Files:** `ai_analysis/threat_summary.py`, `ai_analysis/mitre_mapper.py`, `ai_analysis/supplier_summary.py`  
**Problem:** User-controlled IOC values and supplier profile fields were inserted raw into AI prompts. A crafted input like `\n\nIgnore previous instructions...` could hijack model behavior.  
**Fix:** Added a `_sanitize()` helper in each module that strips newlines and caps field length at 2048 characters before interpolation into any prompt.

---

### 3. Absolute path for supplier example file
**File:** `api/main.py`  
**Problem:** `open("suppliers/example_supplier.json")` resolved relative to the working directory, not the file — silently breaks if the server is started from a different directory.  
**Fix:** Used `pathlib.Path(__file__).parent.parent` to build an absolute path. Also added a `404` response if the file is missing rather than an unhandled exception.

---

### 4. IOC input validation in API
**File:** `api/main.py`  
**Problem:** The `IOCRequest` model accepted empty strings and arbitrarily large payloads.  
**Fix:** Added Pydantic `Field(min_length=1, max_length=2048)` constraint on the `ioc` field. FastAPI automatically returns a `422 Unprocessable Entity` on violation.

---

## Medium Priority — Bug Fixes

### 5. `evaluate_health` now handles all statuses
**File:** `agent/workflow_health_agent.py`  
**Problem:** `check_feed_health` can return `FORBIDDEN`, `DEGRADED`, and `ERROR` statuses, but `evaluate_health` only handled five statuses — the rest silently fell into `"Low"` severity, which was incorrect (e.g., `FORBIDDEN` should be `"High"`).  
**Fix:** Replaced the if/elif chain with a `_SEVERITY_MAP` dict covering all eight possible statuses.

---

### 6. `last_security_review_days` defaults to worst case when missing
**File:** `suppliers/resilience_score.py`  
**Problem:** `profile.get("last_security_review_days", 0)` defaulted to `0`, meaning a supplier with no review date recorded was silently treated as "reviewed today," inflating their score.  
**Fix:** Changed default to `365` — a missing review date is treated conservatively as overdue.

---

### 7. `TIMEOUT` result now includes `latency_seconds`
**File:** `monitoring/feed_health.py`  
**Problem:** The timeout exception branch returned a dict without `latency_seconds`, making the response schema inconsistent. Callers accessing `latency_seconds` only avoided a crash due to a `"N/A"` default in the dashboard.  
**Fix:** Captured elapsed time before returning from the timeout branch. The `ERROR` branch sets `latency_seconds` to `None` explicitly.

---

### 8. Ollama response accessed safely
**File:** `ai_analysis/ollama_client.py`  
**Problem:** `response["message"]["content"]` raised `KeyError` if Ollama returned an unexpected structure or was unreachable.  
**Fix:** Changed to `response.get("message", {}).get("content", "")` with a fallback return value and a warning log.

---

## Robustness — Error Handling

### 9. AI analysis failures return structured HTTP errors
**File:** `api/main.py`  
**Problem:** If any AI function raised an exception, FastAPI returned a raw `500` with a Python traceback.  
**Fix:** Wrapped all AI calls in `try/except` blocks that catch exceptions and raise `HTTPException(502)` with a descriptive message.

---

### 10. Feed health checks are individually fault-isolated
**File:** `agent/workflow_health_agent.py`  
**Problem:** The list comprehension in `run_workflow_health_agent` stopped entirely on the first exception from any feed.  
**Fix:** Replaced with a `for` loop where each feed check is individually wrapped in `try/except`, allowing partial results to be returned.

---

### 11. Feed health checks use streaming to avoid downloading large payloads
**File:** `monitoring/feed_health.py`  
**Problem:** `requests.get()` downloaded the full response body just to read the HTTP status code. The URLhaus feed is several MB.  
**Fix:** Added `stream=True` and called `response.close()` immediately after reading the status code.

---

### 12. Feed requests include a `User-Agent` header
**File:** `monitoring/feed_health.py`  
**Problem:** Requests had no `User-Agent` header. Some threat intel feeds block anonymous or missing user agents.  
**Fix:** Added `_HEADERS = {"User-Agent": "SentinelForge-AI/1.0"}` applied to all feed requests.

---

### 13. `1min.ai` JSON parse errors are logged, not silently swallowed
**File:** `ai_analysis/onemin_client.py`  
**Problem:** The inner `except Exception` caught all JSON structure errors and returned `str(data)`, making failures invisible.  
**Fix:** Changed to `except (KeyError, IndexError, TypeError)` with a `logger.error()` call and a descriptive return value.

---

## Logging — New Centralized Logging System

### 14. Robust logging across all modules
**New file:** `core/logging_config.py`  
A `configure_logging()` function configures the root logger with two handlers:

- **Console** — streams structured log lines to stdout.
- **Rotating file** — writes to `logs/sentinelforge.log`, rotating at 5 MB with 5 backups.

Format: `YYYY-MM-DD HH:MM:SS  LEVEL  module  message`

`LOG_LEVEL` is read from the environment (default: `INFO`).

**Wired into:** `api/main.py` via `configure_logging()` at startup.  
**Module-level loggers added to:** `agent/workflow_health_agent.py`, `ai_analysis/ollama_client.py`, `ai_analysis/onemin_client.py`, `ai_analysis/threat_summary.py`, `ai_analysis/mitre_mapper.py`, `ai_analysis/supplier_summary.py`, `monitoring/feed_health.py`.

---

## Configuration Fixes

### 15. Dashboard API URL is configurable
**File:** `dashboard/app.py`  
**Problem:** `API_BASE` was hardcoded to `http://127.0.0.1:8001`.  
**Fix:** Reads from `SENTINELFORGE_API_URL` environment variable with the original value as a fallback.

### 16. Feed list is a named constant
**File:** `agent/workflow_health_agent.py`  
**Problem:** Feeds were hardcoded inside the function body.  
**Fix:** Moved to a module-level `_FEEDS` constant for easy visibility and future extension.

---

## Dashboard UX Fixes

### 17. Specific exception handling in the dashboard
**File:** `dashboard/app.py`  
**Problem:** The broad `except Exception` caught all errors with the same generic message.  
**Fix:** Added separate handling for `requests.exceptions.Timeout` and `requests.exceptions.ConnectionError` with targeted user-facing messages in all three tabs.

### 18. IOC input validation in the dashboard
**File:** `dashboard/app.py`  
**Problem:** Empty or oversized IOC values were sent straight to the API.  
**Fix:** Added client-side checks: empty input shows a warning, input over 2048 chars shows an error — neither triggers an API call.

---

## Project Hygiene

### 19. `.env.example` documents all required variables
**File:** `.env.example`  
Added documentation for: `AI_PROVIDER`, `ONE_MIN_API_KEY`, `SENTINELFORGE_API_URL`, and `LOG_LEVEL`.

### 20. `.gitignore` extended
**File:** `.gitignore`  
Added: `logs/`, `*.log`, `*.pyo`, `*.pyd`, `.DS_Store`, `*.egg-info/`, `dist/`, `build/`, `.pytest_cache/`, `.mypy_cache/`, `backup/`.

---

## Files Changed

| File | Status |
|------|--------|
| `enrichment/ioc_classifier.py` | Modified |
| `monitoring/feed_health.py` | Modified |
| `suppliers/resilience_score.py` | Modified |
| `agent/workflow_health_agent.py` | Modified |
| `ai_analysis/ollama_client.py` | Modified |
| `ai_analysis/onemin_client.py` | Modified |
| `ai_analysis/threat_summary.py` | Modified |
| `ai_analysis/mitre_mapper.py` | Modified |
| `ai_analysis/supplier_summary.py` | Modified |
| `api/main.py` | Modified |
| `dashboard/app.py` | Modified |
| `.env.example` | Modified |
| `.gitignore` | Modified |
| `core/logging_config.py` | **New file** |
| `core/__init__.py` | **New file** |

---

## Not Changed (out of scope for this pass)

- **Tests** — No test suite exists. Recommended next step: add `pytest` unit tests for `ioc_classifier.py` and `resilience_score.py` as a starting point.
- **Authentication/rate limiting** — The API has no auth or rate limiting. Recommended: add an API key header check or integrate FastAPI's dependency injection with a rate limiter before exposing to the internet.
- **Feed list configuration** — Feeds are currently a hardcoded constant. A future improvement would be a `feeds.yaml` config file or database table.
