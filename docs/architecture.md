# VulnAdvisor — Architecture Guide

This document explains every structural decision made in this codebase and why it was made that way. It is intended to be a learning reference as much as a technical reference.

---

## The Core Principle: Separation of Concerns

The entire architecture is built around one idea: **each piece of code should do one thing and only one thing.**

This is called the **Single Responsibility Principle** and it is one of the most important ideas in software design. When code has one job, it is:
- Easier to understand (you always know where to look)
- Easier to test (you can test each piece in isolation)
- Easier to change (a change in one place does not break another)

In VulnAdvisor this principle is applied at the module level.

---

## Module Map

```
main.py               CLI entry point — argparse, orchestration
core/
  pipeline.py         Pure process_cve() + process_cves() — shared by CLI and API
  fetcher.py          All HTTP calls — one function per source, returns None on failure
  enricher.py         Pure logic — raw data in, EnrichedCVE out
  formatter.py        Terminal + JSON + CSV/HTML/Markdown — no business logic
  models.py           Dataclasses only — zero logic
cache/
  store.py            SQLite TTL cache — shared by CLI and API
api/
  main.py             FastAPI app — middleware, rate limiting, /health endpoint
  routes/v1/cve.py    CVE endpoints — GET /cve/{id}, POST /cve/bulk, GET /cve/summary
tests/
  test_enricher.py    Unit tests for core/enricher — 80 tests, 100% line coverage
```

Each module has a clearly defined job and does not do anyone else's job. `core/` knows nothing about `api/` or `tests/`. Dependencies only flow inward toward the core.

---

## main.py — The Orchestrator

**What it does:** Parses command-line arguments, loads the CISA KEV feed once, then calls `core/pipeline.py` for each CVE ID.

**Why it is thin:** `main.py` should be an entry point, not a logic engine. It wires the pieces together and delegates everything else. If you find business logic in `main.py`, that is a signal it belongs somewhere in `core/`.

**Pattern used:** This is called an **orchestrator** — it coordinates other components without doing the work itself.

**Key decision:** The CISA KEV feed is loaded once before the loop, not once per CVE. This is a simple form of caching. Loading 1,000 CVEs should not download the KEV feed 1,000 times.

---

## core/pipeline.py — The Shared Processing Core

**What it does:** Provides `process_cve()` and `process_cves()` — pure functions that handle the fetch-cache-enrich sequence for one or many CVE IDs. Both the CLI and the API call these functions. Neither caller reimplements the logic.

**Why it exists:** Before `pipeline.py`, the CLI's main loop contained the fetch-and-enrich orchestration inline. This meant the API would have had to duplicate that logic. Extracting it into a pure function that any caller can use is the **Don't Repeat Yourself (DRY)** principle in action.

**Why it is pure:** No `print()` statements, no side effects. Callers decide what to do with results. This makes the function easy to test and easy to call from different contexts (terminal, HTTP handler, future scheduler).

**Key decision:** CVE ID validation (regex `CVE-\d{4}-\d{4,}`) lives here, not in the callers. One validation rule, one place to update it.

---

## core/models.py — The Data Contracts

**What it does:** Defines the shape of data using Python dataclasses. No logic, no functions — just structure.

**Why dataclasses:** Python dataclasses give you a clean way to define structured data without writing boilerplate. They are like a blueprint for what an object looks like.

**Why no logic here:** If `models.py` contained logic, you would have to understand models to understand the logic, and understand the logic to understand models. Keeping them separate means each file is fully understandable on its own.

**Key structures:**
- `CVSSDetails` — the parsed CVSS score and plain-language attack surface
- `PoCInfo` — public PoC status, count, and link
- `RemediationStep` — a single action item (PATCH, WORKAROUND, or REFERENCE)
- `EnrichedCVE` — the complete output object that all other modules pass around

**Pattern used:** This is called a **Data Transfer Object (DTO)** — a plain container that carries data between layers of the application.

---

## core/fetcher.py — The Data Layer

**What it does:** Makes all HTTP requests to external APIs. One function per data source. Returns `None` or an empty dict on failure — never raises an exception.

**Why one function per source:** Each source has its own URL, its own response format, and its own failure modes. Keeping them separate means a problem with one source does not affect the others.

**Why failures are silent:** This is a triage tool. If EPSS is unavailable, the tool should still show CVSS and KEV data. Crashing the entire run because one source is down would make the tool unreliable. Each function returns a safe empty value on failure and the rest of the pipeline handles missing data gracefully.

**Key decision — KEV caching:** The CISA KEV feed is a large JSON file (~200KB). The `_kev_cache` module-level variable means it is downloaded once per session regardless of how many CVEs are looked up. This is the simplest possible caching strategy.

**Pattern used:** This is called the **Repository Pattern** — a layer that abstracts data fetching so the rest of the application does not need to know how or where data comes from.

---

## core/enricher.py — The Logic Layer

**What it does:** Takes raw fetched data and combines it into a structured, plain-language `EnrichedCVE`. This is where all the intelligence lives.

**Why it is the most complex module:** Enrichment is inherently complex — it involves parsing CVSS vectors, mapping CWE IDs to plain language, extracting CPE data, and applying multi-signal triage logic. That complexity is intentional and appropriate here. It would be worse if it were spread across multiple modules.

**Key components:**

`CWE_MAP` — A dictionary mapping CWE IDs to plain-language names, descriptions, and fix guidance. This is a lookup table, not logic. Adding a new CWE is as simple as adding a new entry.

`_parse_cvss_vector()` — CVSS vectors are compact strings like `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`. This function splits them into key-value pairs and translates each code into plain English using lookup dictionaries.

`_triage_priority()` — The core decision engine. Combines CVSS score, KEV status, EPSS probability, and PoC availability into a single P1-P4 priority. This is rule-based, not machine learning — rules are transparent, explainable, and auditable.

**The triage rules:**
```
P1 (fix in 24h)   CVSS >= 9.0 AND (actively exploited OR EPSS >= 50%)
P2 (fix in 7d)    CVSS >= 7.0 AND (exploited OR has PoC OR EPSS >= 30%)
P2 (fix in 7d)    CVSS >= 7.0 (high severity alone)
P3 (fix in 30d)   CVSS >= 4.0
P4 (next cycle)   everything else
```

**Pattern used:** This is called an **enrichment pipeline** — raw data goes in, enriched structured data comes out.

---

## core/formatter.py — The Presentation Layer

**What it does:** Takes an `EnrichedCVE` and renders it to the terminal (with ANSI color codes) or serializes it to JSON.

**Why it is separate from enricher:** The enricher should not know or care how results are displayed. Keeping formatting separate means you can add a new output format (CSV, HTML, Slack message) without touching any of the logic.

**Key decision — JSON output:** The `to_json()` function uses `dataclasses.asdict()` to convert the `EnrichedCVE` to a plain dictionary and then serializes it. This means the `--json` flag gives you a machine-readable version of the exact same data the terminal shows. The REST API uses the same serialization path — the web layer calls `enrich()` and returns the same JSON.

**Pattern used:** This is called the **Presentation Layer** — it only knows how to display data, never how to produce it.

---

## The Open-Core Path

The architecture was designed so that the same core engine powers both the CLI and the API without duplication.

```
Open source CLI (crawl phase — complete):
  main.py → pipeline → fetcher → enricher → formatter → terminal

REST API (walk phase — active):
  HTTP request → pipeline → fetcher → enricher → to_json() → API response
```

Both paths call the same `process_cve()` from `core/pipeline.py` and the same `enrich()` from `core/enricher.py`. The API is not a separate reimplementation — it is another consumer of the same core engine.

This design pattern is called **open-core** — the core logic is free and open source, and the value-added layer (web UI, team features, integrations) is where a commercial product can be built on top.

---

## What Was Deliberately Left Out

**No AI/ML layer.** The triage logic is entirely rule-based. Rules are transparent, auditable, and free. An AI layer would require an API key, cost money, and produce results that are harder to explain. Rule-based is the right choice for an open-source security tool.

**No config file.** There are no user-configurable settings yet. Adding configuration before it is needed is over-engineering. This will be introduced when custom priority overrides become a feature.

**No ORM.** The SQLite cache in `cache/store.py` uses parameterized queries directly — no SQLAlchemy or similar. The schema is a single table. An ORM would add a dependency and abstraction layer with no payoff at this scale.

---

## Testing Strategy

**What is tested:** `core/enricher.py` — the module with the most business logic and the clearest pure-function interface (no I/O, no side effects). 80 tests, 100% line coverage.

**Why private functions are tested directly:** `_triage_priority()` is the most critical logic path in the codebase. Testing it through `enrich()` alone would make it hard to isolate boundary conditions. Python does not enforce private access, and testing internals directly is the right call when those internals are the core decision engine.

**Why no mocking:** All tested functions are pure — they take plain Python dicts and return plain Python objects. No HTTP calls, no SQLite. Pure functions are the highest-ROI test targets because they need zero test infrastructure.

**Coverage scope:** `--cov=core.enricher` only. A global 80% threshold would fail immediately since `fetcher.py`, `pipeline.py`, and the API layer are not yet covered. Scoping to enricher is honest about what is actually tested. Expand scope as each tier gets tests added.

**Pattern used:** This is called **unit testing** — testing the smallest independent unit of logic in isolation. The counterpart is integration testing, which tests multiple components working together.
