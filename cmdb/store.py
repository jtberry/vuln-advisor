"""
cmdb/store.py -- SQLAlchemy-backed persistence layer for the VulnAdvisor CMDB.

Uses SQLAlchemy Core (not ORM) so the domain dataclasses in cmdb/models.py
remain the authoritative domain representation. SQLAlchemy provides a
database-agnostic abstraction: swapping SQLite for PostgreSQL is a connection
string change, not a rewrite.

Pattern: Repository + Data Mapper. CMDBStore is the repository (one clean
interface per entity). The _row_to_* functions are the mappers (they translate
raw DB rows into domain dataclasses). Route handlers never touch SQL directly.

Security: all queries use bound parameters. No f-strings in SQL.

Usage:
    store = CMDBStore()                               # SQLite default
    store = CMDBStore("postgresql://user:pw@host/db") # PostgreSQL
    asset_id = store.create_asset(asset)
    store.create_asset_vuln(vuln)
    assets = store.list_assets()
    store.update_vuln_status(vuln_id, "in_review", from_status="open", owner="alice")
    store.close()
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import (
    Column,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    case,
    create_engine,
    event,
    func,
    select,
    text,
)
from sqlalchemy.engine import Engine

from cmdb.models import Asset, AssetVulnerability, RemediationRecord

_DEFAULT_DB_URL = f"sqlite:///{Path(__file__).parent / 'vulnadvisor_cmdb.db'}"

# SLA deadline in days per priority bucket. Matches CONTEXT.md locked decisions.
_SLA_DAYS: dict[str, int] = {
    "P1": 7,
    "P2": 30,
    "P3": 90,
    "P4": 180,
}

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

metadata = MetaData()

_assets = Table(
    "assets",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("hostname", String(255), nullable=False),
    Column("ip", String(45)),
    Column("environment", String(50), nullable=False, server_default="production"),
    Column("exposure", String(50), nullable=False, server_default="internal"),
    Column("criticality", String(50), nullable=False, server_default="medium"),
    Column("owner", String(255)),
    Column("tags", Text),  # JSON array serialized as text
    Column("created_at", String(32), nullable=False),
    Column("os", String(100)),
    Column("eol_date", String(10)),  # YYYY-MM-DD
    Column("compliance", Text),  # JSON array, like tags
)

_asset_vulns = Table(
    "asset_vulnerabilities",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("asset_id", Integer, nullable=False),
    Column("cve_id", String(30), nullable=False),
    Column("status", String(30), nullable=False, server_default="open"),
    Column("base_priority", String(5)),
    Column("effective_priority", String(5)),
    Column("discovered_at", String(32), nullable=False),
    Column("deadline", String(32)),
    Column("owner", String(255)),
    Column("evidence", Text),
    Column("scanner", String(30), nullable=False, server_default="manual"),
    UniqueConstraint("asset_id", "cve_id", name="uq_asset_cve"),
)

_remediation = Table(
    "remediation_records",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("asset_vuln_id", Integer, nullable=False),
    Column("status", String(30), nullable=False),
    Column("owner", String(255)),
    Column("evidence", Text),
    Column("updated_at", String(32), nullable=False),
    Column("is_regression", Integer, server_default="0"),  # boolean stored as 0/1
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _deadline_for(priority: str) -> Optional[str]:
    """Return ISO 8601 deadline based on the SLA for this priority.

    Returns None only for unrecognised priority values. All four standard
    priority buckets (P1-P4) have defined SLA deadlines in _SLA_DAYS.
    """
    days = _SLA_DAYS.get(priority)
    if days is None:
        return None
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _days_overdue(deadline_iso: str) -> int:
    """Return how many days overdue the deadline is (positive = overdue, negative = future).

    Handles both timezone-aware ISO strings (e.g. '2024-01-01T00:00:00+00:00')
    and naive ISO strings (treated as UTC). Returns an int (floor of the day delta)
    so callers get consistent integer comparisons without extra casting.

    Used by get_overdue_vulns() to classify and sort overdue/approaching vulns.
    """
    try:
        dt = datetime.fromisoformat(deadline_iso)
    except ValueError:
        # Malformed deadline -- treat as zero days overdue
        return 0
    if dt.tzinfo is None:
        # Naive datetime -- assume UTC (defensive handling for legacy data)
        dt = dt.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return int((now - dt).total_seconds() / 86400)


def apply_criticality_modifier(priority: str, criticality: str) -> str:
    """Upgrade triage priority one level for critical assets.

    This modifier lives in cmdb/ rather than core/enricher.py so the CVE
    engine stays asset-agnostic. The enricher operates on a CVE in isolation;
    asset context is the CMDB's concern (Single Responsibility Principle).

    critical + P3 -> P2
    critical + P4 -> P3
    All other combinations: priority unchanged.
    """
    if criticality != "critical":
        return priority
    return {"P3": "P2", "P4": "P3"}.get(priority, priority)


# ---------------------------------------------------------------------------
# Migration
# ---------------------------------------------------------------------------


def _migrate_assets_table(conn) -> None:
    """Add new columns to an existing assets table without dropping data.

    metadata.create_all() only creates missing tables -- it does not add
    columns to existing tables. This function fills that gap by inspecting
    PRAGMA table_info and issuing ALTER TABLE for any missing columns.

    Column names are hardcoded constants (not user input), so string
    interpolation in the ALTER TABLE statement is safe and unavoidable:
    SQLite does not support parameter binding for column names.
    """
    existing = {row[1] for row in conn.execute(text("PRAGMA table_info(assets)"))}
    additions = [
        ("os", "TEXT"),
        ("eol_date", "TEXT"),
        ("compliance", "TEXT"),
        ("org_id", "INTEGER"),  # reserved: SaaS org isolation (walk phase: always NULL)
    ]
    for col, typ in additions:
        if col not in existing:
            conn.execute(text(f"ALTER TABLE assets ADD COLUMN {col} {typ}"))  # nosemgrep
    conn.commit()


def _migrate_vulns_table(conn) -> None:
    """Add new columns to an existing asset_vulnerabilities table without dropping data.

    Mirrors _migrate_assets_table. Column names are constants, not user input,
    so string interpolation in ALTER TABLE is safe and unavoidable.
    """
    existing = {row[1] for row in conn.execute(text("PRAGMA table_info(asset_vulnerabilities)"))}
    additions = [
        ("org_id", "INTEGER"),  # reserved: SaaS org isolation (walk phase: always NULL)
    ]
    for col, typ in additions:
        if col not in existing:
            conn.execute(text(f"ALTER TABLE asset_vulnerabilities ADD COLUMN {col} {typ}"))  # nosemgrep
    conn.commit()


def _migrate_remediation_table(conn) -> None:
    """Add is_regression column to existing remediation_records table."""
    existing = {row[1] for row in conn.execute(text("PRAGMA table_info(remediation_records)"))}
    additions = [
        ("is_regression", "INTEGER DEFAULT 0"),
    ]
    for col, typ in additions:
        if col not in existing:
            conn.execute(text(f"ALTER TABLE remediation_records ADD COLUMN {col} {typ}"))  # nosemgrep
    conn.commit()


def _migrate_status_values(conn) -> None:
    """Rename old status values to analyst-friendly names.

    One-time migration. Safe to re-run (UPDATE WHERE old_value is a no-op
    when no rows match).

    pending     -> open
    in_progress -> in_review
    verified    -> remediated
    """
    renames = [
        ("pending", "open"),
        ("in_progress", "in_review"),
        ("verified", "remediated"),
    ]
    for old, new in renames:
        conn.execute(_asset_vulns.update().where(_asset_vulns.c.status == old).values(status=new))
        conn.execute(_remediation.update().where(_remediation.c.status == old).values(status=new))
    conn.commit()


# ---------------------------------------------------------------------------
# Status workflow
# ---------------------------------------------------------------------------

# Forward order defines "progress" direction. Higher index = more progressed.
# deferred is intentionally omitted -- it is a terminal exit, not part of the
# linear chain, and transitioning TO deferred is never a regression.
_STATUS_ORDER: dict[str, int] = {
    "open": 0,
    "in_review": 1,
    "remediated": 2,
    "closed": 3,
}

_TERMINAL_STATUSES = {"closed", "deferred"}


def _is_regression(from_status: str, to_status: str) -> bool:
    """Return True if this transition moves backwards in the workflow.

    Transitions TO deferred are never regressions -- deferred is a valid
    exit from any active state.
    Transitions FROM a terminal state to a non-terminal state are always
    regressions (re-opening a closed or deferred item).
    """
    if to_status == "deferred":
        return False
    if from_status in _TERMINAL_STATUSES:
        return True
    from_idx = _STATUS_ORDER.get(from_status, -1)
    to_idx = _STATUS_ORDER.get(to_status, -1)
    return to_idx < from_idx


# ---------------------------------------------------------------------------
# WAL mode
# ---------------------------------------------------------------------------


def _set_wal_mode(dbapi_conn, connection_record) -> None:
    """Enable WAL journal mode for concurrent read safety.

    WAL (Write-Ahead Logging) allows readers to proceed without blocking
    during writes. Set per-connection because SQLite PRAGMAs are not
    inherited by new connections from the pool.
    """
    dbapi_conn.execute("PRAGMA journal_mode=WAL")


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------


class CMDBStore:
    def __init__(self, db_url: str = _DEFAULT_DB_URL) -> None:
        connect_args: dict = {}
        if db_url.startswith("sqlite"):
            # SQLite requires check_same_thread=False when used from FastAPI's
            # async context where the same connection may be accessed across
            # threads managed by the ASGI server.
            connect_args["check_same_thread"] = False
        self.engine: Engine = create_engine(db_url, connect_args=connect_args)
        if db_url.startswith("sqlite"):
            event.listen(self.engine, "connect", _set_wal_mode)
        metadata.create_all(self.engine)
        with self.engine.connect() as conn:
            _migrate_assets_table(conn)
            _migrate_vulns_table(conn)
            _migrate_remediation_table(conn)
            _migrate_status_values(conn)

    # ------------------------------------------------------------------
    # Assets
    # ------------------------------------------------------------------

    def create_asset(self, asset: Asset) -> int:
        """Insert a new asset and return its assigned database ID."""
        with self.engine.connect() as conn:
            result = conn.execute(
                _assets.insert().values(
                    hostname=asset.hostname,
                    ip=asset.ip,
                    environment=asset.environment,
                    exposure=asset.exposure,
                    criticality=asset.criticality,
                    owner=asset.owner,
                    tags=json.dumps(asset.tags),
                    created_at=_now_iso(),
                    os=asset.os,
                    eol_date=asset.eol_date,
                    compliance=json.dumps(asset.compliance),
                )
            )
            conn.commit()
            return result.inserted_primary_key[0]

    def update_asset(self, asset_id: int, **fields) -> bool:
        """Update mutable fields on an existing asset.

        Accepts any subset of: hostname, ip, environment, exposure, criticality,
        owner, tags, os, eol_date, compliance. Tags and compliance must be
        passed as list[str]; this method serializes them to JSON before writing.

        Returns True if a row was updated, False if asset_id was not found.
        """
        if "tags" in fields:
            fields["tags"] = json.dumps(fields["tags"])
        if "compliance" in fields:
            fields["compliance"] = json.dumps(fields["compliance"])
        with self.engine.connect() as conn:
            result = conn.execute(_assets.update().where(_assets.c.id == asset_id).values(**fields))
            conn.commit()
        return result.rowcount > 0

    def get_asset(self, asset_id: int) -> Optional[Asset]:
        """Fetch a single asset by ID. Returns None if not found."""
        with self.engine.connect() as conn:
            row = conn.execute(_assets.select().where(_assets.c.id == asset_id)).fetchone()
        return _row_to_asset(row) if row is not None else None

    def get_asset_by_hostname(self, hostname: str) -> Optional[Asset]:
        """Look up an asset by exact hostname match. Returns None if not found."""
        with self.engine.connect() as conn:
            row = conn.execute(_assets.select().where(_assets.c.hostname == hostname)).fetchone()
        return _row_to_asset(row) if row is not None else None

    def list_assets(self) -> list[Asset]:
        """Return all assets ordered by hostname."""
        with self.engine.connect() as conn:
            rows = conn.execute(_assets.select().order_by(_assets.c.hostname)).fetchall()
        return [_row_to_asset(r) for r in rows]

    # ------------------------------------------------------------------
    # Asset vulnerabilities
    # ------------------------------------------------------------------

    def create_asset_vuln(self, vuln: AssetVulnerability) -> int:
        """Link a CVE to an asset and return the record ID.

        Sets discovered_at to now if not already provided.
        Auto-computes the SLA deadline from effective_priority.
        Raises sqlalchemy.exc.IntegrityError if the (asset_id, cve_id) pair
        already exists -- caller should catch and treat as a skip.
        """
        discovered_at = vuln.discovered_at or _now_iso()
        # Use caller-provided deadline if present; otherwise compute from SLA.
        # This allows importing vulns with existing deadlines (e.g. scanner output).
        deadline = vuln.deadline if vuln.deadline else _deadline_for(vuln.effective_priority)
        with self.engine.connect() as conn:
            result = conn.execute(
                _asset_vulns.insert().values(
                    asset_id=vuln.asset_id,
                    cve_id=vuln.cve_id.upper(),
                    status=vuln.status,
                    base_priority=vuln.base_priority,
                    effective_priority=vuln.effective_priority,
                    discovered_at=discovered_at,
                    deadline=deadline,
                    owner=vuln.owner,
                    evidence=vuln.evidence,
                    scanner=vuln.scanner,
                )
            )
            conn.commit()
            return result.inserted_primary_key[0]

    def get_asset_vulns(self, asset_id: int) -> list[AssetVulnerability]:
        """Return all vulnerability records for an asset, P1s first."""
        with self.engine.connect() as conn:
            rows = conn.execute(
                _asset_vulns.select()
                .where(_asset_vulns.c.asset_id == asset_id)
                .order_by(_asset_vulns.c.effective_priority, _asset_vulns.c.discovered_at)
            ).fetchall()
        return [_row_to_vuln(r) for r in rows]

    def get_vuln_by_asset_and_cve(self, asset_id: int, cve_id: str) -> Optional[AssetVulnerability]:
        """Look up a single vuln record by (asset_id, cve_id). Returns None if not found."""
        with self.engine.connect() as conn:
            row = conn.execute(
                _asset_vulns.select().where(
                    (_asset_vulns.c.asset_id == asset_id) & (_asset_vulns.c.cve_id == cve_id.upper())
                )
            ).fetchone()
        return _row_to_vuln(row) if row is not None else None

    def update_vuln_status(
        self,
        vuln_id: int,
        status: str,
        from_status: str = "",
        owner: Optional[str] = None,
        evidence: Optional[str] = None,
    ) -> tuple:
        """Update status on an AssetVulnerability and write an audit record.

        Returns (updated, is_regression).
        Caller supplies from_status (current status before change) to avoid
        a second DB round-trip inside the transaction.
        """
        regression = _is_regression(from_status, status) if from_status else False
        now = _now_iso()
        with self.engine.connect() as conn:
            result = conn.execute(
                _asset_vulns.update()
                .where(_asset_vulns.c.id == vuln_id)
                .values(status=status, owner=owner, evidence=evidence)
            )
            if result.rowcount == 0:
                conn.commit()
                return False, False
            conn.execute(
                _remediation.insert().values(
                    asset_vuln_id=vuln_id,
                    status=status,
                    owner=owner,
                    evidence=evidence,
                    updated_at=now,
                    is_regression=1 if regression else 0,
                )
            )
            conn.commit()
        return True, regression

    def get_priority_counts(self, asset_id: int) -> dict[str, int]:
        """Return open P1/P2/P3/P4 counts for a single asset (closed/deferred excluded)."""
        with self.engine.connect() as conn:
            rows = conn.execute(
                _asset_vulns.select().where(
                    (_asset_vulns.c.asset_id == asset_id) & (_asset_vulns.c.status.not_in(["closed", "deferred"]))
                )
            ).fetchall()
        counts: dict[str, int] = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
        for row in rows:
            p = row.effective_priority
            if p in counts:
                counts[p] += 1
        return counts

    def get_all_priority_counts(self) -> dict[str, int]:
        """Return open P1/P2/P3/P4 counts aggregated across all assets."""
        with self.engine.connect() as conn:
            rows = conn.execute(
                _asset_vulns.select().where(_asset_vulns.c.status.not_in(["closed", "deferred"]))
            ).fetchall()
        counts: dict[str, int] = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
        for row in rows:
            p = row.effective_priority
            if p in counts:
                counts[p] += 1
        return counts

    def get_all_asset_priority_counts(self) -> dict[int, dict[str, int]]:
        """Return open vuln counts per priority per asset in a single query.

        Uses conditional aggregation: COUNT(CASE WHEN condition THEN 1 END)
        groups by asset_id in one SELECT, eliminating the N+1 pattern.

        Terminal statuses (closed, deferred) are excluded from counts.
        Assets with zero open vulns are not returned -- callers should use
        .get(asset_id, {"P1": 0, "P2": 0, "P3": 0, "P4": 0}) for a safe default.
        """
        terminal = ["closed", "deferred"]
        non_terminal = _asset_vulns.c.status.not_in(terminal)
        stmt = select(
            _asset_vulns.c.asset_id,
            func.count(
                case(
                    ((_asset_vulns.c.effective_priority == "P1") & non_terminal, 1),
                )
            ).label("p1"),
            func.count(
                case(
                    ((_asset_vulns.c.effective_priority == "P2") & non_terminal, 1),
                )
            ).label("p2"),
            func.count(
                case(
                    ((_asset_vulns.c.effective_priority == "P3") & non_terminal, 1),
                )
            ).label("p3"),
            func.count(
                case(
                    ((_asset_vulns.c.effective_priority == "P4") & non_terminal, 1),
                )
            ).label("p4"),
        ).group_by(_asset_vulns.c.asset_id)
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).fetchall()
        return {row.asset_id: {"P1": row.p1, "P2": row.p2, "P3": row.p3, "P4": row.p4} for row in rows}

    def get_overdue_vulns(
        self,
        sla_days: Optional[dict[str, int]] = None,
        approaching_days: int = 7,
    ) -> dict[str, list[dict]]:
        """Return overdue and approaching-SLA vulnerabilities across all assets.

        Uses Python date arithmetic (not SQLite date functions) for portability
        and testability. Tradeoff: all open vulns with deadlines are loaded into
        memory before filtering. For a solo analyst tool this is acceptable.

        Args:
            sla_days: Optional override for SLA windows (from app_settings).
                      Defaults to the module-level _SLA_DAYS constant.
            approaching_days: Items with deadline within this many days (but not
                              yet past) are classified as approaching.

        Returns:
            {
              "overdue": [{"asset_id", "hostname", "cve_id", "effective_priority",
                           "days_overdue", "deadline"}, ...],
              "approaching": [{"asset_id", "hostname", "cve_id", "effective_priority",
                               "days_until_due", "deadline"}, ...]
            }
            overdue is sorted by days_overdue descending (worst first).
            approaching is sorted by days_until_due ascending (closest deadline first).
        """
        # sla_days is accepted for API compatibility; deadlines are pre-computed at
        # vuln insert time so the stored deadline column drives overdue classification.
        _ = sla_days
        join_stmt = (
            select(
                _asset_vulns.c.cve_id,
                _asset_vulns.c.effective_priority,
                _asset_vulns.c.deadline,
                _asset_vulns.c.status,
                _assets.c.id.label("asset_id"),
                _assets.c.hostname,
            )
            .select_from(_asset_vulns.join(_assets, _asset_vulns.c.asset_id == _assets.c.id))
            .where(_asset_vulns.c.status.not_in(["closed", "deferred"]) & (_asset_vulns.c.deadline.isnot(None)))
        )
        with self.engine.connect() as conn:
            rows = conn.execute(join_stmt).fetchall()

        overdue: list[dict] = []
        approaching: list[dict] = []
        now = datetime.now(timezone.utc)

        for row in rows:
            try:
                dt = datetime.fromisoformat(row.deadline)
            except (ValueError, TypeError):
                continue
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)

            delta = now - dt  # positive if past deadline, negative if future
            delta_seconds = delta.total_seconds()

            if delta_seconds >= 0:
                # Past deadline -- overdue. Use _days_overdue for consistent int output.
                overdue.append(
                    {
                        "asset_id": row.asset_id,
                        "hostname": row.hostname,
                        "cve_id": row.cve_id,
                        "effective_priority": row.effective_priority,
                        "days_overdue": _days_overdue(row.deadline),
                        "deadline": row.deadline,
                    }
                )
            elif delta_seconds > -(approaching_days * 86400):
                # Within approaching window (deadline is in the future but within the window)
                days_until = int(-delta_seconds / 86400)
                approaching.append(
                    {
                        "asset_id": row.asset_id,
                        "hostname": row.hostname,
                        "cve_id": row.cve_id,
                        "effective_priority": row.effective_priority,
                        "days_until_due": days_until,
                        "deadline": row.deadline,
                    }
                )

        overdue.sort(key=lambda x: x["days_overdue"], reverse=True)
        approaching.sort(key=lambda x: x["days_until_due"])

        return {"overdue": overdue, "approaching": approaching}

    def get_open_vuln_cve_ids(self) -> list[dict]:
        """Return CVE IDs for all open vulnerabilities with asset context.

        Used by the dashboard threat intel section to fetch enrichment data
        for active vulns. Capped at 200 results to limit downstream API calls
        to process_cve(); when exceeded, only P1 and P2 vulns are returned.

        Returns:
            list of dicts: [{"asset_id", "hostname", "cve_id",
                             "effective_priority", "exposure"}, ...]
        """
        import logging

        logger = logging.getLogger(__name__)

        join_stmt = (
            select(
                _asset_vulns.c.cve_id,
                _asset_vulns.c.effective_priority,
                _assets.c.id.label("asset_id"),
                _assets.c.hostname,
                _assets.c.exposure,
            )
            .select_from(_asset_vulns.join(_assets, _asset_vulns.c.asset_id == _assets.c.id))
            .where(_asset_vulns.c.status.not_in(["closed", "deferred"]))
        )
        with self.engine.connect() as conn:
            rows = conn.execute(join_stmt).fetchall()

        results = [
            {
                "asset_id": row.asset_id,
                "hostname": row.hostname,
                "cve_id": row.cve_id,
                "effective_priority": row.effective_priority,
                "exposure": row.exposure,
            }
            for row in rows
        ]

        if len(results) > 200:
            logger.warning(
                "get_open_vuln_cve_ids: %d open vulns exceed cap of 200; limiting to P1/P2 only",
                len(results),
            )
            results = [r for r in results if r["effective_priority"] in ("P1", "P2")]

        return results

    def get_remediation_history(self, vuln_id: int) -> list[RemediationRecord]:
        """Return all audit records for an AssetVulnerability, oldest first."""
        with self.engine.connect() as conn:
            rows = conn.execute(
                _remediation.select().where(_remediation.c.asset_vuln_id == vuln_id).order_by(_remediation.c.updated_at)
            ).fetchall()
        return [
            RemediationRecord(
                id=r.id,
                asset_vuln_id=r.asset_vuln_id,
                status=r.status,
                owner=r.owner,
                evidence=r.evidence,
                updated_at=r.updated_at,
                is_regression=bool(getattr(r, "is_regression", 0)),
            )
            for r in rows
        ]

    def close(self) -> None:
        self.engine.dispose()


# ---------------------------------------------------------------------------
# Row mappers (Data Mapper pattern -- DB row -> domain dataclass)
# ---------------------------------------------------------------------------


def _row_to_asset(row) -> Asset:
    tags: list[str] = json.loads(row.tags) if row.tags else []
    compliance: list[str] = json.loads(row.compliance) if getattr(row, "compliance", None) else []
    return Asset(
        id=row.id,
        hostname=row.hostname,
        ip=row.ip,
        environment=row.environment,
        exposure=row.exposure,
        criticality=row.criticality,
        owner=row.owner,
        tags=tags,
        created_at=row.created_at,
        os=getattr(row, "os", None),
        eol_date=getattr(row, "eol_date", None),
        compliance=compliance,
    )


def _row_to_vuln(row) -> AssetVulnerability:
    return AssetVulnerability(
        id=row.id,
        asset_id=row.asset_id,
        cve_id=row.cve_id,
        status=row.status,
        base_priority=row.base_priority or "",
        effective_priority=row.effective_priority or "",
        discovered_at=row.discovered_at,
        deadline=row.deadline,
        owner=row.owner,
        evidence=row.evidence,
        scanner=row.scanner,
    )
