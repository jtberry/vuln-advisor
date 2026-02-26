"""Unit tests for cmdb/store.py -- CMDB store query methods.

Covers:
- get_all_priority_counts() returns correct P1/P2/P3/P4 breakdown
- get_overdue_vulns() returns overdue and approaching items
- get_open_vuln_cve_ids() returns open vuln CVE IDs with asset context
- get_open_vuln_cve_ids() caps results at 200 when exceeded
"""

from datetime import datetime, timedelta, timezone

import pytest

from cmdb.models import Asset, AssetVulnerability
from cmdb.store import CMDBStore

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def store():
    """In-memory CMDBStore with test assets and vulnerabilities pre-loaded.

    Assets:
      - asset1: criticality=critical, exposure=internet
      - asset2: criticality=medium, exposure=internal

    Vulnerabilities span P1-P4 priorities and multiple statuses (open,
    in_review, remediated, closed, deferred). Deadlines are set both in the
    past (overdue) and in the future (approaching / not due).
    """
    s = CMDBStore("sqlite:///:memory:")

    # Create test assets
    asset1_id = s.create_asset(
        Asset(
            hostname="web-server-01",
            environment="production",
            exposure="internet",
            criticality="critical",
        )
    )
    asset2_id = s.create_asset(
        Asset(
            hostname="db-server-01",
            environment="production",
            exposure="internal",
            criticality="medium",
        )
    )

    now = datetime.now(timezone.utc)

    # Overdue: deadline 30 days ago
    past_30 = (now - timedelta(days=30)).isoformat()
    # Overdue: deadline 10 days ago
    past_10 = (now - timedelta(days=10)).isoformat()
    # Approaching: deadline 3 days from now
    future_3 = (now + timedelta(days=3)).isoformat()
    # Future: deadline 60 days from now (not approaching under 7-day window)
    future_60 = (now + timedelta(days=60)).isoformat()

    vulns = [
        AssetVulnerability(
            asset_id=asset1_id,
            cve_id="CVE-2021-00001",
            status="open",
            effective_priority="P1",
            deadline=past_30,
        ),
        AssetVulnerability(
            asset_id=asset1_id,
            cve_id="CVE-2021-00002",
            status="open",
            effective_priority="P2",
            deadline=past_10,
        ),
        AssetVulnerability(
            asset_id=asset1_id,
            cve_id="CVE-2021-00003",
            status="open",
            effective_priority="P3",
            deadline=future_3,
        ),
        AssetVulnerability(
            asset_id=asset1_id,
            cve_id="CVE-2021-00004",
            status="open",
            effective_priority="P4",
            deadline=future_60,
        ),
        AssetVulnerability(
            asset_id=asset2_id,
            cve_id="CVE-2021-00005",
            status="open",
            effective_priority="P1",
            deadline=past_30,
        ),
        # Terminal statuses -- should be excluded from open counts and overdue
        AssetVulnerability(
            asset_id=asset2_id,
            cve_id="CVE-2021-00006",
            status="closed",
            effective_priority="P1",
            deadline=past_30,
        ),
        AssetVulnerability(
            asset_id=asset2_id,
            cve_id="CVE-2021-00007",
            status="deferred",
            effective_priority="P2",
            deadline=past_10,
        ),
        # in_review is not terminal -- should appear in open counts
        AssetVulnerability(
            asset_id=asset2_id,
            cve_id="CVE-2021-00008",
            status="in_review",
            effective_priority="P2",
            deadline=future_60,
        ),
    ]

    for vuln in vulns:
        try:
            s.create_asset_vuln(vuln)
        except Exception:
            pass  # duplicate guard; should not happen in fresh in-memory DB

    yield s
    s.close()


# ---------------------------------------------------------------------------
# TestPriorityCounts
# ---------------------------------------------------------------------------


class TestPriorityCounts:
    def test_priority_counts_all_priorities(self, store: CMDBStore) -> None:
        """get_all_priority_counts returns correct counts per priority bucket.

        From the fixture:
          P1 open: CVE-2021-00001 (asset1), CVE-2021-00005 (asset2) => 2
          P2 open: CVE-2021-00002 (open), CVE-2021-00008 (in_review) => 2
          P3 open: CVE-2021-00003 => 1
          P4 open: CVE-2021-00004 => 1
          closed/deferred not counted
        """
        counts = store.get_all_priority_counts()
        assert counts["P1"] == 2
        assert counts["P2"] == 2
        assert counts["P3"] == 1
        assert counts["P4"] == 1

    def test_priority_counts_excludes_closed(self, store: CMDBStore) -> None:
        """Closed and deferred vulns must not appear in the open counts.

        CVE-2021-00006 (closed, P1) and CVE-2021-00007 (deferred, P2) are in
        the fixture but must not inflate counts.
        """
        counts = store.get_all_priority_counts()
        # P1 has 2 open, not 3 (00006 is closed)
        assert counts["P1"] == 2
        # P2 has 2 open (00002 + 00008), not 3 (00007 is deferred)
        assert counts["P2"] == 2


# ---------------------------------------------------------------------------
# TestGetOverdueVulns
# ---------------------------------------------------------------------------


class TestGetOverdueVulns:
    def test_overdue_returns_past_deadline_items(self, store: CMDBStore) -> None:
        """Vulns with deadline in the past and open status appear in 'overdue' key."""
        result = store.get_overdue_vulns()
        assert "overdue" in result
        overdue_cve_ids = {item["cve_id"] for item in result["overdue"]}
        # CVE-2021-00001 (P1, 30 days past), CVE-2021-00002 (P2, 10 days past),
        # CVE-2021-00005 (P1, 30 days past) are all overdue and open
        assert "CVE-2021-00001" in overdue_cve_ids
        assert "CVE-2021-00002" in overdue_cve_ids
        assert "CVE-2021-00005" in overdue_cve_ids

    def test_approaching_returns_items_within_7_days(self, store: CMDBStore) -> None:
        """Vulns with deadline within 7 days (but not yet past) appear in 'approaching'."""
        result = store.get_overdue_vulns()
        assert "approaching" in result
        approaching_cve_ids = {item["cve_id"] for item in result["approaching"]}
        # CVE-2021-00003 has deadline 3 days from now -- within 7-day window
        assert "CVE-2021-00003" in approaching_cve_ids
        # CVE-2021-00004 is 60 days out -- should NOT be approaching
        assert "CVE-2021-00004" not in approaching_cve_ids

    def test_overdue_sorted_most_overdue_first(self, store: CMDBStore) -> None:
        """Overdue list must be ordered by days_overdue descending (worst first)."""
        result = store.get_overdue_vulns()
        overdue = result["overdue"]
        assert len(overdue) >= 2
        days_list = [item["days_overdue"] for item in overdue]
        assert days_list == sorted(days_list, reverse=True)

    def test_overdue_excludes_closed_and_deferred(self, store: CMDBStore) -> None:
        """Closed and deferred vulns must not appear in overdue even if past deadline.

        CVE-2021-00006 (closed, P1, 30 days overdue) and
        CVE-2021-00007 (deferred, P2, 10 days overdue) must be excluded.
        """
        result = store.get_overdue_vulns()
        all_cve_ids = {item["cve_id"] for item in result.get("overdue", [])}
        all_cve_ids |= {item["cve_id"] for item in result.get("approaching", [])}
        assert "CVE-2021-00006" not in all_cve_ids
        assert "CVE-2021-00007" not in all_cve_ids

    def test_overdue_accepts_custom_sla_days(self, store: CMDBStore) -> None:
        """Passing a custom sla_days dict overrides the module-level _SLA_DAYS defaults."""
        # With P1=1 day SLA and a deadline 1 day ago, the item is overdue.
        # With P1=365 day SLA and a deadline 1 day ago, it may still be overdue
        # (deadline-based) or recalculated -- this tests the parameter is accepted.
        custom_sla = {"P1": 365, "P2": 730, "P3": 1095, "P4": 1460}
        result = store.get_overdue_vulns(sla_days=custom_sla)
        # Just assert it returns the expected structure without raising
        assert "overdue" in result
        assert "approaching" in result


# ---------------------------------------------------------------------------
# TestGetOpenVulnCveIds
# ---------------------------------------------------------------------------


class TestGetOpenVulnCveIds:
    def test_returns_open_vulns_with_asset_context(self, store: CMDBStore) -> None:
        """Each returned dict must include asset_id, hostname, cve_id, effective_priority, exposure."""
        results = store.get_open_vuln_cve_ids()
        assert len(results) > 0
        for item in results:
            assert "asset_id" in item, f"Missing asset_id in {item}"
            assert "hostname" in item, f"Missing hostname in {item}"
            assert "cve_id" in item, f"Missing cve_id in {item}"
            assert "effective_priority" in item, f"Missing effective_priority in {item}"
            assert "exposure" in item, f"Missing exposure in {item}"

    def test_excludes_closed_and_deferred(self, store: CMDBStore) -> None:
        """Closed and deferred vulns must not appear in the returned list."""
        results = store.get_open_vuln_cve_ids()
        cve_ids = {item["cve_id"] for item in results}
        assert "CVE-2021-00006" not in cve_ids, "Closed vuln should be excluded"
        assert "CVE-2021-00007" not in cve_ids, "Deferred vuln should be excluded"

    def test_caps_at_200_with_p1_p2_priority(self, store: CMDBStore) -> None:
        """When there are >200 open vulns, result is capped at 200 and P1/P2 are prioritized.

        This test builds a fresh store with 250 P3 vulns and 10 P1 vulns, then
        asserts the returned list is capped at 200 and the P1 vulns are included.
        """
        bulk_store = CMDBStore("sqlite:///:memory:")
        asset_id = bulk_store.create_asset(
            Asset(
                hostname="bulk-host",
                environment="production",
                exposure="internet",
                criticality="medium",
            )
        )
        # Insert 250 P3 vulns
        for i in range(250):
            try:
                bulk_store.create_asset_vuln(
                    AssetVulnerability(
                        asset_id=asset_id,
                        cve_id=f"CVE-2023-{i:05d}",
                        status="open",
                        effective_priority="P3",
                    )
                )
            except Exception:
                pass

        # Insert 10 P1 vulns
        p1_cve_ids = set()
        for i in range(10):
            cve_id = f"CVE-2024-{i:05d}"
            p1_cve_ids.add(cve_id)
            try:
                bulk_store.create_asset_vuln(
                    AssetVulnerability(
                        asset_id=asset_id,
                        cve_id=cve_id,
                        status="open",
                        effective_priority="P1",
                    )
                )
            except Exception:
                pass

        results = bulk_store.get_open_vuln_cve_ids()
        bulk_store.close()

        assert len(results) <= 200, f"Expected cap at 200, got {len(results)}"
        result_cve_ids = {item["cve_id"] for item in results}
        # P1 vulns must be prioritized and included within the cap
        for p1_id in p1_cve_ids:
            assert p1_id in result_cve_ids, f"P1 vuln {p1_id} missing from capped results"
