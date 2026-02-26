"""Unit tests for SLA overdue calculation logic in cmdb/store.py.

Covers:
- Days-overdue calculation from ISO deadline strings
- Overdue list sort ordering (most overdue first)
- Approaching-SLA detection (within N days of deadline)
- SLA defaults match CONTEXT.md decisions (P1=7, P2=30, P3=90, P4=180)
"""

from datetime import datetime, timedelta, timezone

import pytest

from cmdb.models import Asset, AssetVulnerability
from cmdb.store import _SLA_DAYS, CMDBStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_store_with_overdue_vulns(days_overdue_list: list[int], days_approaching_list: list[int]) -> CMDBStore:
    """Build a fresh in-memory CMDBStore with vulns at specific deadline offsets.

    days_overdue_list: positive integers, each becomes a deadline that many days ago
    days_approaching_list: positive integers, each becomes a deadline that many days from now
    """
    s = CMDBStore("sqlite:///:memory:")
    asset_id = s.create_asset(
        Asset(
            hostname="sla-test-host",
            environment="production",
            exposure="internal",
            criticality="medium",
        )
    )
    now = datetime.now(timezone.utc)
    counter = 1

    for days in days_overdue_list:
        deadline = (now - timedelta(days=days)).isoformat()
        try:
            s.create_asset_vuln(
                AssetVulnerability(
                    asset_id=asset_id,
                    cve_id=f"CVE-2020-{counter:05d}",
                    status="open",
                    effective_priority="P1",
                    deadline=deadline,
                )
            )
        except Exception:
            pass
        counter += 1

    for days in days_approaching_list:
        deadline = (now + timedelta(days=days)).isoformat()
        try:
            s.create_asset_vuln(
                AssetVulnerability(
                    asset_id=asset_id,
                    cve_id=f"CVE-2020-{counter:05d}",
                    status="open",
                    effective_priority="P2",
                    deadline=deadline,
                )
            )
        except Exception:
            pass
        counter += 1

    return s


# ---------------------------------------------------------------------------
# TestSlaDefaults
# ---------------------------------------------------------------------------


class TestSlaDefaults:
    @pytest.mark.xfail(reason="Awaiting 03-01 update: _SLA_DAYS changes to {P1:7, P2:30, P3:90, P4:180}")
    def test_sla_defaults_match_context(self) -> None:
        """_SLA_DAYS must match the CONTEXT.md decision after 03-01 updates the constant.

        Current value: {P1: 1, P2: 7, P3: 30}
        Expected after 03-01: {P1: 7, P2: 30, P3: 90, P4: 180}
        """
        expected = {"P1": 7, "P2": 30, "P3": 90, "P4": 180}
        assert _SLA_DAYS == expected, f"Expected {expected}, got {_SLA_DAYS}"


# ---------------------------------------------------------------------------
# TestDaysOverdue
# ---------------------------------------------------------------------------


class TestDaysOverdue:
    @pytest.mark.xfail(reason="Awaiting 03-01 implementation of _days_overdue() helper")
    def test_past_deadline_returns_positive_days(self) -> None:
        """A deadline 10 days ago should return approximately 10 days overdue."""
        from cmdb.store import _days_overdue  # type: ignore[attr-defined]

        deadline = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        result = _days_overdue(deadline)
        # Allow 1-day tolerance for test timing edge cases
        assert 9 <= result <= 11, f"Expected ~10, got {result}"

    @pytest.mark.xfail(reason="Awaiting 03-01 implementation of _days_overdue() helper")
    def test_future_deadline_returns_negative_days(self) -> None:
        """A deadline 5 days in the future should return a negative value."""
        from cmdb.store import _days_overdue  # type: ignore[attr-defined]

        deadline = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        result = _days_overdue(deadline)
        assert result < 0, f"Expected negative value for future deadline, got {result}"

    @pytest.mark.xfail(reason="Awaiting 03-01 implementation of _days_overdue() helper")
    def test_today_deadline_returns_zero_or_one(self) -> None:
        """A deadline for today (within the current day) should return 0 or 1."""
        from cmdb.store import _days_overdue  # type: ignore[attr-defined]

        deadline = datetime.now(timezone.utc).isoformat()
        result = _days_overdue(deadline)
        assert result in (0, 1), f"Expected 0 or 1 for today's deadline, got {result}"

    @pytest.mark.xfail(reason="Awaiting 03-01 implementation of _days_overdue() helper")
    def test_naive_datetime_treated_as_utc(self) -> None:
        """A deadline string without timezone info must not raise and returns a reasonable value."""
        from cmdb.store import _days_overdue  # type: ignore[attr-defined]

        # Naive ISO string (no +00:00 suffix)
        naive_deadline = (datetime.utcnow() - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%S")
        result = _days_overdue(naive_deadline)
        # Should be approximately 5 days, treated as UTC
        assert isinstance(result, (int, float)), f"Expected numeric result, got {type(result)}"
        assert result >= 0, f"Expected non-negative for past naive deadline, got {result}"

    @pytest.mark.xfail(reason="Awaiting 03-01 implementation of _days_overdue() helper")
    def test_timezone_aware_deadline_handled(self) -> None:
        """A deadline with explicit UTC timezone offset must produce correct result."""
        from cmdb.store import _days_overdue  # type: ignore[attr-defined]

        deadline = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        result = _days_overdue(deadline)
        # 7 days overdue, allow 1-day tolerance
        assert 6 <= result <= 8, f"Expected ~7, got {result}"


# ---------------------------------------------------------------------------
# TestOverdueSort
# ---------------------------------------------------------------------------


class TestOverdueSort:
    @pytest.mark.xfail(reason="Awaiting 03-01 implementation of get_overdue_vulns()")
    def test_overdue_items_sorted_most_overdue_first(self) -> None:
        """Overdue list must be ordered by days_overdue descending: [45, 30, 10]."""
        s = _make_store_with_overdue_vulns(days_overdue_list=[30, 10, 45], days_approaching_list=[])
        try:
            result = s.get_overdue_vulns()
            overdue = result.get("overdue", [])
            assert len(overdue) == 3, f"Expected 3 overdue items, got {len(overdue)}"
            days_list = [item["days_overdue"] for item in overdue]
            assert days_list == sorted(days_list, reverse=True), f"Expected descending order, got {days_list}"
            # Verify approximate magnitudes: first ~45, last ~10
            assert days_list[0] > days_list[-1]
        finally:
            s.close()

    @pytest.mark.xfail(reason="Awaiting 03-01 implementation of get_overdue_vulns()")
    def test_approaching_items_sorted_closest_first(self) -> None:
        """Approaching list must be ordered by deadline ascending (closest due date first): [1, 3, 5]."""
        s = _make_store_with_overdue_vulns(days_overdue_list=[], days_approaching_list=[5, 1, 3])
        try:
            result = s.get_overdue_vulns()
            approaching = result.get("approaching", [])
            assert len(approaching) == 3, f"Expected 3 approaching items, got {len(approaching)}"
            # Each item should have days_until_due (or similar) showing the ordering
            # Alternatively check that the first item has the smallest days until deadline
            # The field name will be determined by 03-01 implementation
            # Accept either days_until_due or days_overdue (negative = days until)
            field = "days_until_due" if "days_until_due" in approaching[0] else "days_overdue"
            values = [item[field] for item in approaching]
            assert values == sorted(values), f"Expected ascending order for approaching, got {values}"
        finally:
            s.close()
