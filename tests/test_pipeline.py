"""Unit tests for core/pipeline.py — process_cve and process_cves.

All external I/O (HTTP fetchers, SQLite cache) is mocked. Tests focus on:
- CVE ID validation
- Cache hit / cache miss behavior
- Deduplication in process_cves
- Error handling (invalid format, NVD not found)
"""

from unittest.mock import MagicMock, patch

import pytest

from core.pipeline import process_cve, process_cves

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

_VALID_ID = "CVE-2021-44228"

# Minimal NVD CVE dict — enough for enrich() to produce an EnrichedCVE
_MINIMAL_CVE_RAW = {
    "id": _VALID_ID,
    "descriptions": [{"lang": "en", "value": "Test description."}],
    "metrics": {},
    "weaknesses": [],
    "configurations": [],
    "references": [],
}

_EPSS_DATA = {"score": 0.5, "percentile": 0.9}
_POC_DATA = {"has_poc": True, "count": 2, "sources": ["GitHub"]}

# ---------------------------------------------------------------------------
# TestProcessCve
# ---------------------------------------------------------------------------


class TestProcessCve:
    def test_invalid_format_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid CVE ID format"):
            process_cve("not-a-cve", kev_set=set())

    def test_lowercase_id_normalized_and_accepted(self):
        """process_cve uppercases the ID before validation."""
        with patch("core.pipeline.fetch_nvd", return_value=None):
            result = process_cve("cve-2021-44228", kev_set=set())
        assert result is None  # fetch returned None, so process_cve returns None

    def test_nvd_not_found_returns_none(self):
        with patch("core.pipeline.fetch_nvd", return_value=None):
            result = process_cve(_VALID_ID, kev_set=set())
        assert result is None

    def test_cache_hit_skips_fetcher(self):
        """When cache returns data, fetch_nvd must not be called."""
        cached_payload = {
            "cve_raw": _MINIMAL_CVE_RAW,
            "epss_data": _EPSS_DATA,
            "poc_data": _POC_DATA,
        }
        cache = MagicMock()
        cache.get.return_value = cached_payload

        with patch("core.pipeline.fetch_nvd") as mock_fetch:
            result = process_cve(_VALID_ID, kev_set=set(), cache=cache)

        mock_fetch.assert_not_called()
        assert result is not None
        assert result.id == _VALID_ID

    def test_cache_miss_calls_fetchers_and_stores(self):
        """Cache miss triggers fetchers and stores result."""
        cache = MagicMock()
        cache.get.return_value = None  # miss

        with (
            patch("core.pipeline.fetch_nvd", return_value=_MINIMAL_CVE_RAW),
            patch("core.pipeline.fetch_epss", return_value=_EPSS_DATA),
            patch("core.pipeline.fetch_poc", return_value=_POC_DATA),
        ):
            result = process_cve(_VALID_ID, kev_set=set(), cache=cache)

        cache.set.assert_called_once()
        assert result is not None
        assert result.id == _VALID_ID

    def test_no_cache_calls_fetchers_no_store(self):
        """With cache=None, fetchers are called but no cache.set call is made."""
        with (
            patch("core.pipeline.fetch_nvd", return_value=_MINIMAL_CVE_RAW),
            patch("core.pipeline.fetch_epss", return_value=_EPSS_DATA),
            patch("core.pipeline.fetch_poc", return_value=_POC_DATA),
        ):
            result = process_cve(_VALID_ID, kev_set=set(), cache=None)

        assert result is not None
        assert result.id == _VALID_ID

    def test_kev_set_membership_flows_through(self):
        """CVE in kev_set results in is_kev=True on the enriched result."""
        with (
            patch("core.pipeline.fetch_nvd", return_value=_MINIMAL_CVE_RAW),
            patch("core.pipeline.fetch_epss", return_value={}),
            patch("core.pipeline.fetch_poc", return_value={}),
        ):
            result = process_cve(_VALID_ID, kev_set={_VALID_ID}, cache=None)

        assert result is not None
        assert result.is_kev is True

    def test_nvd_api_key_forwarded_to_fetch_nvd(self):
        """nvd_api_key is passed through to fetch_nvd."""
        with (
            patch("core.pipeline.fetch_nvd", return_value=_MINIMAL_CVE_RAW) as mock_nvd,
            patch("core.pipeline.fetch_epss", return_value={}),
            patch("core.pipeline.fetch_poc", return_value={}),
        ):
            process_cve(_VALID_ID, kev_set=set(), nvd_api_key="test-key")

        mock_nvd.assert_called_once_with(_VALID_ID, api_key="test-key")

    def test_exposure_internal_default(self):
        """Default exposure is 'internal' — no assertion needed on triage since it depends
        on CVSS score, but the call must not raise."""
        with (
            patch("core.pipeline.fetch_nvd", return_value=_MINIMAL_CVE_RAW),
            patch("core.pipeline.fetch_epss", return_value={}),
            patch("core.pipeline.fetch_poc", return_value={}),
        ):
            result = process_cve(_VALID_ID, kev_set=set())

        assert result is not None


# ---------------------------------------------------------------------------
# TestProcessCves
# ---------------------------------------------------------------------------


class TestProcessCves:
    def test_empty_list_returns_empty(self):
        result = process_cves([], kev_set=set())
        assert result == []

    def test_invalid_id_skipped_silently(self):
        """process_cves catches ValueError and skips invalid IDs."""
        result = process_cves(["not-a-cve", "also-bad"], kev_set=set())
        assert result == []

    def test_nvd_not_found_skipped(self):
        """process_cves skips CVEs where fetch_nvd returns None."""
        with patch("core.pipeline.fetch_nvd", return_value=None):
            result = process_cves([_VALID_ID], kev_set=set())
        assert result == []

    def test_valid_id_returned(self):
        with (
            patch("core.pipeline.fetch_nvd", return_value=_MINIMAL_CVE_RAW),
            patch("core.pipeline.fetch_epss", return_value={}),
            patch("core.pipeline.fetch_poc", return_value={}),
        ):
            result = process_cves([_VALID_ID], kev_set=set())

        assert len(result) == 1
        assert result[0].id == _VALID_ID

    def test_deduplication_case_insensitive(self):
        """Duplicate CVE IDs (different case) are processed only once."""
        with (
            patch("core.pipeline.fetch_nvd", return_value=_MINIMAL_CVE_RAW) as mock_nvd,
            patch("core.pipeline.fetch_epss", return_value={}),
            patch("core.pipeline.fetch_poc", return_value={}),
        ):
            result = process_cves([_VALID_ID, _VALID_ID.lower(), _VALID_ID], kev_set=set())

        assert len(result) == 1
        mock_nvd.assert_called_once()

    def test_mixed_valid_invalid_returns_only_valid(self):
        """Invalid IDs are skipped; valid IDs are processed normally."""
        valid_id_2 = "CVE-2022-12345"
        raw_2 = {**_MINIMAL_CVE_RAW, "id": valid_id_2}

        def fake_nvd(cve_id, api_key=None):
            if cve_id == _VALID_ID:
                return _MINIMAL_CVE_RAW
            if cve_id == valid_id_2:
                return raw_2
            return None

        with (
            patch("core.pipeline.fetch_nvd", side_effect=fake_nvd),
            patch("core.pipeline.fetch_epss", return_value={}),
            patch("core.pipeline.fetch_poc", return_value={}),
        ):
            result = process_cves(["bad-id", _VALID_ID, valid_id_2], kev_set=set())

        assert len(result) == 2
        ids = {r.id for r in result}
        assert _VALID_ID in ids
        assert valid_id_2 in ids

    def test_order_preserved_after_dedup(self):
        """First-occurrence order is preserved after deduplication."""
        id_a = "CVE-2021-44228"
        id_b = "CVE-2022-12345"
        raw_b = {**_MINIMAL_CVE_RAW, "id": id_b}

        def fake_nvd(cve_id, api_key=None):
            return _MINIMAL_CVE_RAW if cve_id == id_a else raw_b

        with (
            patch("core.pipeline.fetch_nvd", side_effect=fake_nvd),
            patch("core.pipeline.fetch_epss", return_value={}),
            patch("core.pipeline.fetch_poc", return_value={}),
        ):
            result = process_cves([id_a, id_b, id_a], kev_set=set())  # id_a duplicated at end

        assert len(result) == 2
        assert result[0].id == id_a
        assert result[1].id == id_b
