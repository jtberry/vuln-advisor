"""
tests/test_ingest.py -- Unit tests for cmdb/ingest.py parser functions.

All four parsers are tested here: parse_csv, parse_trivy_json,
parse_grype_json, and parse_nessus_csv. These are pure functions (no I/O,
no DB) so no fixtures or mocking are needed -- call them directly with
inline test data.

Coverage: valid input, invalid input, edge cases, and skipping bad rows.

Learning note: Testing boundary conditions (empty hostname, non-CVE IDs,
invalid JSON) is just as important as testing the happy path. Edge cases
expose parser fragility before it reaches production data.
"""

import json

from cmdb.ingest import parse_csv, parse_grype_json, parse_nessus_csv, parse_trivy_json

# ===========================================================================
# parse_csv tests
# ===========================================================================


class TestParseCsv:
    """Tests for the generic CSV ingest parser."""

    def test_valid_single_row_returns_one_record(self):
        """Happy path: one valid row produces one IngestRecord."""
        content = "hostname,cve_id\nwebserver01,CVE-2021-44228\n"
        records = parse_csv(content)
        assert len(records) == 1
        assert records[0].hostname == "webserver01"
        assert records[0].cve_id == "CVE-2021-44228"
        assert records[0].scanner == "csv"

    def test_multiple_valid_rows_returns_correct_count(self):
        """Multiple valid rows each produce one IngestRecord."""
        content = "hostname,cve_id\nhost1,CVE-2021-44228\nhost2,CVE-2022-0001\n"
        records = parse_csv(content)
        assert len(records) == 2
        assert records[0].cve_id == "CVE-2021-44228"
        assert records[1].cve_id == "CVE-2022-0001"

    def test_row_with_empty_hostname_is_skipped(self):
        """Rows with an empty hostname field are silently dropped."""
        content = "hostname,cve_id\n,CVE-2021-44228\n"
        records = parse_csv(content)
        assert records == []

    def test_row_with_empty_cve_id_is_skipped(self):
        """Rows with an empty cve_id field are silently dropped."""
        content = "hostname,cve_id\nwebserver01,\n"
        records = parse_csv(content)
        assert records == []

    def test_extra_columns_are_ignored(self):
        """Columns beyond hostname,cve_id do not break parsing."""
        content = "hostname,cve_id,severity,score\nhost1,CVE-2021-44228,HIGH,9.8\n"
        records = parse_csv(content)
        assert len(records) == 1
        assert records[0].hostname == "host1"
        assert records[0].cve_id == "CVE-2021-44228"

    def test_cve_id_is_uppercased(self):
        """Lowercase CVE IDs are normalized to uppercase."""
        content = "hostname,cve_id\nhost1,cve-2021-44228\n"
        records = parse_csv(content)
        assert len(records) == 1
        assert records[0].cve_id == "CVE-2021-44228"

    def test_discovered_at_and_scanner_fields_are_set(self):
        """IngestRecord has discovered_at (non-empty) and scanner='csv'."""
        content = "hostname,cve_id\nhost1,CVE-2021-44228\n"
        records = parse_csv(content)
        assert records[0].scanner == "csv"
        assert records[0].discovered_at  # non-empty ISO timestamp


# ===========================================================================
# parse_trivy_json tests
# ===========================================================================


class TestParseTrivyJson:
    """Tests for the Trivy JSON ingest parser."""

    def _trivy_json(self, artifact_name: str = "my-image:latest", vulns: list = None) -> str:
        """Build a minimal Trivy JSON payload."""
        if vulns is None:
            vulns = [{"VulnerabilityID": "CVE-2021-44228", "PkgName": "log4j"}]
        return json.dumps(
            {
                "ArtifactName": artifact_name,
                "Results": [
                    {
                        "Target": "my-image (ubuntu 22.04)",
                        "Vulnerabilities": vulns,
                    }
                ],
            }
        )

    def test_valid_trivy_json_returns_one_record(self):
        """Happy path: one vulnerability produces one IngestRecord."""
        records = parse_trivy_json(self._trivy_json())
        assert len(records) == 1
        assert records[0].hostname == "my-image:latest"
        assert records[0].cve_id == "CVE-2021-44228"
        assert records[0].scanner == "trivy"

    def test_hostname_from_artifact_name(self):
        """ArtifactName is used as the hostname."""
        records = parse_trivy_json(self._trivy_json(artifact_name="nginx:1.25"))
        assert records[0].hostname == "nginx:1.25"

    def test_invalid_json_returns_empty_list(self):
        """Non-JSON input returns an empty list without raising."""
        records = parse_trivy_json("this is not json")
        assert records == []

    def test_missing_results_key_returns_empty_list(self):
        """JSON without a 'Results' key returns an empty list."""
        records = parse_trivy_json(json.dumps({"ArtifactName": "img:latest"}))
        assert records == []

    def test_non_cve_vulnerability_ids_are_skipped(self):
        """GHSA and other non-CVE IDs are filtered out."""
        vulns = [
            {"VulnerabilityID": "GHSA-xxxx-yyyy-zzzz"},
            {"VulnerabilityID": "CVE-2022-0001"},
        ]
        records = parse_trivy_json(self._trivy_json(vulns=vulns))
        assert len(records) == 1
        assert records[0].cve_id == "CVE-2022-0001"

    def test_missing_artifact_name_defaults_to_unknown(self):
        """Missing ArtifactName falls back to 'unknown' as hostname."""
        payload = json.dumps(
            {
                "Results": [
                    {
                        "Target": "some-target",
                        "Vulnerabilities": [{"VulnerabilityID": "CVE-2021-44228"}],
                    }
                ]
            }
        )
        records = parse_trivy_json(payload)
        assert len(records) == 1
        assert records[0].hostname == "unknown"


# ===========================================================================
# parse_grype_json tests
# ===========================================================================


class TestParseGrypeJson:
    """Tests for the Grype JSON ingest parser."""

    def _grype_json(self, user_input: str = "nginx:latest", cve_id: str = "CVE-2021-44228") -> str:
        """Build a minimal Grype JSON payload."""
        return json.dumps(
            {
                "source": {"target": {"userInput": user_input}},
                "matches": [
                    {
                        "vulnerability": {"id": cve_id},
                        "artifact": {"name": "somelib"},
                    }
                ],
            }
        )

    def test_valid_grype_json_returns_one_record(self):
        """Happy path: one match produces one IngestRecord."""
        records = parse_grype_json(self._grype_json())
        assert len(records) == 1
        assert records[0].hostname == "nginx:latest"
        assert records[0].cve_id == "CVE-2021-44228"
        assert records[0].scanner == "grype"

    def test_hostname_from_source_target_user_input(self):
        """source.target.userInput is used as the hostname."""
        records = parse_grype_json(self._grype_json(user_input="myapp:v2"))
        assert records[0].hostname == "myapp:v2"

    def test_non_cve_vulnerability_ids_are_skipped(self):
        """Non-CVE IDs (e.g. GHSA-) are filtered out."""
        payload = json.dumps(
            {
                "source": {"target": {"userInput": "img:latest"}},
                "matches": [
                    {"vulnerability": {"id": "GHSA-xxxx-yyyy-zzzz"}, "artifact": {}},
                    {"vulnerability": {"id": "CVE-2022-0001"}, "artifact": {}},
                ],
            }
        )
        records = parse_grype_json(payload)
        assert len(records) == 1
        assert records[0].cve_id == "CVE-2022-0001"

    def test_missing_user_input_defaults_to_unknown(self):
        """Missing source.target.userInput falls back to 'unknown'."""
        payload = json.dumps(
            {
                "source": {},
                "matches": [{"vulnerability": {"id": "CVE-2021-44228"}, "artifact": {}}],
            }
        )
        records = parse_grype_json(payload)
        assert records[0].hostname == "unknown"

    def test_invalid_json_returns_empty_list(self):
        """Non-JSON input returns an empty list without raising."""
        records = parse_grype_json("not json at all")
        assert records == []


# ===========================================================================
# parse_nessus_csv tests
# ===========================================================================


class TestParseNessusCsv:
    """Tests for the Nessus CSV ingest parser."""

    _HEADER = "Plugin ID,CVE,CVSS v2.0 Base Score,Risk,Host,Protocol,Port,Name\n"

    def test_single_cve_returns_one_record(self):
        """Happy path: one CVE in the row produces one IngestRecord."""
        content = self._HEADER + "123,CVE-2021-44228,9.8,Critical,10.0.0.1,tcp,443,Log4Shell\n"
        records = parse_nessus_csv(content)
        assert len(records) == 1
        assert records[0].cve_id == "CVE-2021-44228"
        assert records[0].hostname == "10.0.0.1"
        assert records[0].scanner == "nessus"

    def test_comma_separated_cves_expand_to_multiple_records(self):
        """A single row with comma-separated CVE IDs expands to N records.

        Nessus encodes multiple CVEs as a quoted comma-separated value in one
        cell -- DictReader reads it as a single string, which parse_nessus_csv
        then splits on commas.
        """
        content = self._HEADER + '123,"CVE-2021-44228,CVE-2022-0001",9.8,Critical,host1,tcp,80,Test\n'
        records = parse_nessus_csv(content)
        assert len(records) == 2
        cve_ids = {r.cve_id for r in records}
        assert "CVE-2021-44228" in cve_ids
        assert "CVE-2022-0001" in cve_ids

    def test_semicolon_separated_cves_expand_to_multiple_records(self):
        """Semicolon-separated CVE IDs are treated the same as commas."""
        content = self._HEADER + '123,"CVE-2021-44228;CVE-2022-0001",9.8,Critical,host2,tcp,80,Test\n'
        records = parse_nessus_csv(content)
        assert len(records) == 2
        cve_ids = {r.cve_id for r in records}
        assert "CVE-2021-44228" in cve_ids
        assert "CVE-2022-0001" in cve_ids

    def test_row_with_empty_host_is_skipped(self):
        """Rows with an empty Host column are silently dropped."""
        content = self._HEADER + "123,CVE-2021-44228,9.8,Critical,,tcp,80,Test\n"
        records = parse_nessus_csv(content)
        assert records == []

    def test_row_with_empty_cve_column_is_skipped(self):
        """Rows with an empty CVE column are silently dropped."""
        content = self._HEADER + "123,,9.8,Critical,host1,tcp,80,Test\n"
        records = parse_nessus_csv(content)
        assert records == []

    def test_non_cve_ids_in_cve_cell_are_filtered_out(self):
        """Non-CVE IDs (e.g. 'N/A' or GHSA IDs) in the CVE cell are skipped."""
        content = self._HEADER + '123,"GHSA-xxxx,N/A,CVE-2021-44228",9.8,Critical,host1,tcp,80,Test\n'
        records = parse_nessus_csv(content)
        assert len(records) == 1
        assert records[0].cve_id == "CVE-2021-44228"
