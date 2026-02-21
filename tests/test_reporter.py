"""Tests for Azure Cost Optimizer - Reporter Module."""

import json
import pytest
from datetime import datetime, timezone

from analyzer.scanner import ScanResult, Finding, WasteCategory
from analyzer.reporter import ReportGenerator


@pytest.fixture
def sample_scan_result():
    """Create a sample scan result with various findings."""
    result = ScanResult(
        subscription_id="12345678-abcd-1234-efgh-123456789012",
        subscription_name="Production Subscription",
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
    )

    findings = [
        Finding(
            resource_id="/subscriptions/sub/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/web-server-01",
            resource_name="web-server-01",
            resource_group="rg-prod",
            category=WasteCategory.IDLE_VM,
            severity="high",
            current_cost_monthly=280.32,
            estimated_savings_monthly=280.32,
            recommendation="VM 'web-server-01' has avg CPU 2.1% over 14 days. Deallocate to save $280.32/month.",
            details={"vm_size": "Standard_D8s_v3", "avg_cpu_percent": 2.1},
        ),
        Finding(
            resource_id="/subscriptions/sub/resourceGroups/rg-dev/providers/Microsoft.Compute/virtualMachines/dev-box-02",
            resource_name="dev-box-02",
            resource_group="rg-dev",
            category=WasteCategory.OVERSIZED_VM,
            severity="medium",
            current_cost_monthly=140.16,
            estimated_savings_monthly=70.08,
            recommendation="VM 'dev-box-02' has avg CPU 8.3%. Downsize to Standard_D2s_v3.",
            details={"current_size": "Standard_D4s_v3", "suggested_size": "Standard_D2s_v3"},
        ),
        Finding(
            resource_id="/subscriptions/sub/resourceGroups/rg-prod/providers/Microsoft.Compute/disks/orphaned-disk-01",
            resource_name="orphaned-disk-01",
            resource_group="rg-prod",
            category=WasteCategory.UNATTACHED_DISK,
            severity="medium",
            current_cost_monthly=73.22,
            estimated_savings_monthly=73.22,
            recommendation="Disk 'orphaned-disk-01' (128GB) is unattached. Delete to save $73.22/month.",
        ),
        Finding(
            resource_id="/subscriptions/sub/resourceGroups/rg-dev/providers/Microsoft.Network/publicIPAddresses/unused-ip",
            resource_name="unused-ip",
            resource_group="rg-dev",
            category=WasteCategory.UNUSED_PUBLIC_IP,
            severity="low",
            current_cost_monthly=3.65,
            estimated_savings_monthly=3.65,
            recommendation="Public IP 'unused-ip' is not associated with any resource.",
        ),
    ]

    for f in findings:
        result.add_finding(f)

    return result


class TestReportGenerator:
    def test_console_report(self, sample_scan_result):
        reporter = ReportGenerator(sample_scan_result)
        report = reporter.generate_console_report()

        assert "AZURE COST OPTIMIZATION REPORT" in report
        assert "Production Subscription" in report
        assert "web-server-01" in report
        assert "$427.27" in report  # Total monthly waste

    def test_json_report_valid(self, sample_scan_result):
        reporter = ReportGenerator(sample_scan_result)
        report = reporter.generate_json_report()

        data = json.loads(report)
        assert data["meta"]["tool"] == "Azure Cost Optimizer"
        assert data["summary"]["total_findings"] == 4
        assert data["summary"]["total_monthly_waste"] == 427.27
        assert len(data["findings"]) == 4

    def test_json_report_structure(self, sample_scan_result):
        reporter = ReportGenerator(sample_scan_result)
        data = json.loads(reporter.generate_json_report())

        for finding in data["findings"]:
            assert "resource_id" in finding
            assert "resource_name" in finding
            assert "category" in finding
            assert "severity" in finding
            assert "current_cost_monthly" in finding
            assert "estimated_savings_monthly" in finding
            assert "recommendation" in finding

    def test_csv_report(self, sample_scan_result):
        reporter = ReportGenerator(sample_scan_result)
        report = reporter.generate_csv_report()

        lines = report.strip().split("\n")
        assert len(lines) == 5  # header + 4 findings
        assert "Resource Name" in lines[0]
        assert "web-server-01" in report

    def test_html_report(self, sample_scan_result):
        reporter = ReportGenerator(sample_scan_result)
        report = reporter.generate_html_report()

        assert "<!DOCTYPE html>" in report
        assert "Azure Cost Optimization Report" in report
        assert "web-server-01" in report
        assert "$427.27" in report

    def test_empty_scan_result(self):
        result = ScanResult(
            subscription_id="empty-sub",
            subscription_name="Empty",
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
        )
        reporter = ReportGenerator(result)

        console = reporter.generate_console_report()
        assert "Total Findings: 0" in console

        data = json.loads(reporter.generate_json_report())
        assert data["summary"]["total_findings"] == 0

    def test_save_report(self, sample_scan_result, tmp_path):
        reporter = ReportGenerator(sample_scan_result)
        saved = reporter.save_report(output_dir=str(tmp_path), formats=["json", "csv"])

        assert len(saved) == 2
        for path in saved:
            assert tmp_path.name in path

    def test_count_by_severity(self, sample_scan_result):
        reporter = ReportGenerator(sample_scan_result)
        by_sev = reporter._count_by_severity()

        assert by_sev["high"]["count"] == 1
        assert by_sev["medium"]["count"] == 2
        assert by_sev["low"]["count"] == 1

    def test_count_by_category(self, sample_scan_result):
        reporter = ReportGenerator(sample_scan_result)
        by_cat = reporter._count_by_category()

        assert by_cat["idle_vm"]["count"] == 1
        assert by_cat["oversized_vm"]["count"] == 1
        assert by_cat["unattached_disk"]["count"] == 1
        assert by_cat["unused_public_ip"]["count"] == 1
