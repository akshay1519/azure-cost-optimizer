"""Tests for Azure Cost Optimizer - Scanner Module."""

import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, PropertyMock

from analyzer.scanner import (
    AzureScanner,
    ScanResult,
    Finding,
    WasteCategory,
)


class TestFinding:
    def test_finding_creation(self):
        f = Finding(
            resource_id="/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
            resource_name="vm1",
            resource_group="rg1",
            category=WasteCategory.IDLE_VM,
            severity="high",
            current_cost_monthly=140.16,
            estimated_savings_monthly=140.16,
            recommendation="Deallocate idle VM",
        )
        assert f.resource_name == "vm1"
        assert f.severity == "high"
        assert f.estimated_savings_monthly == 140.16
        assert f.category == WasteCategory.IDLE_VM

    def test_finding_default_timestamp(self):
        f = Finding(
            resource_id="id",
            resource_name="test",
            resource_group="rg",
            category=WasteCategory.UNATTACHED_DISK,
            severity="medium",
            current_cost_monthly=50.0,
            estimated_savings_monthly=50.0,
            recommendation="Delete disk",
        )
        assert f.timestamp  # Should have a default timestamp


class TestScanResult:
    def test_empty_result(self):
        r = ScanResult(
            subscription_id="test-sub",
            subscription_name="Test Subscription",
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
        )
        assert len(r.findings) == 0
        assert r.total_monthly_waste == 0.0

    def test_add_finding(self):
        r = ScanResult(
            subscription_id="test-sub",
            subscription_name="Test",
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
        )
        f = Finding(
            resource_id="id1",
            resource_name="vm1",
            resource_group="rg1",
            category=WasteCategory.IDLE_VM,
            severity="high",
            current_cost_monthly=100.0,
            estimated_savings_monthly=100.0,
            recommendation="Delete",
        )
        r.add_finding(f)
        assert len(r.findings) == 1
        assert r.total_monthly_waste == 100.0

    def test_add_multiple_findings(self):
        r = ScanResult(
            subscription_id="test-sub",
            subscription_name="Test",
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
        )
        for i, amount in enumerate([100.0, 50.0, 25.0]):
            r.add_finding(Finding(
                resource_id=f"id{i}",
                resource_name=f"resource{i}",
                resource_group="rg",
                category=WasteCategory.IDLE_VM,
                severity="high",
                current_cost_monthly=amount,
                estimated_savings_monthly=amount,
                recommendation="Fix it",
            ))
        assert len(r.findings) == 3
        assert r.total_monthly_waste == 175.0


class TestAzureScanner:
    @patch("analyzer.scanner.DefaultAzureCredential")
    @patch("analyzer.scanner.ComputeManagementClient")
    @patch("analyzer.scanner.NetworkManagementClient")
    @patch("analyzer.scanner.MonitorManagementClient")
    @patch("analyzer.scanner.ResourceManagementClient")
    def test_scanner_initialization(self, mock_resource, mock_monitor, mock_network, mock_compute, mock_cred):
        scanner = AzureScanner(subscription_id="test-sub-123")
        assert scanner.subscription_id == "test-sub-123"
        assert scanner.idle_cpu_threshold == 5.0
        assert scanner.idle_days == 14

    @patch("analyzer.scanner.DefaultAzureCredential")
    @patch("analyzer.scanner.ComputeManagementClient")
    @patch("analyzer.scanner.NetworkManagementClient")
    @patch("analyzer.scanner.MonitorManagementClient")
    @patch("analyzer.scanner.ResourceManagementClient")
    def test_scanner_custom_thresholds(self, mock_resource, mock_monitor, mock_network, mock_compute, mock_cred):
        scanner = AzureScanner(
            subscription_id="test-sub",
            idle_cpu_threshold=10.0,
            idle_days=7,
            oversized_cpu_threshold=15.0,
            snapshot_age_days=60,
        )
        assert scanner.idle_cpu_threshold == 10.0
        assert scanner.idle_days == 7
        assert scanner.oversized_cpu_threshold == 15.0
        assert scanner.snapshot_age_days == 60

    def test_estimate_vm_cost_known_size(self):
        assert AzureScanner.VM_PRICING["standard_d4s_v3"] == 140.16

    def test_estimate_disk_cost(self):
        assert AzureScanner._estimate_disk_cost(32) == 19.71
        assert AzureScanner._estimate_disk_cost(64) == 38.21
        assert AzureScanner._estimate_disk_cost(128) == 73.22
        assert AzureScanner._estimate_disk_cost(256) == 140.71
        assert AzureScanner._estimate_disk_cost(512) == 270.34
        assert AzureScanner._estimate_disk_cost(1024) == 540.68

    @patch("analyzer.scanner.DefaultAzureCredential")
    @patch("analyzer.scanner.ComputeManagementClient")
    @patch("analyzer.scanner.NetworkManagementClient")
    @patch("analyzer.scanner.MonitorManagementClient")
    @patch("analyzer.scanner.ResourceManagementClient")
    def test_scan_unattached_disks(self, mock_resource, mock_monitor, mock_network, mock_compute, mock_cred):
        # Create mock disk
        mock_disk = MagicMock()
        mock_disk.id = "/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.Compute/disks/disk1"
        mock_disk.name = "orphaned-disk"
        mock_disk.disk_state = "Unattached"
        mock_disk.managed_by = None
        mock_disk.disk_size_gb = 64
        mock_disk.sku = MagicMock()
        mock_disk.sku.name = "Premium_LRS"
        mock_disk.location = "eastus"
        mock_disk.time_created = datetime(2025, 1, 1, tzinfo=timezone.utc)

        mock_compute_instance = mock_compute.return_value
        mock_compute_instance.disks.list.return_value = [mock_disk]

        scanner = AzureScanner(subscription_id="test-sub")
        findings = scanner._scan_unattached_disks()

        assert len(findings) == 1
        assert findings[0].category == WasteCategory.UNATTACHED_DISK
        assert findings[0].resource_name == "orphaned-disk"
        assert findings[0].estimated_savings_monthly == 38.21

    @patch("analyzer.scanner.DefaultAzureCredential")
    @patch("analyzer.scanner.ComputeManagementClient")
    @patch("analyzer.scanner.NetworkManagementClient")
    @patch("analyzer.scanner.MonitorManagementClient")
    @patch("analyzer.scanner.ResourceManagementClient")
    def test_scan_unused_public_ips(self, mock_resource, mock_monitor, mock_network, mock_compute, mock_cred):
        mock_ip = MagicMock()
        mock_ip.id = "/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/ip1"
        mock_ip.name = "unused-ip"
        mock_ip.ip_configuration = None
        mock_ip.ip_address = "20.0.0.1"
        mock_ip.public_ip_allocation_method = "Static"
        mock_ip.sku = MagicMock()
        mock_ip.sku.name = "Basic"
        mock_ip.location = "eastus"

        mock_network_instance = mock_network.return_value
        mock_network_instance.public_ip_addresses.list_all.return_value = [mock_ip]

        scanner = AzureScanner(subscription_id="test-sub")
        findings = scanner._scan_unused_public_ips()

        assert len(findings) == 1
        assert findings[0].category == WasteCategory.UNUSED_PUBLIC_IP
        assert findings[0].resource_name == "unused-ip"

    @patch("analyzer.scanner.DefaultAzureCredential")
    @patch("analyzer.scanner.ComputeManagementClient")
    @patch("analyzer.scanner.NetworkManagementClient")
    @patch("analyzer.scanner.MonitorManagementClient")
    @patch("analyzer.scanner.ResourceManagementClient")
    def test_scan_old_snapshots(self, mock_resource, mock_monitor, mock_network, mock_compute, mock_cred):
        mock_snap = MagicMock()
        mock_snap.id = "/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.Compute/snapshots/snap1"
        mock_snap.name = "old-snapshot"
        mock_snap.time_created = datetime(2025, 6, 1, tzinfo=timezone.utc)  # Old enough
        mock_snap.disk_size_gb = 128
        mock_snap.location = "eastus"

        mock_compute_instance = mock_compute.return_value
        mock_compute_instance.snapshots.list.return_value = [mock_snap]

        scanner = AzureScanner(subscription_id="test-sub", snapshot_age_days=30)
        findings = scanner._scan_old_snapshots()

        assert len(findings) == 1
        assert findings[0].category == WasteCategory.OLD_SNAPSHOT
        assert findings[0].resource_name == "old-snapshot"
        # 128 GB * $0.05 = $6.40/month
        assert findings[0].estimated_savings_monthly == 6.40


class TestWasteCategory:
    def test_all_categories_exist(self):
        assert WasteCategory.IDLE_VM.value == "idle_vm"
        assert WasteCategory.OVERSIZED_VM.value == "oversized_vm"
        assert WasteCategory.UNATTACHED_DISK.value == "unattached_disk"
        assert WasteCategory.UNUSED_PUBLIC_IP.value == "unused_public_ip"
        assert WasteCategory.OLD_SNAPSHOT.value == "old_snapshot"
        assert WasteCategory.STOPPED_VM_WITH_DISK.value == "stopped_vm_with_premium_disk"
