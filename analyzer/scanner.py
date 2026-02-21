"""
Azure Resource Scanner - Core module for scanning Azure resources.

Scans VMs, disks, public IPs, and other resources to identify:
- Idle VMs (low CPU/network for 14+ days)
- Oversized VMs (CPU < 10% average, could downsize)
- Unattached disks (orphaned managed disks)
- Unused public IPs (not associated with any resource)
- Old snapshots (older than 30 days)
"""

import logging
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import ResourceManagementClient

logger = logging.getLogger(__name__)


class WasteCategory(Enum):
    """Categories of resource waste."""
    IDLE_VM = "idle_vm"
    OVERSIZED_VM = "oversized_vm"
    UNATTACHED_DISK = "unattached_disk"
    UNUSED_PUBLIC_IP = "unused_public_ip"
    OLD_SNAPSHOT = "old_snapshot"
    STOPPED_VM_WITH_DISK = "stopped_vm_with_premium_disk"


@dataclass
class Finding:
    """A single cost optimization finding."""
    resource_id: str
    resource_name: str
    resource_group: str
    category: WasteCategory
    severity: str  # "high", "medium", "low"
    current_cost_monthly: float
    estimated_savings_monthly: float
    recommendation: str
    details: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ScanResult:
    """Complete scan result for a subscription."""
    subscription_id: str
    subscription_name: str
    scan_timestamp: str
    findings: list[Finding] = field(default_factory=list)
    total_monthly_waste: float = 0.0
    total_resources_scanned: int = 0
    errors: list[str] = field(default_factory=list)

    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        self.total_monthly_waste += finding.estimated_savings_monthly


class AzureScanner:
    """Scans Azure subscriptions for cost optimization opportunities."""

    # VM pricing estimates (USD/month) for common sizes
    VM_PRICING = {
        "standard_b1s": 7.59,
        "standard_b1ms": 15.18,
        "standard_b2s": 30.37,
        "standard_b2ms": 60.74,
        "standard_d2s_v3": 70.08,
        "standard_d4s_v3": 140.16,
        "standard_d8s_v3": 280.32,
        "standard_d16s_v3": 560.64,
        "standard_d2s_v5": 70.08,
        "standard_d4s_v5": 140.16,
        "standard_d8s_v5": 280.32,
        "standard_e2s_v3": 91.98,
        "standard_e4s_v3": 183.96,
        "standard_e8s_v3": 367.92,
        "standard_f2s_v2": 61.32,
        "standard_f4s_v2": 122.64,
        "standard_f8s_v2": 245.28,
    }

    DISK_PRICING = {
        "standard_lrs": {"p10": 19.71, "p20": 38.21, "p30": 73.22, "p40": 140.71, "p50": 270.34},
        "premium_lrs": {"p10": 19.71, "p20": 38.21, "p30": 73.22, "p40": 140.71, "p50": 270.34},
    }

    PUBLIC_IP_MONTHLY = 3.65  # Basic static public IP

    def __init__(
        self,
        subscription_id: str,
        credential: Optional[DefaultAzureCredential] = None,
        idle_cpu_threshold: float = 5.0,
        idle_days: int = 14,
        oversized_cpu_threshold: float = 10.0,
        snapshot_age_days: int = 30,
    ):
        self.subscription_id = subscription_id
        self.credential = credential or DefaultAzureCredential()
        self.idle_cpu_threshold = idle_cpu_threshold
        self.idle_days = idle_days
        self.oversized_cpu_threshold = oversized_cpu_threshold
        self.snapshot_age_days = snapshot_age_days

        # Initialize Azure clients
        self.compute_client = ComputeManagementClient(self.credential, self.subscription_id)
        self.network_client = NetworkManagementClient(self.credential, self.subscription_id)
        self.monitor_client = MonitorManagementClient(self.credential, self.subscription_id)
        self.resource_client = ResourceManagementClient(self.credential, self.subscription_id)

    def scan_all(self) -> ScanResult:
        """Run all scans and return combined results."""
        sub_info = self._get_subscription_name()
        result = ScanResult(
            subscription_id=self.subscription_id,
            subscription_name=sub_info,
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
        )

        scanners = [
            ("VMs", self._scan_idle_vms),
            ("Oversized VMs", self._scan_oversized_vms),
            ("Unattached Disks", self._scan_unattached_disks),
            ("Unused Public IPs", self._scan_unused_public_ips),
            ("Old Snapshots", self._scan_old_snapshots),
            ("Stopped VMs with Premium Disks", self._scan_stopped_vms_premium_disks),
        ]

        for name, scanner_fn in scanners:
            try:
                logger.info(f"Scanning: {name}...")
                findings = scanner_fn()
                for f in findings:
                    result.add_finding(f)
                result.total_resources_scanned += len(findings)
                logger.info(f"  Found {len(findings)} issues in {name}")
            except Exception as e:
                error_msg = f"Error scanning {name}: {str(e)}"
                logger.error(error_msg)
                result.errors.append(error_msg)

        logger.info(
            f"Scan complete: {len(result.findings)} findings, "
            f"${result.total_monthly_waste:,.2f}/month potential savings"
        )
        return result

    def _get_subscription_name(self) -> str:
        """Get the subscription display name."""
        try:
            from azure.mgmt.resource import SubscriptionClient
            sub_client = SubscriptionClient(self.credential)
            sub = sub_client.subscriptions.get(self.subscription_id)
            return sub.display_name or self.subscription_id
        except Exception:
            return self.subscription_id

    def _get_vm_cpu_metrics(self, resource_id: str, days: int) -> Optional[float]:
        """Get average CPU percentage for a VM over N days."""
        try:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)

            metrics = self.monitor_client.metrics.list(
                resource_uri=resource_id,
                timespan=f"{start_time.strftime('%Y-%m-%dT%H:%M:%SZ')}/{end_time.strftime('%Y-%m-%dT%H:%M:%SZ')}",
                interval="PT1H",
                metricnames="Percentage CPU",
                aggregation="Average",
            )

            values = []
            for metric in metrics.value:
                for ts in metric.timeseries:
                    for data in ts.data:
                        if data.average is not None:
                            values.append(data.average)

            return sum(values) / len(values) if values else None
        except Exception as e:
            logger.warning(f"Could not get CPU metrics for {resource_id}: {e}")
            return None

    def _get_vm_network_metrics(self, resource_id: str, days: int) -> Optional[float]:
        """Get total network bytes for a VM over N days."""
        try:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)

            metrics = self.monitor_client.metrics.list(
                resource_uri=resource_id,
                timespan=f"{start_time.strftime('%Y-%m-%dT%H:%M:%SZ')}/{end_time.strftime('%Y-%m-%dT%H:%M:%SZ')}",
                interval="PT1H",
                metricnames="Network In Total,Network Out Total",
                aggregation="Total",
            )

            total_bytes = 0
            for metric in metrics.value:
                for ts in metric.timeseries:
                    for data in ts.data:
                        if data.total is not None:
                            total_bytes += data.total

            return total_bytes
        except Exception as e:
            logger.warning(f"Could not get network metrics for {resource_id}: {e}")
            return None

    def _estimate_vm_cost(self, vm_size: str) -> float:
        """Estimate monthly cost for a VM size."""
        return self.VM_PRICING.get(vm_size.lower(), 100.0)  # Default $100 if unknown

    def _scan_idle_vms(self) -> list[Finding]:
        """Find VMs with very low CPU and network usage."""
        findings = []
        vms = list(self.compute_client.virtual_machines.list_all())

        for vm in vms:
            if not vm.id:
                continue

            # Check instance view for power state
            rg = vm.id.split("/")[4]
            instance_view = self.compute_client.virtual_machines.instance_view(rg, vm.name)
            is_running = any(
                s.code == "PowerState/running"
                for s in (instance_view.statuses or [])
            )

            if not is_running:
                continue

            avg_cpu = self._get_vm_cpu_metrics(vm.id, self.idle_days)
            network_bytes = self._get_vm_network_metrics(vm.id, self.idle_days)

            if avg_cpu is not None and avg_cpu < self.idle_cpu_threshold:
                # Low network too? Likely truly idle
                is_idle_network = network_bytes is not None and network_bytes < 1_000_000  # < 1MB

                if is_idle_network or network_bytes is None:
                    monthly_cost = self._estimate_vm_cost(vm.hardware_profile.vm_size)
                    findings.append(Finding(
                        resource_id=vm.id,
                        resource_name=vm.name,
                        resource_group=rg,
                        category=WasteCategory.IDLE_VM,
                        severity="high",
                        current_cost_monthly=monthly_cost,
                        estimated_savings_monthly=monthly_cost,
                        recommendation=(
                            f"VM '{vm.name}' has avg CPU {avg_cpu:.1f}% over {self.idle_days} days "
                            f"with minimal network traffic. Consider deallocating or deleting. "
                            f"Potential savings: ${monthly_cost:,.2f}/month."
                        ),
                        details={
                            "vm_size": vm.hardware_profile.vm_size,
                            "avg_cpu_percent": round(avg_cpu, 2),
                            "network_bytes": network_bytes or 0,
                            "location": vm.location,
                        },
                    ))

        return findings

    def _scan_oversized_vms(self) -> list[Finding]:
        """Find VMs that are significantly oversized based on CPU usage."""
        findings = []
        vms = list(self.compute_client.virtual_machines.list_all())

        # Define downsize mappings
        downsize_map = {
            "standard_d4s_v3": ("standard_d2s_v3", 70.08),
            "standard_d8s_v3": ("standard_d4s_v3", 140.16),
            "standard_d16s_v3": ("standard_d8s_v3", 280.32),
            "standard_d4s_v5": ("standard_d2s_v5", 70.08),
            "standard_d8s_v5": ("standard_d4s_v5", 140.16),
            "standard_e4s_v3": ("standard_e2s_v3", 91.98),
            "standard_e8s_v3": ("standard_e4s_v3", 183.96),
            "standard_f4s_v2": ("standard_f2s_v2", 61.32),
            "standard_f8s_v2": ("standard_f4s_v2", 122.64),
        }

        for vm in vms:
            if not vm.id:
                continue

            vm_size = vm.hardware_profile.vm_size.lower()
            if vm_size not in downsize_map:
                continue

            avg_cpu = self._get_vm_cpu_metrics(vm.id, self.idle_days)
            if avg_cpu is not None and avg_cpu < self.oversized_cpu_threshold:
                rg = vm.id.split("/")[4]
                current_cost = self._estimate_vm_cost(vm_size)
                suggested_size, suggested_cost = downsize_map[vm_size]
                savings = current_cost - suggested_cost

                findings.append(Finding(
                    resource_id=vm.id,
                    resource_name=vm.name,
                    resource_group=rg,
                    category=WasteCategory.OVERSIZED_VM,
                    severity="medium",
                    current_cost_monthly=current_cost,
                    estimated_savings_monthly=savings,
                    recommendation=(
                        f"VM '{vm.name}' ({vm_size}) has avg CPU {avg_cpu:.1f}%. "
                        f"Downsize to {suggested_size} to save ${savings:,.2f}/month."
                    ),
                    details={
                        "current_size": vm_size,
                        "suggested_size": suggested_size,
                        "avg_cpu_percent": round(avg_cpu, 2),
                        "location": vm.location,
                    },
                ))

        return findings

    def _scan_unattached_disks(self) -> list[Finding]:
        """Find managed disks not attached to any VM."""
        findings = []
        disks = list(self.compute_client.disks.list())

        for disk in disks:
            if disk.disk_state == "Unattached" and disk.managed_by is None:
                rg = disk.id.split("/")[4]
                # Estimate cost based on disk size
                disk_gb = disk.disk_size_gb or 0
                if disk_gb <= 32:
                    monthly_cost = 19.71
                elif disk_gb <= 64:
                    monthly_cost = 38.21
                elif disk_gb <= 128:
                    monthly_cost = 73.22
                elif disk_gb <= 256:
                    monthly_cost = 140.71
                else:
                    monthly_cost = 270.34

                findings.append(Finding(
                    resource_id=disk.id,
                    resource_name=disk.name,
                    resource_group=rg,
                    category=WasteCategory.UNATTACHED_DISK,
                    severity="medium",
                    current_cost_monthly=monthly_cost,
                    estimated_savings_monthly=monthly_cost,
                    recommendation=(
                        f"Disk '{disk.name}' ({disk_gb}GB, {disk.sku.name}) is unattached. "
                        f"Delete to save ${monthly_cost:,.2f}/month."
                    ),
                    details={
                        "disk_size_gb": disk_gb,
                        "sku": disk.sku.name if disk.sku else "Unknown",
                        "location": disk.location,
                        "time_created": disk.time_created.isoformat() if disk.time_created else None,
                    },
                ))

        return findings

    def _scan_unused_public_ips(self) -> list[Finding]:
        """Find public IP addresses not associated with any resource."""
        findings = []
        public_ips = list(self.network_client.public_ip_addresses.list_all())

        for ip in public_ips:
            if ip.ip_configuration is None:
                rg = ip.id.split("/")[4]
                findings.append(Finding(
                    resource_id=ip.id,
                    resource_name=ip.name,
                    resource_group=rg,
                    category=WasteCategory.UNUSED_PUBLIC_IP,
                    severity="low",
                    current_cost_monthly=self.PUBLIC_IP_MONTHLY,
                    estimated_savings_monthly=self.PUBLIC_IP_MONTHLY,
                    recommendation=(
                        f"Public IP '{ip.name}' ({ip.ip_address or 'dynamic'}) "
                        f"is not associated with any resource. Delete to save "
                        f"${self.PUBLIC_IP_MONTHLY:.2f}/month."
                    ),
                    details={
                        "ip_address": ip.ip_address,
                        "allocation_method": str(ip.public_ip_allocation_method),
                        "sku": ip.sku.name if ip.sku else "Basic",
                        "location": ip.location,
                    },
                ))

        return findings

    def _scan_old_snapshots(self) -> list[Finding]:
        """Find snapshots older than the threshold."""
        findings = []
        snapshots = list(self.compute_client.snapshots.list())
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.snapshot_age_days)

        for snap in snapshots:
            if snap.time_created and snap.time_created < cutoff:
                rg = snap.id.split("/")[4]
                disk_gb = snap.disk_size_gb or 0
                # Snapshots cost ~$0.05/GB/month
                monthly_cost = disk_gb * 0.05
                age_days = (datetime.now(timezone.utc) - snap.time_created).days

                findings.append(Finding(
                    resource_id=snap.id,
                    resource_name=snap.name,
                    resource_group=rg,
                    category=WasteCategory.OLD_SNAPSHOT,
                    severity="low",
                    current_cost_monthly=monthly_cost,
                    estimated_savings_monthly=monthly_cost,
                    recommendation=(
                        f"Snapshot '{snap.name}' is {age_days} days old ({disk_gb}GB). "
                        f"Delete to save ${monthly_cost:,.2f}/month."
                    ),
                    details={
                        "disk_size_gb": disk_gb,
                        "age_days": age_days,
                        "time_created": snap.time_created.isoformat(),
                        "location": snap.location,
                    },
                ))

        return findings

    def _scan_stopped_vms_premium_disks(self) -> list[Finding]:
        """Find stopped (deallocated) VMs still paying for premium disks."""
        findings = []
        vms = list(self.compute_client.virtual_machines.list_all())

        for vm in vms:
            if not vm.id:
                continue

            rg = vm.id.split("/")[4]
            instance_view = self.compute_client.virtual_machines.instance_view(rg, vm.name)
            is_deallocated = any(
                s.code == "PowerState/deallocated"
                for s in (instance_view.statuses or [])
            )

            if not is_deallocated:
                continue

            # Check if VM has premium disks
            storage_profile = vm.storage_profile
            disk_ids = []
            if storage_profile.os_disk and storage_profile.os_disk.managed_disk:
                disk_ids.append(storage_profile.os_disk.managed_disk.id)
            for data_disk in (storage_profile.data_disks or []):
                if data_disk.managed_disk:
                    disk_ids.append(data_disk.managed_disk.id)

            premium_disk_cost = 0
            premium_disks = []
            for disk_id in disk_ids:
                try:
                    disk_rg = disk_id.split("/")[4]
                    disk_name = disk_id.split("/")[-1]
                    disk = self.compute_client.disks.get(disk_rg, disk_name)
                    if disk.sku and "premium" in disk.sku.name.lower():
                        disk_gb = disk.disk_size_gb or 0
                        cost = self._estimate_disk_cost(disk_gb)
                        premium_disk_cost += cost
                        premium_disks.append({"name": disk.name, "size_gb": disk_gb, "cost": cost})
                except Exception:
                    pass

            if premium_disk_cost > 0:
                # Savings = switch to Standard HDD
                estimated_savings = premium_disk_cost * 0.6  # ~60% savings switching to standard

                findings.append(Finding(
                    resource_id=vm.id,
                    resource_name=vm.name,
                    resource_group=rg,
                    category=WasteCategory.STOPPED_VM_WITH_DISK,
                    severity="medium",
                    current_cost_monthly=premium_disk_cost,
                    estimated_savings_monthly=estimated_savings,
                    recommendation=(
                        f"VM '{vm.name}' is deallocated but has {len(premium_disks)} premium disk(s) "
                        f"costing ${premium_disk_cost:,.2f}/month. Switch to Standard HDD or delete "
                        f"to save ~${estimated_savings:,.2f}/month."
                    ),
                    details={
                        "premium_disks": premium_disks,
                        "location": vm.location,
                    },
                ))

        return findings

    @staticmethod
    def _estimate_disk_cost(size_gb: int) -> float:
        """Estimate premium disk monthly cost by size."""
        if size_gb <= 32:
            return 19.71
        elif size_gb <= 64:
            return 38.21
        elif size_gb <= 128:
            return 73.22
        elif size_gb <= 256:
            return 140.71
        elif size_gb <= 512:
            return 270.34
        else:
            return 540.68
