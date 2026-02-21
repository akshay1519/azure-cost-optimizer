"""
Compliance Automation - Collects Azure Policy evidence and generates audit-ready reports.

Scans Azure Policy assignments, compliance states, and generates
evidence reports suitable for SOC2, ISO 27001, and other audits.
"""

import json
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional

from azure.identity import DefaultAzureCredential
from azure.mgmt.policyinsights import PolicyInsightsClient
from azure.mgmt.resource import PolicyClient

logger = logging.getLogger(__name__)


@dataclass
class PolicyComplianceRecord:
    """A single policy compliance record."""
    policy_assignment_id: str
    policy_name: str
    policy_description: str
    compliance_state: str  # "Compliant", "NonCompliant", "Exempt"
    resource_id: str
    resource_type: str
    resource_group: str
    timestamp: str
    details: dict = field(default_factory=dict)


@dataclass
class ComplianceReport:
    """Full compliance report for a subscription."""
    subscription_id: str
    subscription_name: str
    scan_timestamp: str
    total_policies: int = 0
    compliant_count: int = 0
    non_compliant_count: int = 0
    exempt_count: int = 0
    compliance_percentage: float = 0.0
    records: list[PolicyComplianceRecord] = field(default_factory=list)
    summary_by_category: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


class ComplianceScanner:
    """Scans Azure Policy compliance and generates audit evidence."""

    # Common compliance categories
    POLICY_CATEGORIES = {
        "security": ["Security Center", "Azure Security Benchmark", "CIS"],
        "networking": ["Network", "NSG", "Firewall", "VNet"],
        "identity": ["Identity", "RBAC", "MFA", "AAD", "Entra"],
        "data_protection": ["Encryption", "TDE", "Key Vault", "SSL", "TLS"],
        "monitoring": ["Monitoring", "Diagnostic", "Log Analytics", "Audit"],
        "compute": ["VM", "Compute", "Container", "Kubernetes"],
        "storage": ["Storage", "Blob", "Disk"],
    }

    def __init__(
        self,
        subscription_id: str,
        credential: Optional[DefaultAzureCredential] = None,
    ):
        self.subscription_id = subscription_id
        self.credential = credential or DefaultAzureCredential()
        self.policy_client = PolicyClient(self.credential, self.subscription_id)
        self.insights_client = PolicyInsightsClient(self.credential, self.subscription_id)

    def scan_compliance(self) -> ComplianceReport:
        """Run a full compliance scan."""
        report = ComplianceReport(
            subscription_id=self.subscription_id,
            subscription_name=self._get_subscription_name(),
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
        )

        try:
            self._collect_policy_states(report)
            self._calculate_summary(report)
        except Exception as e:
            error_msg = f"Error during compliance scan: {str(e)}"
            logger.error(error_msg)
            report.errors.append(error_msg)

        return report

    def _get_subscription_name(self) -> str:
        try:
            from azure.mgmt.resource import SubscriptionClient
            sub_client = SubscriptionClient(self.credential)
            sub = sub_client.subscriptions.get(self.subscription_id)
            return sub.display_name or self.subscription_id
        except Exception:
            return self.subscription_id

    def _collect_policy_states(self, report: ComplianceReport):
        """Collect all policy compliance states."""
        logger.info("Collecting policy compliance states...")

        try:
            # Get policy states summary
            summary = self.insights_client.policy_states.summarize_for_subscription(
                policy_states_summary_resource="latest",
                subscription_id=self.subscription_id,
            )

            if summary.value:
                for summary_item in summary.value:
                    if summary_item.results:
                        report.total_policies = summary_item.results.total_policies_count or 0
                        report.non_compliant_count = (
                            summary_item.results.non_compliant_policies or 0
                        )

                    # Process individual policy assignments
                    for pa in (summary_item.policy_assignments or []):
                        self._process_policy_assignment(report, pa)

        except Exception as e:
            logger.error(f"Error collecting policy states: {e}")
            report.errors.append(str(e))

        # Also collect detailed non-compliant resources
        try:
            query_results = self.insights_client.policy_states.list_query_results_for_subscription(
                policy_states_resource="latest",
                subscription_id=self.subscription_id,
                query_options={"filter": "complianceState eq 'NonCompliant'", "top": 500},
            )

            for state in query_results:
                record = PolicyComplianceRecord(
                    policy_assignment_id=state.policy_assignment_id or "",
                    policy_name=state.policy_definition_name or "Unknown",
                    policy_description=state.policy_definition_action or "",
                    compliance_state="NonCompliant",
                    resource_id=state.resource_id or "",
                    resource_type=state.resource_type or "",
                    resource_group=state.resource_group or "",
                    timestamp=state.timestamp.isoformat() if state.timestamp else "",
                    details={
                        "policy_definition_id": state.policy_definition_id,
                        "policy_set_definition_id": state.policy_set_definition_id,
                        "management_group_ids": state.management_group_ids,
                    },
                )
                report.records.append(record)

        except Exception as e:
            logger.error(f"Error querying non-compliant resources: {e}")
            report.errors.append(str(e))

    def _process_policy_assignment(self, report: ComplianceReport, pa):
        """Process a single policy assignment summary."""
        if pa.results:
            compliant = pa.results.compliant_resources or 0
            non_compliant = pa.results.non_compliant_resources or 0
            report.compliant_count += compliant
            report.non_compliant_count += non_compliant

    def _calculate_summary(self, report: ComplianceReport):
        """Calculate summary statistics."""
        total = report.compliant_count + report.non_compliant_count + report.exempt_count
        if total > 0:
            report.compliance_percentage = (report.compliant_count / total) * 100

        # Categorize findings
        for record in report.records:
            category = self._categorize_policy(record.policy_name)
            if category not in report.summary_by_category:
                report.summary_by_category[category] = {
                    "total": 0,
                    "non_compliant": 0,
                    "resources": [],
                }
            report.summary_by_category[category]["total"] += 1
            if record.compliance_state == "NonCompliant":
                report.summary_by_category[category]["non_compliant"] += 1
                report.summary_by_category[category]["resources"].append(
                    record.resource_id
                )

    def _categorize_policy(self, policy_name: str) -> str:
        """Categorize a policy into a compliance domain."""
        name_upper = policy_name.upper()
        for category, keywords in self.POLICY_CATEGORIES.items():
            if any(kw.upper() in name_upper for kw in keywords):
                return category
        return "other"

    def generate_audit_report(self, report: ComplianceReport, output_format: str = "json") -> str:
        """Generate an audit-ready compliance report."""
        if output_format == "json":
            return self._generate_json_audit(report)
        elif output_format == "html":
            return self._generate_html_audit(report)
        else:
            return self._generate_text_audit(report)

    def _generate_json_audit(self, report: ComplianceReport) -> str:
        audit = {
            "audit_metadata": {
                "tool": "Azure Cost Optimizer - Compliance Module",
                "version": "1.0.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "subscription_id": report.subscription_id,
                "subscription_name": report.subscription_name,
            },
            "compliance_summary": {
                "total_policies_evaluated": report.total_policies,
                "compliant_resources": report.compliant_count,
                "non_compliant_resources": report.non_compliant_count,
                "exempt_resources": report.exempt_count,
                "compliance_percentage": round(report.compliance_percentage, 2),
            },
            "categories": report.summary_by_category,
            "non_compliant_details": [
                {
                    "policy_name": r.policy_name,
                    "resource_id": r.resource_id,
                    "resource_type": r.resource_type,
                    "resource_group": r.resource_group,
                    "timestamp": r.timestamp,
                }
                for r in report.records
                if r.compliance_state == "NonCompliant"
            ],
            "errors": report.errors,
        }
        return json.dumps(audit, indent=2)

    def _generate_text_audit(self, report: ComplianceReport) -> str:
        lines = []
        lines.append("=" * 70)
        lines.append("  AZURE COMPLIANCE AUDIT REPORT")
        lines.append("=" * 70)
        lines.append(f"  Subscription: {report.subscription_name}")
        lines.append(f"  Date: {report.scan_timestamp}")
        lines.append(f"  Compliance: {report.compliance_percentage:.1f}%")
        lines.append("")
        lines.append(f"  Compliant Resources:     {report.compliant_count}")
        lines.append(f"  Non-Compliant Resources: {report.non_compliant_count}")
        lines.append(f"  Exempt Resources:        {report.exempt_count}")
        lines.append("")

        if report.summary_by_category:
            lines.append("  BREAKDOWN BY CATEGORY")
            lines.append("  " + "─" * 40)
            for cat, info in sorted(report.summary_by_category.items()):
                lines.append(
                    f"  {cat.replace('_', ' ').title()}: "
                    f"{info['non_compliant']} non-compliant / {info['total']} total"
                )

        lines.append("")
        lines.append(f"  NON-COMPLIANT RESOURCES ({len(report.records)})")
        lines.append("  " + "─" * 40)
        for i, r in enumerate(report.records[:50], 1):
            lines.append(f"  {i}. [{r.policy_name}]")
            lines.append(f"     Resource: {r.resource_id}")
            lines.append(f"     Type: {r.resource_type}")
            lines.append("")

        if len(report.records) > 50:
            lines.append(f"  ... and {len(report.records) - 50} more")

        lines.append("=" * 70)
        return "\n".join(lines)

    def _generate_html_audit(self, report: ComplianceReport) -> str:
        non_compliant_rows = ""
        for r in report.records:
            non_compliant_rows += f"""
            <tr>
                <td>{r.policy_name}</td>
                <td>{r.resource_type}</td>
                <td>{r.resource_group}</td>
                <td>{r.timestamp}</td>
            </tr>"""

        compliance_color = "#27ae60" if report.compliance_percentage >= 80 else (
            "#f39c12" if report.compliance_percentage >= 60 else "#e74c3c"
        )

        category_rows = ""
        for cat, info in sorted(report.summary_by_category.items()):
            category_rows += f"""
            <tr>
                <td>{cat.replace('_', ' ').title()}</td>
                <td>{info['total']}</td>
                <td>{info['non_compliant']}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Azure Compliance Audit Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f7fa; margin: 0; padding: 20px; }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        h1 {{ color: #0078d4; }}
        .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin: 20px 0; }}
        .card {{ background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .card h3 {{ color: #666; font-size: 0.85em; text-transform: uppercase; }}
        .card .value {{ font-size: 1.8em; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        th {{ background: #0078d4; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #eee; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Azure Compliance Audit Report</h1>
        <p>Subscription: {report.subscription_name} | Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>

        <div class="cards">
            <div class="card">
                <h3>Compliance Score</h3>
                <div class="value" style="color: {compliance_color}">{report.compliance_percentage:.1f}%</div>
            </div>
            <div class="card">
                <h3>Total Policies</h3>
                <div class="value">{report.total_policies}</div>
            </div>
            <div class="card">
                <h3>Compliant</h3>
                <div class="value" style="color: #27ae60">{report.compliant_count}</div>
            </div>
            <div class="card">
                <h3>Non-Compliant</h3>
                <div class="value" style="color: #e74c3c">{report.non_compliant_count}</div>
            </div>
        </div>

        <h2>By Category</h2>
        <table>
            <thead><tr><th>Category</th><th>Total</th><th>Non-Compliant</th></tr></thead>
            <tbody>{category_rows}</tbody>
        </table>

        <h2>Non-Compliant Resources</h2>
        <table>
            <thead><tr><th>Policy</th><th>Resource Type</th><th>Resource Group</th><th>Timestamp</th></tr></thead>
            <tbody>{non_compliant_rows}</tbody>
        </table>

        <div style="text-align:center; color:#999; margin-top:40px;">
            Azure Cost Optimizer - Compliance Module v1.0.0
        </div>
    </div>
</body>
</html>"""
