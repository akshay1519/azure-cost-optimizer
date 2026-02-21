"""
Security Automation - Ingests Azure Sentinel/Log Analytics logs and highlights anomalies.

Connects to Azure Log Analytics workspace to:
- Detect unusual sign-in patterns
- Flag high-severity security alerts
- Identify brute-force attempts
- Detect privilege escalation events
- Monitor resource deletion spikes
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from typing import Optional

from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus

logger = logging.getLogger(__name__)


@dataclass
class SecurityAlert:
    """A single security anomaly/alert."""
    alert_id: str
    title: str
    severity: str  # "critical", "high", "medium", "low", "informational"
    category: str
    description: str
    affected_resource: str
    timestamp: str
    raw_data: dict = field(default_factory=dict)
    recommendation: str = ""


@dataclass
class SecurityReport:
    """Complete security scan report."""
    workspace_id: str
    scan_timestamp: str
    alerts: list[SecurityAlert] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for a in self.alerts if a.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for a in self.alerts if a.severity == "high")


class SecurityScanner:
    """Scans Azure Sentinel / Log Analytics for security anomalies."""

    # KQL queries for different security checks
    QUERIES = {
        "failed_signins": {
            "title": "Brute Force / Failed Sign-in Attempts",
            "category": "identity",
            "severity": "high",
            "query": """
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType != "0"
| summarize FailedAttempts=count(), DistinctIPs=dcount(IPAddress)
    by UserPrincipalName, AppDisplayName, bin(TimeGenerated, 1h)
| where FailedAttempts > 10
| order by FailedAttempts desc
| take 50
""",
        },
        "suspicious_signins": {
            "title": "Suspicious Sign-in Locations",
            "category": "identity",
            "severity": "medium",
            "query": """
SigninLogs
| where TimeGenerated > ago(7d)
| where RiskLevelDuringSignIn in ("high", "medium")
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
    RiskLevelDuringSignIn, RiskState, AppDisplayName
| order by TimeGenerated desc
| take 100
""",
        },
        "privilege_escalation": {
            "title": "Privilege Escalation Events",
            "category": "identity",
            "severity": "critical",
            "query": """
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("Add member to role", "Add eligible member to role",
    "Add owner to", "Add member to group")
| where TargetResources has_any ("Global Administrator", "Privileged Role Administrator",
    "Application Administrator", "Owner")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc
| take 50
""",
        },
        "resource_deletions": {
            "title": "Mass Resource Deletions",
            "category": "resource",
            "severity": "high",
            "query": """
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue endswith "DELETE"
| where ActivityStatusValue == "Success"
| summarize DeleteCount=count() by Caller, bin(TimeGenerated, 1h)
| where DeleteCount > 5
| order by DeleteCount desc
| take 50
""",
        },
        "sentinel_incidents": {
            "title": "Azure Sentinel Incidents",
            "category": "sentinel",
            "severity": "high",
            "query": """
SecurityIncident
| where TimeGenerated > ago(7d)
| where Status != "Closed"
| project TimeGenerated, Title, Severity, Status, Owner,
    IncidentNumber, Description
| order by TimeGenerated desc
| take 100
""",
        },
        "security_alerts": {
            "title": "Security Center Alerts",
            "category": "security_center",
            "severity": "high",
            "query": """
SecurityAlert
| where TimeGenerated > ago(7d)
| where AlertSeverity in ("High", "Critical")
| project TimeGenerated, AlertName, AlertSeverity, Description,
    RemediationSteps, Entities
| order by TimeGenerated desc
| take 100
""",
        },
        "unusual_network": {
            "title": "Unusual Network Connections",
            "category": "network",
            "severity": "medium",
            "query": """
AzureNetworkAnalytics_CL
| where TimeGenerated > ago(7d)
| where FlowType_s == "MaliciousFlow"
| project TimeGenerated, SrcIP_s, DestIP_s, DestPort_d,
    FlowType_s, L7Protocol_s
| order by TimeGenerated desc
| take 100
""",
        },
        "key_vault_access": {
            "title": "Sensitive Key Vault Operations",
            "category": "data_protection",
            "severity": "medium",
            "query": """
AzureDiagnostics
| where TimeGenerated > ago(7d)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName in ("SecretGet", "SecretList", "KeyGet", "CertificateGet")
| summarize AccessCount=count() by CallerIPAddress, identity_claim_upn_s,
    OperationName, bin(TimeGenerated, 1h)
| where AccessCount > 20
| order by AccessCount desc
| take 50
""",
        },
    }

    RECOMMENDATIONS = {
        "identity": "Review Azure AD sign-in logs, enable MFA, and consider Conditional Access policies.",
        "resource": "Audit Azure Activity logs, review RBAC permissions, and enable resource locks on critical resources.",
        "sentinel": "Investigate open incidents in Azure Sentinel, assign to analysts, and update playbooks.",
        "security_center": "Review Defender for Cloud recommendations and remediate high-severity alerts.",
        "network": "Review NSG rules, enable Azure Firewall, and investigate flagged connections.",
        "data_protection": "Review Key Vault access policies, enable soft-delete and purge protection.",
    }

    def __init__(
        self,
        workspace_id: str,
        credential: Optional[DefaultAzureCredential] = None,
        lookback_days: int = 7,
    ):
        self.workspace_id = workspace_id
        self.credential = credential or DefaultAzureCredential()
        self.lookback_days = lookback_days
        self.logs_client = LogsQueryClient(self.credential)

    def scan_all(self) -> SecurityReport:
        """Run all security queries and return combined results."""
        report = SecurityReport(
            workspace_id=self.workspace_id,
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
        )

        for query_name, query_config in self.QUERIES.items():
            try:
                logger.info(f"Running security check: {query_config['title']}...")
                alerts = self._run_query(query_name, query_config)
                report.alerts.extend(alerts)
                logger.info(f"  Found {len(alerts)} alert(s)")
            except Exception as e:
                error_msg = f"Error running {query_name}: {str(e)}"
                logger.warning(error_msg)
                report.errors.append(error_msg)

        # Build summary
        report.summary = self._build_summary(report)

        logger.info(
            f"Security scan complete: {len(report.alerts)} alerts "
            f"({report.critical_count} critical, {report.high_count} high)"
        )
        return report

    def _run_query(self, query_name: str, config: dict) -> list[SecurityAlert]:
        """Execute a KQL query and return security alerts."""
        alerts = []

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=self.lookback_days)

        response = self.logs_client.query_workspace(
            workspace_id=self.workspace_id,
            query=config["query"],
            timespan=(start_time, end_time),
        )

        if response.status == LogsQueryStatus.SUCCESS:
            for table in response.tables:
                columns = [col.name for col in table.columns]
                for row in table.rows:
                    row_dict = dict(zip(columns, row))

                    alert = SecurityAlert(
                        alert_id=f"{query_name}_{hash(str(row))}",
                        title=config["title"],
                        severity=config["severity"],
                        category=config["category"],
                        description=self._format_alert_description(query_name, row_dict),
                        affected_resource=self._extract_resource(row_dict),
                        timestamp=str(row_dict.get("TimeGenerated", "")),
                        raw_data=row_dict,
                        recommendation=self.RECOMMENDATIONS.get(config["category"], ""),
                    )
                    alerts.append(alert)

        elif response.status == LogsQueryStatus.PARTIAL:
            logger.warning(f"Partial results for {query_name}: {response.partial_error}")
            for table in response.partial_data:
                columns = [col.name for col in table.columns]
                for row in table.rows:
                    row_dict = dict(zip(columns, row))
                    alert = SecurityAlert(
                        alert_id=f"{query_name}_{hash(str(row))}",
                        title=config["title"],
                        severity=config["severity"],
                        category=config["category"],
                        description=self._format_alert_description(query_name, row_dict),
                        affected_resource=self._extract_resource(row_dict),
                        timestamp=str(row_dict.get("TimeGenerated", "")),
                        raw_data=row_dict,
                        recommendation=self.RECOMMENDATIONS.get(config["category"], ""),
                    )
                    alerts.append(alert)

        return alerts

    def _format_alert_description(self, query_name: str, data: dict) -> str:
        """Format an alert description based on query type and data."""
        if query_name == "failed_signins":
            return (
                f"User '{data.get('UserPrincipalName', 'Unknown')}' had "
                f"{data.get('FailedAttempts', 0)} failed sign-in attempts "
                f"from {data.get('DistinctIPs', 0)} distinct IPs "
                f"on app '{data.get('AppDisplayName', 'Unknown')}'."
            )
        elif query_name == "suspicious_signins":
            return (
                f"Suspicious sign-in for '{data.get('UserPrincipalName', 'Unknown')}' "
                f"from {data.get('Location', 'Unknown')} (IP: {data.get('IPAddress', 'Unknown')}) "
                f"with risk level: {data.get('RiskLevelDuringSignIn', 'Unknown')}."
            )
        elif query_name == "privilege_escalation":
            return (
                f"Privilege escalation: {data.get('OperationName', 'Unknown operation')} "
                f"initiated by {data.get('InitiatedBy', 'Unknown')}."
            )
        elif query_name == "resource_deletions":
            return (
                f"User '{data.get('Caller', 'Unknown')}' deleted "
                f"{data.get('DeleteCount', 0)} resources in one hour."
            )
        elif query_name == "sentinel_incidents":
            return (
                f"Sentinel Incident #{data.get('IncidentNumber', '?')}: "
                f"{data.get('Title', 'Unknown')} — {data.get('Description', '')[:200]}"
            )
        elif query_name == "security_alerts":
            return (
                f"Security Alert: {data.get('AlertName', 'Unknown')} "
                f"({data.get('AlertSeverity', 'Unknown')} severity). "
                f"{data.get('Description', '')[:200]}"
            )
        elif query_name == "key_vault_access":
            return (
                f"High-volume Key Vault access: {data.get('AccessCount', 0)} "
                f"{data.get('OperationName', 'operations')} from "
                f"{data.get('identity_claim_upn_s', data.get('CallerIPAddress', 'Unknown'))}."
            )
        else:
            return f"Security finding in {query_name}: {json.dumps(data)[:200]}"

    def _extract_resource(self, data: dict) -> str:
        """Extract the most relevant resource identifier from a row."""
        for key in [
            "UserPrincipalName", "ResourceId", "resource_id",
            "Caller", "CallerIPAddress", "SrcIP_s", "IPAddress",
        ]:
            if key in data and data[key]:
                return str(data[key])
        return "Unknown"

    def _build_summary(self, report: SecurityReport) -> dict:
        """Build a summary of the security report."""
        by_severity = {}
        by_category = {}

        for alert in report.alerts:
            by_severity.setdefault(alert.severity, 0)
            by_severity[alert.severity] += 1

            by_category.setdefault(alert.category, 0)
            by_category[alert.category] += 1

        return {
            "total_alerts": len(report.alerts),
            "by_severity": by_severity,
            "by_category": by_category,
            "critical_count": report.critical_count,
            "high_count": report.high_count,
        }

    def generate_report(self, report: SecurityReport, output_format: str = "json") -> str:
        """Generate security report in specified format."""
        if output_format == "json":
            return self._generate_json(report)
        elif output_format == "html":
            return self._generate_html(report)
        else:
            return self._generate_text(report)

    def _generate_json(self, report: SecurityReport) -> str:
        output = {
            "meta": {
                "tool": "Azure Cost Optimizer - Security Module",
                "version": "1.0.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "workspace_id": report.workspace_id,
            },
            "summary": report.summary,
            "alerts": [
                {
                    "alert_id": a.alert_id,
                    "title": a.title,
                    "severity": a.severity,
                    "category": a.category,
                    "description": a.description,
                    "affected_resource": a.affected_resource,
                    "timestamp": a.timestamp,
                    "recommendation": a.recommendation,
                }
                for a in report.alerts
            ],
            "errors": report.errors,
        }
        return json.dumps(output, indent=2, default=str)

    def _generate_text(self, report: SecurityReport) -> str:
        lines = []
        lines.append("=" * 70)
        lines.append("  AZURE SECURITY SCAN REPORT")
        lines.append("=" * 70)
        lines.append(f"  Workspace: {report.workspace_id}")
        lines.append(f"  Scan Time: {report.scan_timestamp}")
        lines.append(f"  Total Alerts: {len(report.alerts)}")
        lines.append(f"  Critical: {report.critical_count} | High: {report.high_count}")
        lines.append("")

        for sev in ["critical", "high", "medium", "low"]:
            sev_alerts = [a for a in report.alerts if a.severity == sev]
            if sev_alerts:
                lines.append(f"  [{sev.upper()}] ({len(sev_alerts)} alerts)")
                lines.append("  " + "─" * 40)
                for a in sev_alerts[:20]:
                    lines.append(f"  • {a.title}")
                    lines.append(f"    {a.description}")
                    lines.append(f"    Resource: {a.affected_resource}")
                    lines.append(f"    Recommendation: {a.recommendation}")
                    lines.append("")
                if len(sev_alerts) > 20:
                    lines.append(f"  ... and {len(sev_alerts) - 20} more {sev} alerts")
                lines.append("")

        lines.append("=" * 70)
        return "\n".join(lines)

    def _generate_html(self, report: SecurityReport) -> str:
        alert_rows = ""
        sev_colors = {
            "critical": "#8b0000",
            "high": "#e74c3c",
            "medium": "#f39c12",
            "low": "#3498db",
            "informational": "#95a5a6",
        }
        for a in sorted(report.alerts, key=lambda x: ["critical", "high", "medium", "low"].index(x.severity) if x.severity in ["critical", "high", "medium", "low"] else 4):
            color = sev_colors.get(a.severity, "#999")
            alert_rows += f"""
            <tr>
                <td><span style="background:{color};color:white;padding:2px 8px;border-radius:3px;font-size:0.8em;">{a.severity.upper()}</span></td>
                <td>{a.title}</td>
                <td>{a.description[:150]}</td>
                <td>{a.affected_resource}</td>
                <td>{a.recommendation}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Azure Security Scan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f7fa; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #c0392b; }}
        .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .card {{ background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
        .card h3 {{ color: #666; font-size: 0.85em; text-transform: uppercase; }}
        .card .value {{ font-size: 1.8em; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; background: white; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        th {{ background: #c0392b; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #eee; font-size: 0.9em; }}
        tr:hover {{ background: #fff5f5; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Azure Security Scan Report</h1>
        <p>Workspace: {report.workspace_id} | Scanned: {report.scan_timestamp}</p>
        <div class="cards">
            <div class="card"><h3>Total Alerts</h3><div class="value">{len(report.alerts)}</div></div>
            <div class="card"><h3>Critical</h3><div class="value" style="color:#8b0000">{report.critical_count}</div></div>
            <div class="card"><h3>High</h3><div class="value" style="color:#e74c3c">{report.high_count}</div></div>
            <div class="card"><h3>Medium</h3><div class="value" style="color:#f39c12">{sum(1 for a in report.alerts if a.severity=='medium')}</div></div>
        </div>
        <h2>Security Alerts</h2>
        <table>
            <thead><tr><th>Severity</th><th>Check</th><th>Description</th><th>Resource</th><th>Recommendation</th></tr></thead>
            <tbody>{alert_rows}</tbody>
        </table>
        <div style="text-align:center;color:#999;margin-top:40px;">Azure Cost Optimizer - Security Module v1.0.0</div>
    </div>
</body>
</html>"""
