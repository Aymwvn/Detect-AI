"""
Synthetic attack scenarios (architecture doc section 23).

Each function returns a list of CommonAlertSchema objects representing one
realistic attack pattern — used both by tests/test_scenarios.py (proving
the full pipeline handles each pattern correctly) and
scripts/run_benchmark.py (measuring pipeline behavior across all of them).

These are synthetic/fabricated data for testing purposes — no real
incident, host, or user data. Timestamps are relative to a fixed anchor so
scenarios are deterministic and reproducible across runs.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.schemas import CommonAlertSchema, ExistingMitreMapping, Severity, SourceProduct

ANCHOR_TIME = datetime(2026, 6, 15, 9, 0, 0, tzinfo=timezone.utc)


def _t(offset_seconds: float) -> datetime:
    return ANCHOR_TIME + timedelta(seconds=offset_seconds)


def powershell_execution_chain() -> list[CommonAlertSchema]:
    """Office document -> encoded PowerShell -> network callback ->
    scheduled task persistence. The canonical example used throughout
    docs/ARCHITECTURE.md."""
    return [
        CommonAlertSchema(
            timestamp=_t(0),
            source="scenario-generator",
            source_product=SourceProduct.GENERIC_WEBHOOK,
            severity=Severity.MEDIUM,
            rule_name="Suspicious email attachment opened",
            hostname="WIN10-FINANCE-07",
            username="j.doe",
            file_name="invoice.doc",
            tags=["email", "office"],
        ),
        CommonAlertSchema(
            timestamp=_t(3),
            source="scenario-generator",
            source_product=SourceProduct.GENERIC_WEBHOOK,
            severity=Severity.HIGH,
            rule_name="PowerShell Encoded Command from Office Process",
            hostname="WIN10-FINANCE-07",
            username="j.doe",
            process_name="powershell.exe",
            parent_process="winword.exe",
            command_line="powershell.exe -enc SQBFAFgA...",
            existing_mitre_attack_mapping=[
                ExistingMitreMapping(technique_id="T1059.001", technique_name="PowerShell", tactic="Execution")
            ],
            tags=["office", "powershell", "encoded-command"],
        ),
        CommonAlertSchema(
            timestamp=_t(7),
            source="scenario-generator",
            source_product=SourceProduct.GENERIC_WEBHOOK,
            severity=Severity.HIGH,
            rule_name="Outbound connection from PowerShell to rare external IP",
            hostname="WIN10-FINANCE-07",
            username="j.doe",
            process_name="powershell.exe",
            destination_ip="185.203.0.1",
            destination_port=443,
            protocol="tcp",
        ),
        CommonAlertSchema(
            timestamp=_t(12),
            source="scenario-generator",
            source_product=SourceProduct.GENERIC_WEBHOOK,
            severity=Severity.CRITICAL,
            rule_name="New scheduled task created by non-admin process",
            hostname="WIN10-FINANCE-07",
            username="j.doe",
            process_name="schtasks.exe",
            parent_process="powershell.exe",
            existing_mitre_attack_mapping=[
                ExistingMitreMapping(
                    technique_id="T1053.005", technique_name="Scheduled Task", tactic="Persistence"
                )
            ],
        ),
    ]


def brute_force_authentication() -> list[CommonAlertSchema]:
    """Repeated failed logins from one source IP against one account,
    followed by a successful login — the classic brute-force pattern."""
    alerts = []
    for i in range(5):
        alerts.append(
            CommonAlertSchema(
                timestamp=_t(i * 10),
                source="scenario-generator",
                source_product=SourceProduct.GENERIC_WEBHOOK,
                severity=Severity.LOW,
                rule_name="Failed authentication attempt",
                username="admin.svc",
                source_ip="203.0.113.44",
                authentication_context={"auth_method": "password", "success": False, "failed_attempt_count": i + 1},
            )
        )
    alerts.append(
        CommonAlertSchema(
            timestamp=_t(60),
            source="scenario-generator",
            source_product=SourceProduct.GENERIC_WEBHOOK,
            severity=Severity.HIGH,
            rule_name="Successful authentication following brute-force pattern",
            username="admin.svc",
            source_ip="203.0.113.44",
            authentication_context={"auth_method": "password", "success": True},
            existing_mitre_attack_mapping=[
                ExistingMitreMapping(technique_id="T1110", technique_name="Brute Force", tactic="Credential Access")
            ],
        )
    )
    return alerts


def suspicious_dns_c2_beacon() -> list[CommonAlertSchema]:
    """Repeated DNS queries to a rarely-seen domain at regular intervals —
    a classic C2 beaconing pattern."""
    return [
        CommonAlertSchema(
            timestamp=_t(i * 300),
            source="scenario-generator",
            source_product=SourceProduct.GENERIC_WEBHOOK,
            severity=Severity.MEDIUM,
            rule_name="DNS query to rare/newly-seen domain",
            hostname="LINUX-WEB-03",
            domain="a8f3d9e1.duckdns.org",
            protocol="udp",
        )
        for i in range(4)
    ]


def credential_access_lsass_dump() -> list[CommonAlertSchema]:
    """rundll32.exe accessing lsass.exe memory — classic credential
    dumping technique (e.g. via a Mimikatz-style tool)."""
    return [
        CommonAlertSchema(
            timestamp=_t(0),
            source="scenario-generator",
            source_product=SourceProduct.GENERIC_WEBHOOK,
            severity=Severity.CRITICAL,
            rule_name="Process accessing LSASS memory",
            hostname="WIN10-IT-02",
            username="it.admin",
            process_name="rundll32.exe",
            command_line="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 lsass.dmp full",
            existing_mitre_attack_mapping=[
                ExistingMitreMapping(
                    technique_id="T1003.001", technique_name="LSASS Memory", tactic="Credential Access"
                )
            ],
        )
    ]


def lateral_movement_admin_login() -> list[CommonAlertSchema]:
    """A privileged account logging into multiple hosts in a short window
    — a lateral-movement indicator."""
    hostnames = ["WIN10-FINANCE-07", "WIN10-HR-03", "WIN10-IT-02"]
    return [
        CommonAlertSchema(
            timestamp=_t(i * 45),
            source="scenario-generator",
            source_product=SourceProduct.GENERIC_WEBHOOK,
            severity=Severity.HIGH,
            rule_name="Domain admin interactive login to workstation",
            hostname=hostname,
            username="domain.admin",
            existing_mitre_attack_mapping=[
                ExistingMitreMapping(
                    technique_id="T1021.001", technique_name="Remote Desktop Protocol", tactic="Lateral Movement"
                )
            ],
        )
        for i, hostname in enumerate(hostnames)
    ]


ALL_SCENARIOS = {
    "powershell_execution_chain": powershell_execution_chain,
    "brute_force_authentication": brute_force_authentication,
    "suspicious_dns_c2_beacon": suspicious_dns_c2_beacon,
    "credential_access_lsass_dump": credential_access_lsass_dump,
    "lateral_movement_admin_login": lateral_movement_admin_login,
}
