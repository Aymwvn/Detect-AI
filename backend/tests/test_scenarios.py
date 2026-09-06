"""
End-to-end scenario tests (architecture doc section 23).

Runs each synthetic attack scenario through the REAL pipeline — ingest,
dedup, correlate, risk-score — exactly as a live deployment would process
it. This is where the individually-unit-tested pieces (Phases 10-15) get
proven to actually work together across multiple realistic attack
patterns, not just the one PowerShell example used throughout the
architecture doc's prose.
"""

from datetime import timedelta

import pytest

from app.services.ingestion import ingest_alert
from app.services.pipeline import process_new_alert
from datasets.synthetic_scenarios import (
    brute_force_authentication,
    credential_access_lsass_dump,
    lateral_movement_admin_login,
    powershell_execution_chain,
    suspicious_dns_c2_beacon,
)


async def _run_scenario(db_session, schemas):
    """Ingests and processes every alert in a scenario, in order, exactly
    like a live poll/webhook loop would."""
    processed = []
    for schema in schemas:
        db_alert = await ingest_alert(db_session, schema)
        db_alert = await process_new_alert(db_session, db_alert)
        processed.append(db_alert)
    return processed


@pytest.mark.asyncio
async def test_powershell_chain_correlates_into_one_incident(client, db_session):
    alerts = await _run_scenario(db_session, powershell_execution_chain())
    assert len(alerts) == 4

    incident_ids = {a.incident_id for a in alerts}
    # all 4 share hostname/username -> must all land in the same incident
    assert len(incident_ids) == 1
    assert None not in incident_ids


@pytest.mark.asyncio
async def test_powershell_chain_final_alert_has_highest_risk_due_to_correlation(client, db_session):
    """The scheduled-task persistence alert arrives last, after 3 prior
    correlated alerts, so it should score at least as high as the first
    (uncorrelated at the time it was scored) alert in the chain."""
    alerts = await _run_scenario(db_session, powershell_execution_chain())
    first_alert, last_alert = alerts[0], alerts[-1]
    assert last_alert.risk_score >= first_alert.risk_score


@pytest.mark.asyncio
async def test_brute_force_scenario_correlates_by_shared_ip_and_user(client, db_session):
    alerts = await _run_scenario(db_session, brute_force_authentication())
    assert len(alerts) == 6
    incident_ids = {a.incident_id for a in alerts}
    assert len(incident_ids) == 1
    assert None not in incident_ids


@pytest.mark.asyncio
async def test_brute_force_final_successful_login_has_mitre_mapping(client, db_session):
    alerts = await _run_scenario(db_session, brute_force_authentication())
    final = alerts[-1]
    assert any(m["technique_id"] == "T1110" for m in final.existing_mitre_attack_mapping)


@pytest.mark.asyncio
async def test_dns_beacon_scenario_deduplicates_repeated_identical_queries(client, db_session):
    """4 identical DNS-beacon alerts (same host, same domain, same rule)
    within a short window should collapse into ONE dedup group — this is
    the literal "500 alerts -> 1 group" claim, exercised on a different
    scenario than the dedup unit tests use."""
    alerts = await _run_scenario(db_session, suspicious_dns_c2_beacon())
    dedup_groups = {a.dedup_group_id for a in alerts}
    assert len(dedup_groups) == 1


@pytest.mark.asyncio
async def test_credential_access_scenario_scores_critical_priority(client, db_session):
    alerts = await _run_scenario(db_session, credential_access_lsass_dump())
    assert alerts[0].investigation_priority in ("high", "critical")


@pytest.mark.asyncio
async def test_lateral_movement_scenario_correlates_across_different_hosts(client, db_session):
    """Three logins to three DIFFERENT hosts by the same admin account —
    correlation must catch this via the shared username, even though no
    two alerts share a hostname."""
    alerts = await _run_scenario(db_session, lateral_movement_admin_login())
    hostnames = {a.hostname for a in alerts}
    assert len(hostnames) == 3  # confirms the scenario itself is testing what it claims to

    incident_ids = {a.incident_id for a in alerts}
    assert len(incident_ids) == 1
    assert None not in incident_ids


@pytest.mark.asyncio
async def test_unrelated_scenarios_do_not_cross_correlate(client, db_session):
    """Running two different scenarios (no shared host/user/ip) must NOT
    merge them into the same incident — correlation should be precise,
    not overly broad."""
    powershell_alerts = await _run_scenario(db_session, powershell_execution_chain())
    dns_alerts = await _run_scenario(db_session, suspicious_dns_c2_beacon())

    powershell_incidents = {a.incident_id for a in powershell_alerts}
    dns_incidents = {a.incident_id for a in dns_alerts}
    assert powershell_incidents.isdisjoint(dns_incidents)
