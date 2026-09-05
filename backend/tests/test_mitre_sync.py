"""
Tests for app/services/mitre/sync.py.

Uses a small hand-built STIX bundle fixture rather than the full ~5MB
official bundle — same shape as real MITRE data (verified separately, see
PHASE15_NOTES in the delivery summary), but fast and deterministic for
the test suite.
"""

from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.models import Base, MitreTechnique
from app.services.mitre.sync import parse_stix_bundle, sync_mitre_techniques

SAMPLE_STIX_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--001",
            "name": "Command and Scripting Interpreter: PowerShell",
            "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1059.001",
                    "url": "https://attack.mitre.org/techniques/T1059/001",
                }
            ],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--002",
            "name": "Phishing",
            "description": "Adversaries may send phishing messages.",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1566",
                    "url": "https://attack.mitre.org/techniques/T1566",
                }
            ],
        },
        {
            # revoked -> must be skipped
            "type": "attack-pattern",
            "id": "attack-pattern--003",
            "name": "Old Revoked Technique",
            "revoked": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
        },
        {
            # deprecated -> must be skipped
            "type": "attack-pattern",
            "id": "attack-pattern--004",
            "name": "Old Deprecated Technique",
            "x_mitre_deprecated": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9998"}],
        },
        {
            # not an attack-pattern at all -> must be skipped
            "type": "course-of-action",
            "id": "course-of-action--001",
            "name": "Some mitigation",
        },
        {
            # attack-pattern with no mitre-attack external_id -> must be skipped
            "type": "attack-pattern",
            "id": "attack-pattern--005",
            "name": "No valid ID",
            "external_references": [{"source_name": "some-other-source", "external_id": "X1"}],
        },
    ],
}


@pytest_asyncio.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_maker = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with session_maker() as s:
        yield s
    await engine.dispose()


class FakeAsyncClient:
    def __init__(self, bundle: dict):
        self._bundle = bundle

    async def get(self, url):
        return FakeResponse(self._bundle)


class FakeResponse:
    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body


# --- parse_stix_bundle -------------------------------------------------

def test_parse_extracts_valid_techniques_only():
    techniques = parse_stix_bundle(SAMPLE_STIX_BUNDLE)
    ids = {t["technique_id"] for t in techniques}
    assert ids == {"T1059.001", "T1566"}


def test_parse_skips_revoked_and_deprecated():
    techniques = parse_stix_bundle(SAMPLE_STIX_BUNDLE)
    ids = {t["technique_id"] for t in techniques}
    assert "T9999" not in ids
    assert "T9998" not in ids


def test_parse_extracts_tactic_readable_form():
    techniques = parse_stix_bundle(SAMPLE_STIX_BUNDLE)
    t1566 = next(t for t in techniques if t["technique_id"] == "T1566")
    assert t1566["tactic"] == "Initial Access"


def test_parse_extracts_subtechnique_id_directly():
    """Sub-techniques are separate STIX objects with dotted IDs — no
    special-casing needed since technique_id is just a string PK."""
    techniques = parse_stix_bundle(SAMPLE_STIX_BUNDLE)
    t1059 = next(t for t in techniques if t["technique_id"] == "T1059.001")
    assert t1059["name"] == "Command and Scripting Interpreter: PowerShell"


def test_parse_empty_bundle_returns_empty_list():
    assert parse_stix_bundle({"objects": []}) == []


# --- sync_mitre_techniques -------------------------------------------------

@pytest.mark.asyncio
async def test_sync_inserts_new_techniques(session: AsyncSession):
    fake_client = FakeAsyncClient(SAMPLE_STIX_BUNDLE)
    count = await sync_mitre_techniques(session, client=fake_client)
    assert count == 2

    technique = await session.get(MitreTechnique, "T1059.001")
    assert technique is not None
    assert technique.name == "Command and Scripting Interpreter: PowerShell"


@pytest.mark.asyncio
async def test_sync_is_idempotent_and_updates_existing(session: AsyncSession):
    fake_client = FakeAsyncClient(SAMPLE_STIX_BUNDLE)
    await sync_mitre_techniques(session, client=fake_client)

    updated_bundle = {
        "objects": [
            {
                **SAMPLE_STIX_BUNDLE["objects"][0],
                "name": "Renamed Technique",
            }
        ]
    }
    fake_client_2 = FakeAsyncClient(updated_bundle)
    count = await sync_mitre_techniques(session, client=fake_client_2)
    assert count == 1

    technique = await session.get(MitreTechnique, "T1059.001")
    assert technique.name == "Renamed Technique"

    # the T1566 row from the first sync must still exist — sync never deletes
    still_there = await session.get(MitreTechnique, "T1566")
    assert still_there is not None
