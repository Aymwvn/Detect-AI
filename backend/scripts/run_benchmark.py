"""
Benchmark: rule-based-only vs AI-assisted triage (architecture doc section
24).

Runs every synthetic scenario (datasets/synthetic_scenarios.py) through
the full pipeline twice — once with no AI provider, once with a fake
provider standing in for a real LLM — and reports the difference.

HONEST LIMITATION, stated plainly: no real LLM was available in the
environment that built this (no API keys, no network access to a live
model). The "AI-assisted" numbers below come from a scripted FakeProvider
that returns a fixed, plausible-looking analysis for every alert — they
demonstrate that the AI-assisted CODE PATH runs and produces different,
richer output than rule-based-only (extra evidence, MITRE techniques,
recommended actions), NOT that a real LLM would produce these exact
numbers or even agree with them. Re-run this script with a real
AI_PROVIDER configured (ollama/openai/anthropic) to get numbers that
actually mean something for a report.

Usage (from backend/):
    python scripts/run_benchmark.py
"""

from __future__ import annotations

import asyncio
import sys

sys.path.insert(0, ".")

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402

from app.db.models import Base  # noqa: E402
from app.services.ai.analysis import analyze_alert as run_ai_analysis  # noqa: E402
from app.services.ingestion import ingest_alert  # noqa: E402
from app.services.pipeline import process_new_alert  # noqa: E402
from datasets.synthetic_scenarios import ALL_SCENARIOS  # noqa: E402


class FakeBenchmarkProvider:
    """Stands in for a real LLM — see module docstring's honest limitation
    note. Returns a fixed, schema-valid response so the AI-assisted path
    actually runs end-to-end (parsing, evidence reconciliation, MITRE
    cross-check) rather than being skipped."""

    provider_type = "fake-benchmark"
    model = "fake-benchmark-v1"

    async def complete(self, system_prompt: str, user_prompt: str) -> str:
        return """{
            "classification": "likely_malicious",
            "risk_score": 75,
            "confidence": 0.8,
            "summary": "Simulated AI analysis for benchmarking purposes only.",
            "evidence": [{"reference": "field:hostname", "description": "Host context available"}],
            "mitre_techniques": [],
            "false_positive_hypotheses": ["Legitimate administrative activity"],
            "recommended_actions": ["Review with analyst"],
            "missing_information": [],
            "investigation_priority": "high"
        }"""


async def run_benchmark() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_maker = async_sessionmaker(bind=engine, expire_on_commit=False)

    print("=" * 70)
    print("DetectAI Benchmark: Rule-Based-Only vs AI-Assisted (synthetic data)")
    print("=" * 70)
    print()

    rule_based_scores = []
    ai_assisted_evidence_counts = []
    total_alerts = 0
    total_deduped_groups = 0
    total_incidents = set()
    mitre_technique_count = 0

    for name, generator in ALL_SCENARIOS.items():
        async with session_maker() as db:
            schemas = generator()
            processed = []
            for schema in schemas:
                db_alert = await ingest_alert(db, schema)
                db_alert = await process_new_alert(db, db_alert)
                processed.append(db_alert)

            total_alerts += len(processed)
            total_deduped_groups += len({a.dedup_group_id for a in processed})
            total_incidents.update(a.incident_id for a in processed if a.incident_id)
            mitre_technique_count += sum(len(a.existing_mitre_attack_mapping) for a in processed)
            rule_based_scores.extend(a.risk_score for a in processed if a.risk_score is not None)

            # AI-assisted pass: run the fake provider on the highest-risk
            # alert in the scenario (the one an analyst would open first).
            highest_risk_alert = max(processed, key=lambda a: a.risk_score or 0)
            analysis = await run_ai_analysis(db, highest_risk_alert, FakeBenchmarkProvider())
            ai_assisted_evidence_counts.append(len(analysis.evidence))

            print(f"Scenario: {name}")
            print(f"  Alerts generated:       {len(processed)}")
            print(f"  Dedup groups:           {len({a.dedup_group_id for a in processed})}")
            print(f"  Correlated incidents:   {len({a.incident_id for a in processed if a.incident_id})}")
            print(f"  Rule-based risk scores: {[a.risk_score for a in processed]}")
            print(f"  AI classification:      {analysis.classification} (evidence items: {len(analysis.evidence)})")
            print()

    await engine.dispose()

    print("-" * 70)
    print("Summary across all scenarios")
    print("-" * 70)
    print(f"Total synthetic alerts:              {total_alerts}")
    print(f"Total dedup groups:                  {total_deduped_groups}")
    print(f"Dedup rate:                          {1 - total_deduped_groups / total_alerts:.1%}")
    print(f"Total distinct incidents formed:     {len(total_incidents)}")
    print(f"Mean rule-based risk score:          {sum(rule_based_scores) / len(rule_based_scores):.1f}")
    print(f"Total vendor-supplied MITRE mappings: {mitre_technique_count}")
    print(f"Mean AI-assisted evidence items/alert (fake provider): "
          f"{sum(ai_assisted_evidence_counts) / len(ai_assisted_evidence_counts):.1f}")
    print()
    print("NOTE: AI-assisted figures use a scripted fake provider, not a real")
    print("LLM. Re-run with AI_PROVIDER=ollama/openai/anthropic configured for")
    print("numbers that reflect actual model behavior.")


if __name__ == "__main__":
    asyncio.run(run_benchmark())
