"""
MITRE ATT&CK sync (architecture doc section 10: "Static MITRE ATT&CK
STIX/JSON bundle, periodically synced — no live external dependency at
request time").

Fetches the official Enterprise ATT&CK STIX 2.1 bundle from MITRE's public
GitHub repository and upserts every attack-pattern object into the
mitre_techniques table. This is a periodic, explicitly-triggered sync
(POST /api/v1/mitre/sync) — not something that runs on every request, so
DetectAI's MITRE mapping never depends on MITRE's GitHub being reachable
at analysis time.

STIX format note: technique objects are `type: "attack-pattern"`.
Sub-techniques (e.g. T1059.001) are their own separate attack-pattern
objects — the STIX bundle doesn't nest them under their parent, so this
sync naturally produces one row per technique AND per sub-technique,
which is exactly the shape mitre_techniques.technique_id (a bare string
primary key) already expects.
"""

from __future__ import annotations

from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import MitreTechnique

DEFAULT_MITRE_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)

_MAX_DESCRIPTION_LENGTH = 4000  # matches MitreTechnique.description column size


def _extract_technique_id(stix_obj: dict[str, Any]) -> Optional[str]:
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _extract_url(stix_obj: dict[str, Any]) -> Optional[str]:
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None


def _extract_tactic(stix_obj: dict[str, Any]) -> Optional[str]:
    """STIX kill_chain_phases use MITRE's tactic shortname (e.g.
    "initial-access") — converted to a readable form ("Initial Access").
    A technique can map to multiple tactics; this keeps only the first,
    since MitreTechnique.tactic is a single field. Multi-tactic detail is
    still fully preserved in raw_event-equivalent storage if ever needed —
    the AI/rule-based analysis paths only need "a" tactic for display, not
    the complete list."""
    for phase in stix_obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            return phase.get("phase_name", "").replace("-", " ").title()
    return None


def parse_stix_bundle(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Extracts every active (non-revoked, non-deprecated) technique and
    sub-technique from a STIX bundle into plain dicts ready for
    MitreTechnique(**dict). Objects with no recognizable MITRE technique
    ID (malformed or non-ATT&CK sources mixed into the bundle) are skipped
    rather than raising — a single bad object shouldn't abort the sync."""
    techniques: list[dict[str, Any]] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = _extract_technique_id(obj)
        if not technique_id:
            continue

        description = (obj.get("description") or "")[:_MAX_DESCRIPTION_LENGTH]
        techniques.append(
            {
                "technique_id": technique_id,
                "name": obj.get("name", "Unknown"),
                "tactic": _extract_tactic(obj),
                "description": description,
                "url": _extract_url(obj),
            }
        )
    return techniques


async def _fetch_bundle(url: str, client: Any = None) -> dict[str, Any]:
    if client is None:
        try:
            import httpx
        except ImportError as exc:
            raise RuntimeError(
                "The 'httpx' package is required to sync MITRE data. Install with: pip install httpx"
            ) from exc
        async with httpx.AsyncClient(timeout=60.0) as owned_client:
            response = await owned_client.get(url)
            response.raise_for_status()
            return response.json()

    response = await client.get(url)
    return response.json()


async def sync_mitre_techniques(
    db: AsyncSession, url: str = DEFAULT_MITRE_BUNDLE_URL, client: Any = None
) -> int:
    """Fetches the bundle, parses it, and upserts every technique. Returns
    the number of techniques synced. Existing rows are updated in place
    (name/tactic/description/url may change between MITRE releases);
    nothing is ever deleted, so a technique that disappears from a newer
    bundle (unlikely, but possible for deprecated/merged techniques) stays
    available for historical alerts that already reference it."""
    bundle = await _fetch_bundle(url, client=client)
    techniques = parse_stix_bundle(bundle)

    for technique in techniques:
        existing = await db.get(MitreTechnique, technique["technique_id"])
        if existing is not None:
            existing.name = technique["name"]
            existing.tactic = technique["tactic"]
            existing.description = technique["description"]
            existing.url = technique["url"]
        else:
            db.add(MitreTechnique(**technique))

    await db.commit()
    return len(techniques)
