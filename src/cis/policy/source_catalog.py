"""Closed loader for the operational policy-source catalog."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from ..errors import PolicySourceConflict
from .sources import PolicySourceAuthority

DEFAULT_SOURCE_CATALOG = (
    Path(__file__).resolve().parents[3] / "policy" / "operational_sources.json"
)
_FIELDS = {"schema_version", "catalog_id", "provenance", "policies"}
_SCHEMA_VERSION = "1.0.0"


def load_source_catalog(path: str | Path = DEFAULT_SOURCE_CATALOG) -> dict:
    source = Path(path)
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicySourceConflict("operational policy source catalog is unreadable",
                                   path=str(source)) from exc
    if not isinstance(document, Mapping) or set(document) != _FIELDS:
        raise PolicySourceConflict(
            "operational policy source catalog has an invalid closed schema",
            path=str(source),
            present=(sorted(document) if isinstance(document, Mapping) else None),
        )
    for field in ("schema_version", "catalog_id", "provenance"):
        if not isinstance(document[field], str) or not document[field].strip():
            raise PolicySourceConflict("policy source catalog field is invalid",
                                       field=field, path=str(source))
    if document["schema_version"] != _SCHEMA_VERSION:
        raise PolicySourceConflict(
            "operational policy source catalog has an unknown schema version",
            path=str(source), recorded=document["schema_version"],
            expected=_SCHEMA_VERSION,
        )
    policies = document["policies"]
    if not isinstance(policies, list) or not policies:
        raise PolicySourceConflict("policy source catalog carries no documents",
                                   path=str(source))
    return dict(document)


def ingest_source_catalog(authority: PolicySourceAuthority,
                          path: str | Path = DEFAULT_SOURCE_CATALOG) -> list:
    catalog = load_source_catalog(path)
    provenance = (f"{catalog['provenance']}; catalog={catalog['catalog_id']}; "
                  f"path={Path(path)}")
    return authority.ingest_many(catalog["policies"], provenance=provenance)


__all__ = ["DEFAULT_SOURCE_CATALOG", "ingest_source_catalog", "load_source_catalog"]
