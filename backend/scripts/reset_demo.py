"""
reset_demo.py — Safe Demo Environment Reset & Seed Script (Phase 6)

Resets local SQLite database and seeds default demo organization, demo security lead, demo analyst,
and authorized local OWASP WebGoat target metadata.
Only allowed in non-production environments (RIZINTEL_ENV != 'production').
"""

from __future__ import annotations

import os
import sys

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from database import init_db, create_registered_asset, update_asset_authorization
from services.org_service import _seed_demo_org, DEMO_ORG_ID


def reset_demo_database():
    env = os.getenv("RIZINTEL_ENV", "development").strip().lower()
    if env == "production":
        print("ERROR: Demo reset script cannot be executed in production environment (RIZINTEL_ENV=production). Aborting.")
        sys.exit(1)

    print("Initializing SQLite DDL schema...")
    init_db()

    print("Seeding demo organization and user memberships...")
    _seed_demo_org()

    print("Seeding authorized local OWASP WebGoat target asset...")
    asset_id = "ASSET-WEBGOAT-001"
    try:
        create_registered_asset(
            asset_id=asset_id,
            organization_id=DEMO_ORG_ID,
            display_name="OWASP WebGoat Target App",
            host="127.0.0.1",
            normalized_host="127.0.0.1:8085",
            port=8085,
            environment="STAGING",
            criticality="HIGH",
            internet_facing=True,
            data_sensitivity="CONFIDENTIAL",
            created_by="usr-lead-003",
        )
    except Exception as e:
        print(f"Asset creation notice: {e}")

    update_asset_authorization(
        organization_id=DEMO_ORG_ID,
        asset_id=asset_id,
        new_status="AUTHORIZED",
        updated_by="usr-lead-003",
    )

    print("Demo environment reset and seed complete!")


if __name__ == "__main__":
    reset_demo_database()
