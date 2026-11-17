#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate local credentials once; never rotate a running database implicitly."""
import base64
import os
from pathlib import Path
import secrets
import shutil
os.umask(0o077)
root = Path(__file__).resolve().parent.parent
folder = root / ".secrets"
folder.mkdir(mode=0o700, exist_ok=True)
for name in ("postgres_password", "webhook_token", "admin_password", "trivy_token"):
    path = folder / name
    if not path.exists():
        path.write_text(secrets.token_urlsafe(36))
# Dependency-Track 5 key-encryption key (base64 AES-256). Losing it makes stored integration secrets unreadable.
if not (folder / "dt_kek").exists():
    (folder / "dt_kek").write_text(base64.b64encode(secrets.token_bytes(32)).decode())
if not (folder / "routes.json").exists():
    (folder / "routes.json").write_text("[]\n")
if not (root / ".env").exists():
    shutil.copyfile(root / ".env.example", root / ".env")
for name in ("postgres_password", "webhook_token", "admin_password", "trivy_token", "dt_kek", "routes.json"):
    path = folder / name
    if path.is_file():
        path.chmod(0o444)  # Files are bind-mounted into containers with different UIDs; parent stays 0700.
print("Local secrets initialized. Configure .env and .secrets/routes.json. Existing values preserved.")
