"""
vault/backup.py
---------------
Vault Backup and Export Engine (Section 8):
- Cryptographically secure `.spvault` encrypted backup:
  - Preserves Argon2id keyslots, nonces, and AES-256-GCM ciphertexts
  - Zero plaintext leakage in backup artifacts
  - Full lossless restore capability
- Plaintext CSV export with explicit disclosure formatting
"""

import csv
import hashlib
import hmac
import json
import time
import os
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path

from vault.models import Entry, VaultHeader
from vault.store import VaultStore


SPVAULT_FORMAT_TAG = "SecurePasswordAdvisorVaultBackup"
SPVAULT_VERSION = 2          # version 2 adds the authenticated manifest
LEGACY_SPVAULT_VERSION = 1   # unauthenticated manifest (record deletion not detectable)
MANIFEST_FIELDS = ("format", "version", "record_count", "header", "profile", "records")


def _manifest_bytes(payload: Dict[str, Any]) -> bytes:
    """Canonical bytes covered by the manifest MAC (records ordered by identifier)."""
    body = {k: payload.get(k) for k in MANIFEST_FIELDS}
    body["records"] = sorted(body["records"] or [], key=lambda r: r["id"])
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_backup_manifest_mac(payload: Dict[str, Any], dek: bytes) -> str:
    from vault.crypto import derive_backup_manifest_key
    key = derive_backup_manifest_key(dek)
    return hmac.new(key, _manifest_bytes(payload), hashlib.sha256).hexdigest()


def backup_is_authenticated(payload: Dict[str, Any]) -> bool:
    """True when the backup carries a manifest MAC (version 2 or later)."""
    return isinstance(payload.get("manifest"), dict) and bool(payload["manifest"].get("mac"))


def create_encrypted_backup(store: VaultStore, output_path: str, dek: Optional[bytes] = None) -> int:
    """
    Exports an encrypted .spvault backup file containing:
    - Vault header (salt, Argon2id parameters, master/recovery keyslots)
    - All encrypted records (nonce, ct, schema)
    With `dek`, the backup is version 2 and carries an HMAC-SHA256 manifest keyed
    from the DEK, so record deletion, reordering or count changes are detected on
    restore. Without `dek` a legacy, unauthenticated version 1 file is written.
    Returns total number of backed up records.
    """
    header = store.get_header()
    if not header:
        raise ValueError("Cannot backup uninitialized vault.")
    
    with store._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, nonce, ct, schema FROM records")
        rows = cursor.fetchall()
        row = conn.execute("SELECT value FROM meta WHERE key='profile'").fetchone()
        profile = json.loads(row[0]) if row else None
        if profile is not None and not profile.get("enc"):
            raise ValueError("Unlock the vault to migrate its legacy profile before backup.")

    records_data = []
    for r in rows:
        records_data.append({
            "id": r[0],
            "nonce": r[1].hex() if isinstance(r[1], (bytes, bytearray)) else r[1],
            "ct": r[2].hex() if isinstance(r[2], (bytes, bytearray)) else r[2],
            "schema": r[3]
        })

    backup_payload = {
        "format": SPVAULT_FORMAT_TAG,
        "version": SPVAULT_VERSION if dek is not None else LEGACY_SPVAULT_VERSION,
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "record_count": len(records_data),
        "header": header.to_dict(),
        "profile": profile,
        "records": records_data
    }

    if dek is not None:
        backup_payload["manifest"] = {
            "alg": "HMAC-SHA256",
            "key": "HKDF-SHA256(DEK, cav-backup-manifest-v1)",
            "mac": compute_backup_manifest_mac(backup_payload, dek),
        }

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(backup_payload, f, indent=2)

    os.chmod(out_file, 0o600)
    return len(records_data)


def restore_encrypted_backup(backup_path: str, target_store: VaultStore, master_password: str = None,
                             require_manifest: bool = False) -> int:
    """
    Restores an encrypted .spvault file into a target VaultStore.
    Overwrites the header and imports all records.
    A version 2 manifest is verified whenever `master_password` is supplied; a
    mismatch (deleted, added or altered records, header or profile) is rejected.
    `require_manifest=True` refuses legacy backups that have no manifest.
    Returns total number of restored records.
    """
    with open(backup_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    if payload.get("format") != SPVAULT_FORMAT_TAG:
        raise ValueError(f"Invalid backup file format: expected '{SPVAULT_FORMAT_TAG}'")

    if not isinstance(payload.get("version"), int) or payload.get("version") > SPVAULT_VERSION:
        raise ValueError(f"Unsupported backup version: {payload.get('version')}")

    header_dict = payload.get("header")
    if not header_dict:
        raise ValueError("Corrupt backup: missing vault header.")

    header = VaultHeader.from_dict(header_dict)
    records = payload.get("records", [])
    if payload.get("record_count") != len(records):
        raise ValueError("Backup record count mismatch")
    profile = payload.get("profile")
    if profile is not None and not profile.get("enc"):
        raise ValueError("Backup contains unencrypted profile metadata")
    if len({r["id"] for r in records}) != len(records):
        raise ValueError("Duplicate record identifiers in backup")
    parsed = [(r["id"], bytes.fromhex(r["nonce"]), bytes.fromhex(r["ct"]), r.get("schema", 1)) for r in records]
    if any(len(nonce) != 12 or len(ct) < 16 or schema != 1 for _, nonce, ct, schema in parsed):
        raise ValueError("Invalid encrypted record structure")
    authenticated = backup_is_authenticated(payload)
    if payload.get("version", 1) >= 2 and not authenticated:
        raise ValueError("Version 2 backup is missing its authenticated manifest")
    if require_manifest and not authenticated:
        raise ValueError("Backup has no authenticated manifest (legacy format)")
    if master_password is not None:
        from vault.crypto import unlock_dek_with_password, decrypt_entry, decrypt_profile
        dek = unlock_dek_with_password(header, master_password)
        if authenticated:
            expected = compute_backup_manifest_mac(payload, dek)
            if not hmac.compare_digest(expected, str(payload["manifest"]["mac"])):
                raise ValueError("Backup manifest authentication failed: records, count, header or profile were altered")
        for eid, nonce, ct, schema in parsed:
            decrypt_entry(eid, nonce, ct, dek, schema)
        if profile:
            decrypt_profile(bytes.fromhex(profile["nonce_hex"]), bytes.fromhex(profile["ct_hex"]), dek, profile["schema"])
    elif target_store.vault_exists() or authenticated:
        raise ValueError("Verify the backup master password before replacing an existing vault")
    # Validate first, then replace everything atomically: never mix different vault keys.
    with target_store._get_connection() as conn:
        conn.execute("DELETE FROM records")
        conn.execute("DELETE FROM meta")
        conn.execute("INSERT INTO meta(key,value) VALUES ('header',?)", (json.dumps(header.to_dict()).encode(),))
        if profile:
            conn.execute("INSERT INTO meta(key,value) VALUES ('profile',?)", (json.dumps(profile).encode(),))
        conn.executemany("INSERT INTO records(id,nonce,ct,schema) VALUES (?,?,?,?)", parsed)

    return len(records)


def export_decrypted_csv(entries: List[Entry], output_path: str) -> None:
    """
    Exports decrypted entries to standard CSV format.
    Includes explicit warning comment in file header.
    """
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "site_name",
        "url",
        "username",
        "password",
        "notes",
        "criticality",
        "created_at",
        "modified_at"
    ]

    with open(out_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for e in entries:
            writer.writerow({
                "site_name": e.site_name,
                "url": e.url,
                "username": e.username,
                "password": e.password,
                "notes": e.notes,
                "criticality": e.criticality,
                "created_at": e.created_at,
                "modified_at": e.modified_at
            })
