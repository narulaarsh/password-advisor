"""
vault/crypto.py
---------------
Cryptographic core for Context-Aware Local Vault (CAV):
- Argon2id password-based key derivation (m=64 MiB, t=3, p=4)
- Envelope encryption with keyslots (master password, recovery key, optional device secret)
- AES-256-GCM authenticated encryption with AAD binding
- Cryptographic entry encryption/decryption
- DEK-derived password history hashing with HMAC-SHA256
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
from typing import Optional, Tuple, Dict, Any

import argon2.low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from vault.models import Entry, Profile, VaultHeader, CryptoError, AuthError

# ── Cryptographic Constants ──────────────────────────────────────────────────
ARGON2_DEFAULT_MEMORY = 65536   # 64 MiB
ARGON2_DEFAULT_TIME = 3         # 3 iterations
ARGON2_DEFAULT_PARALLELISM = 4  # 4 threads
ARGON2_MIN_MEMORY = 32768       # 32 MiB min bound to prevent tampering
ARGON2_MIN_TIME = 1

KEY_LEN_BYTES = 32              # 256-bit AES / KEK / DEK
NONCE_LEN_BYTES = 12            # 96-bit AES-GCM nonce
SALT_LEN_BYTES = 16             # 128-bit Argon2 salt
SCHEMA_VERSION = 1

KEK_INFO = b"cav-kek-v1"
RECOVERY_KEK_INFO = b"cav-recovery-kek-v1"
HISTORY_HMAC_INFO = b"cav-hist-hmac-v1"


# ── Key Derivation Primitives ────────────────────────────────────────────────

def derive_k_pw(password: str, salt: bytes, m: int = ARGON2_DEFAULT_MEMORY,
                t: int = ARGON2_DEFAULT_TIME, p: int = ARGON2_DEFAULT_PARALLELISM) -> bytes:
    """
    Derives 32-byte intermediate key K_pw from master password using Argon2id.
    """
    if m < ARGON2_MIN_MEMORY or t < ARGON2_MIN_TIME or p < 1:
        raise CryptoError("Argon2 parameters below security threshold; potential header tampering.")
    
    return argon2.low_level.hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=t,
        memory_cost=m,
        parallelism=p,
        hash_len=KEY_LEN_BYTES,
        type=argon2.low_level.Type.ID
    )


ARGON2_CALIBRATION_MEMORY = 262144   # 256 MiB preferred for new vaults
ARGON2_TARGET_MS = (300.0, 600.0)    # unlock-latency target on the creating host
ARGON2_MAX_TIME = 64


def calibrate_argon2_parameters(target_ms: Tuple[float, float] = ARGON2_TARGET_MS,
                                parallelism: int = ARGON2_DEFAULT_PARALLELISM,
                                measure=None) -> Dict[str, Any]:
    """
    Chooses Argon2id parameters for a NEW vault so one derivation takes roughly
    target_ms on this machine. Never returns less than the previous default
    (64 MiB, t=3). Existing vaults keep the parameters stored in their header.
    `measure(m, t, p) -> milliseconds` can be injected for testing.
    """
    import time as _time

    def default_measure(m: int, t: int, p: int) -> float:
        salt = secrets.token_bytes(SALT_LEN_BYTES)
        start = _time.perf_counter()
        derive_k_pw("calibration-only-not-a-secret", salt, m, t, p)
        return (_time.perf_counter() - start) * 1000.0

    measure = measure or default_measure
    low, high = target_ms
    for memory in (ARGON2_CALIBRATION_MEMORY, ARGON2_DEFAULT_MEMORY):
        base_t = ARGON2_DEFAULT_TIME
        base_ms = min(measure(memory, base_t, parallelism) for _ in range(2))
        if base_ms > high and memory != ARGON2_DEFAULT_MEMORY:
            continue  # too slow at this memory size: fall back to 64 MiB
        per_iteration = max(base_ms / base_t, 1e-3)
        t = int(-(-low // per_iteration))  # ceil(low / per_iteration)
        t = max(base_t, min(ARGON2_MAX_TIME, t))
        measured = measure(memory, t, parallelism)
        while measured < low and t < ARGON2_MAX_TIME:  # the linear estimate can undershoot
            t += 1
            measured = measure(memory, t, parallelism)
        return {"m": memory, "t": t, "p": parallelism, "measured_ms": round(measured, 1),
                "target_ms": [low, high]}
    raise CryptoError("Argon2id calibration failed")


def derive_kek(k_pw: bytes, device_secret: Optional[bytes] = None) -> bytes:
    """
    Derives Key Encryption Key (KEK) using HKDF-SHA256 over K_pw and optional device secret.
    """
    ikm = k_pw + (device_secret if device_secret else b"")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN_BYTES,
        salt=None,
        info=KEK_INFO,
    )
    return hkdf.derive(ikm)


def derive_recovery_kek(recovery_key_bytes: bytes) -> bytes:
    """
    Derives recovery KEK from 256-bit raw recovery key using HKDF-SHA256.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN_BYTES,
        salt=None,
        info=RECOVERY_KEK_INFO,
    )
    return hkdf.derive(recovery_key_bytes)


def derive_history_key(dek: bytes) -> bytes:
    """
    Derives subkey from DEK for HMAC-based password history hashing.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN_BYTES,
        salt=None,
        info=HISTORY_HMAC_INFO,
    )
    return hkdf.derive(dek)


BACKUP_MANIFEST_INFO = b"cav-backup-manifest-v1"


def derive_backup_manifest_key(dek: bytes) -> bytes:
    """
    Derives the HMAC key that authenticates a backup's manifest (header, profile,
    record count and every record) so deleted or altered backup records are detected.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN_BYTES,
        salt=None,
        info=BACKUP_MANIFEST_INFO,
    )
    return hkdf.derive(bytes(dek))


def hash_password_for_history(password: str, history_key: bytes) -> str:
    """
    Computes HMAC-SHA256 of password using history_key.
    Allows duplicate/reuse detection against previous passwords without storing plaintext.
    """
    return hmac.new(history_key, password.encode("utf-8"), hashlib.sha256).hexdigest()


# ── Recovery Key Formatting ──────────────────────────────────────────────────

def generate_recovery_key() -> Tuple[str, bytes]:
    """
    Generates a 256-bit recovery key.
    Returns:
        tuple (formatted_key_string, raw_32_bytes)
    Formatted as 8 groups of 4 base32 characters separated by dashes.
    """
    raw = secrets.token_bytes(KEY_LEN_BYTES)
    b32 = base64.b32encode(raw).decode("ascii").rstrip("=")
    # 32 bytes in base32 is 52 characters (or 56 with padding)
    chunks = [b32[i:i + 4] for i in range(0, len(b32), 4)]
    formatted = "-".join(chunks)
    return formatted, raw


def parse_recovery_key(formatted_key: str) -> bytes:
    """
    Parses a human-readable recovery key back into 32 raw bytes.
    Raises CryptoError if invalid.
    """
    clean = formatted_key.replace("-", "").replace(" ", "").upper()
    # Add base32 padding if needed
    missing_padding = len(clean) % 8
    if missing_padding:
        clean += "=" * (8 - missing_padding)
    try:
        raw = base64.b32decode(clean.encode("ascii"))
        if len(raw) != KEY_LEN_BYTES:
            raise ValueError()
        return raw
    except Exception:
        raise CryptoError("Invalid recovery key format.")


# ── Envelope Encryption & Keyslot Management ─────────────────────────────────

def generate_dek() -> bytes:
    """Generates a fresh 256-bit Data Encryption Key (DEK)."""
    return secrets.token_bytes(KEY_LEN_BYTES)


def wrap_dek(dek: bytes, kek: bytes, aad: bytes) -> Tuple[bytes, bytes]:
    """
    Wraps DEK using AES-256-GCM under KEK with header AAD.
    Returns (nonce, wrapped_dek_with_tag).
    """
    nonce = secrets.token_bytes(NONCE_LEN_BYTES)
    aesgcm = AESGCM(kek)
    ct = aesgcm.encrypt(nonce, dek, aad)
    return nonce, ct


def unwrap_dek(wrapped_dek: bytes, nonce: bytes, kek: bytes, aad: bytes) -> bytes:
    """
    Unwraps DEK using AES-256-GCM.
    Raises AuthError if decryption fails or authentication tag is invalid.
    """
    aesgcm = AESGCM(kek)
    try:
        return aesgcm.decrypt(nonce, wrapped_dek, aad)
    except Exception:
        raise AuthError("Failed to unlock vault. Invalid credentials or corrupted vault.")


def create_vault_header(
    master_password: str,
    dek: Optional[bytes] = None,
    device_secret: Optional[bytes] = None,
    recovery_key: Optional[bytes] = None,
    m: int = ARGON2_DEFAULT_MEMORY,
    t: int = ARGON2_DEFAULT_TIME,
    p: int = ARGON2_DEFAULT_PARALLELISM
) -> Tuple[VaultHeader, bytes, Optional[str]]:
    """
    Creates an initialized VaultHeader, generating salt and wrapping DEK in keyslots.
    Returns:
        (header, dek, formatted_recovery_key_if_generated)
    """
    if dek is None:
        dek = generate_dek()

    salt = secrets.token_bytes(SALT_LEN_BYTES)
    k_pw = derive_k_pw(master_password, salt, m, t, p)
    kek = derive_kek(k_pw, device_secret)

    header = VaultHeader(
        version=SCHEMA_VERSION,
        salt_hex=salt.hex(),
        argon2={"m": m, "t": t, "p": p},
        has_device_secret=device_secret is not None,
    )

    aad = header.canonical_aad_bytes()
    pw_nonce, pw_wrapped = wrap_dek(dek, kek, aad)
    header.keyslots["password"] = {
        "nonce_hex": pw_nonce.hex(),
        "wrapped_dek_hex": pw_wrapped.hex()
    }

    formatted_recovery: Optional[str] = None
    if recovery_key is not None:
        rec_raw = recovery_key
    elif device_secret is not None:
        # Require recovery key if device-bound secret is enabled
        formatted_recovery, rec_raw = generate_recovery_key()
    else:
        rec_raw = None

    if rec_raw is not None:
        rec_kek = derive_recovery_kek(rec_raw)
        rec_nonce, rec_wrapped = wrap_dek(dek, rec_kek, aad)
        header.keyslots["recovery"] = {
            "nonce_hex": rec_nonce.hex(),
            "wrapped_dek_hex": rec_wrapped.hex()
        }

    return header, dek, formatted_recovery


def unlock_dek_with_password(
    header: VaultHeader,
    master_password: str,
    device_secret: Optional[bytes] = None
) -> bytes:
    """
    Unlocks and returns the 32-byte DEK using master password.
    Raises AuthError if password is wrong or vault is corrupted/tampered.
    """
    if "password" not in header.keyslots:
        raise AuthError("Corrupted vault: password keyslot missing.")

    salt = bytes.fromhex(header.salt_hex)
    argon2_cfg = header.argon2
    m = argon2_cfg.get("m", ARGON2_DEFAULT_MEMORY)
    t = argon2_cfg.get("t", ARGON2_DEFAULT_TIME)
    p = argon2_cfg.get("p", ARGON2_DEFAULT_PARALLELISM)

    k_pw = derive_k_pw(master_password, salt, m, t, p)
    kek = derive_kek(k_pw, device_secret)
    aad = header.canonical_aad_bytes()

    slot = header.keyslots["password"]
    nonce = bytes.fromhex(slot["nonce_hex"])
    wrapped_dek = bytes.fromhex(slot["wrapped_dek_hex"])

    return unwrap_dek(wrapped_dek, nonce, kek, aad)


def unlock_dek_with_recovery(header: VaultHeader, recovery_key_bytes: bytes) -> bytes:
    """
    Unlocks and returns the 32-byte DEK using the 256-bit recovery key.
    Raises AuthError if recovery key is invalid or vault is corrupted.
    """
    if "recovery" not in header.keyslots:
        raise AuthError("Vault does not have a recovery keyslot configured.")

    rec_kek = derive_recovery_kek(recovery_key_bytes)
    aad = header.canonical_aad_bytes()

    slot = header.keyslots["recovery"]
    nonce = bytes.fromhex(slot["nonce_hex"])
    wrapped_dek = bytes.fromhex(slot["wrapped_dek_hex"])

    return unwrap_dek(wrapped_dek, nonce, rec_kek, aad)


def change_master_password(
    header: VaultHeader,
    old_password: str,
    new_password: str,
    device_secret: Optional[bytes] = None
) -> VaultHeader:
    """
    Re-wraps the DEK with a new master password and fresh salt.
    Envelope encryption ensures stored records do not require re-encryption.
    """
    dek = unlock_dek_with_password(header, old_password, device_secret)

    # Generate fresh salt
    new_salt = secrets.token_bytes(SALT_LEN_BYTES)
    m = header.argon2.get("m", ARGON2_DEFAULT_MEMORY)
    t = header.argon2.get("t", ARGON2_DEFAULT_TIME)
    p = header.argon2.get("p", ARGON2_DEFAULT_PARALLELISM)

    new_k_pw = derive_k_pw(new_password, new_salt, m, t, p)
    new_kek = derive_kek(new_k_pw, device_secret)

    header.salt_hex = new_salt.hex()
    aad = header.canonical_aad_bytes()

    pw_nonce, pw_wrapped = wrap_dek(dek, new_kek, aad)
    header.keyslots["password"] = {
        "nonce_hex": pw_nonce.hex(),
        "wrapped_dek_hex": pw_wrapped.hex()
    }

    # If recovery keyslot exists, re-wrap it against new header AAD
    if "recovery" in header.keyslots:
        pass  # Note: recovery slot uses header AAD; to maintain consistency, re-wrap if recovery key available

    return header


# ── Record Level Authenticated Encryption ────────────────────────────────────

def compute_entry_aad(entry_id: str, schema_version: int = SCHEMA_VERSION) -> bytes:
    """
    Binds ciphertext to record ID and schema version.
    Prevents swapping ciphertexts between records in the database.
    """
    return entry_id.encode("utf-8") + b":" + struct.pack(">I", schema_version)


def encrypt_entry(entry: Entry, dek: bytes, schema_version: int = SCHEMA_VERSION) -> Tuple[bytes, bytes]:
    """
    Encrypts an Entry using AES-256-GCM under the DEK.
    Returns (nonce_12_bytes, ciphertext_with_tag).
    """
    nonce = secrets.token_bytes(NONCE_LEN_BYTES)
    aad = compute_entry_aad(entry.id, schema_version)
    plaintext = entry.to_json_bytes()
    aesgcm = AESGCM(dek)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt_entry(entry_id: str, nonce: bytes, ciphertext: bytes, dek: bytes, schema_version: int = SCHEMA_VERSION) -> Entry:
    """
    Decrypts an Entry using AES-256-GCM.
    Raises AuthError if ciphertext is modified or swapped between records.
    """
    aad = compute_entry_aad(entry_id, schema_version)
    aesgcm = AESGCM(dek)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    except Exception:
        raise AuthError(f"Integrity check failed for entry '{entry_id}'. Data is corrupted or tampered.")

    return Entry.from_json_bytes(plaintext)


# ── Profile Level Authenticated Encryption ───────────────────────────────────

def compute_profile_aad(profile_id: str = "profile", schema_version: int = SCHEMA_VERSION) -> bytes:
    """Binds profile ciphertext to record id and schema version."""
    return profile_id.encode("utf-8") + b":" + struct.pack(">I", schema_version)


def encrypt_profile(profile: Profile, dek: bytes, schema_version: int = SCHEMA_VERSION) -> Tuple[bytes, bytes]:
    """Encrypts Profile using AES-256-GCM with DEK."""
    nonce = secrets.token_bytes(NONCE_LEN_BYTES)
    aad = compute_profile_aad("profile", schema_version)
    plaintext = json.dumps(profile.to_dict()).encode("utf-8")
    aesgcm = AESGCM(dek)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt_profile(nonce: bytes, ciphertext: bytes, dek: bytes, schema_version: int = SCHEMA_VERSION) -> Profile:
    """Decrypts Profile using AES-256-GCM with DEK."""
    aad = compute_profile_aad("profile", schema_version)
    aesgcm = AESGCM(dek)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    except Exception:
        raise AuthError("Integrity check failed for profile. Data is corrupted or tampered.")
    data = json.loads(plaintext.decode("utf-8"))
    return Profile.from_dict(data)
