"""
vault/ui_common.py
------------------
Common UI framework, styling, and session authentication for Streamlit app:
- Sleek dark-mode glassmorphic theme and custom typography
- Session-level store and auto-lock management
- Gatekeeper function `require_unlocked_vault()` ensuring no unauthorized page access
- Setup and Unlock interactive forms
"""

import math
import os
import time
from typing import Optional, Tuple, Dict, Any

import streamlit as st
from streamlit_autorefresh import st_autorefresh

from vault.models import VaultHeader, Profile, Entry
from vault.crypto import (
    create_vault_header,
    calibrate_argon2_parameters,
    generate_recovery_key,
    parse_recovery_key,
    unlock_dek_with_password,
    unlock_dek_with_recovery,
)
from vault.store import VaultStore
from vault.session import SessionManager, validate_master_password

DB_PATH = "vault.db"


def apply_custom_styles():
    """Injects modern, premium CSS with glassmorphism and crisp typography."""
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

        html, body, [class*="css"] {
            font-family: 'Inter', sans-serif;
        }

        code, pre {
            font-family: 'JetBrains Mono', monospace !important;
        }

        /* Glassmorphism Cards */
        .cav-card {
            background: rgba(255, 255, 255, 0.04);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            padding: 1.25rem;
            margin-bottom: 1rem;
            transition: transform 0.15s ease, border-color 0.15s ease;
        }
        .cav-card:hover {
            border-color: rgba(59, 130, 246, 0.4);
        }

        /* Health Gauge Card */
        .vhs-gauge-card {
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.9));
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 1.5rem;
            text-align: center;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        }

        /* Status Badges */
        .badge {
            display: inline-block;
            padding: 0.25rem 0.6rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-right: 0.4rem;
            margin-bottom: 0.3rem;
        }
        .badge-danger {
            background-color: rgba(239, 68, 68, 0.2);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.4);
        }
        .badge-warning {
            background-color: rgba(245, 158, 11, 0.2);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.4);
        }
        .badge-info {
            background-color: rgba(59, 130, 246, 0.2);
            color: #60a5fa;
            border: 1px solid rgba(59, 130, 246, 0.4);
        }
        .badge-success {
            background-color: rgba(16, 185, 129, 0.2);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.4);
        }

        /* Password Pill */
        .password-pill {
            font-family: 'JetBrains Mono', monospace;
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 0.3rem 0.75rem;
            border-radius: 6px;
            font-size: 0.9rem;
            color: #38bdf8;
        }
        </style>
        """,
        unsafe_allow_html=True
    )


def get_store() -> VaultStore:
    """Returns singleton VaultStore instance attached to session."""
    if "_vault_store" not in st.session_state:
        st.session_state._vault_store = VaultStore(db_path=DB_PATH)
    return st.session_state._vault_store


def render_setup_view(store: VaultStore):
    """Renders initial vault setup wizard."""
    st.subheader(" Initialize Your Local Secure Vault")
    st.markdown(
        "Welcome to **Context-Aware Vault**. Your passwords and profile will be protected "
        "using **Argon2id KDF** and **AES-256-GCM** envelope encryption on your local machine. "
        "No keys or credentials ever leave your host."
    )

    with st.form("vault_init_form"):
        st.markdown("#### 1. Set Master Password")
        mpw = st.text_input("Master Password", type="password", key="init_mpw", help="At least 12 characters, high entropy, zero known breaches.")
        mpw_confirm = st.text_input("Confirm Master Password", type="password", key="init_mpw_confirm")
        
        st.markdown("#### 2. Optional Context Profile (for Thematic Defense)")
        st.caption("Used exclusively locally by the audit engine to detect guessable personal data in your passwords.")
        col1, col2 = st.columns(2)
        with col1:
            first_name = st.text_input("First Name", value="Maya")
            city = st.text_input("Hometown / City", value="Denver")
        with col2:
            surname = st.text_input("Surname", value="Carter")
            birth_year = st.number_input("Birth Year", min_value=1900, max_value=2026, value=1998)
        
        theme = st.text_input(
            "Preferred Passphrase Theme",
            value="baking",
            placeholder="e.g. baking, scifi, nature, gaming, travel...",
            help="Type any topic or theme you like. Used for generating personalized passphrases."
        )

        submit_init = st.form_submit_button("Create Vault & Generate Emergency Recovery Key", type="primary")

    if submit_init:
        if not mpw:
            st.error("Master password cannot be empty.")
            return
        if mpw != mpw_confirm:
            st.error("Master passwords do not match.")
            return

        # Profile object
        profile = Profile(
            first_name=first_name.strip(),
            surname=surname.strip(),
            city=city.strip(),
            birth_year=int(birth_year),
            theme=theme.strip()
        )

        # Validate master password against dogfooding detector
        is_valid, issues = validate_master_password(mpw, profile=profile)
        if not is_valid:
            for issue in issues:
                st.error(f" {issue}")
            return

        with st.spinner("Calibrating Argon2id for this device and deriving keys..."):
            # Parameters are chosen once for this new vault and stored in its header.
            kdf = calibrate_argon2_parameters()
            formatted_rec, rec_raw = generate_recovery_key()
            header, dek, _ = create_vault_header(mpw, recovery_key=rec_raw,
                                                 m=kdf["m"], t=kdf["t"], p=kdf["p"])
            store.save_header(header)
            store.save_profile(profile, dek)

            # Save in session
            st.session_state._cav_dek = bytearray(dek)
            st.session_state._cav_unlocked = True
            st.session_state._cav_last_activity = time.time()
            st.session_state._cav_new_recovery_key = formatted_rec

        st.rerun()


def render_unlock_view(store: VaultStore):
    """Renders unlock screen for an existing vault."""
    allowed, wait_secs = store.check_unlock_allowed()

    st.subheader(" Vault Locked")
    st.markdown("Enter your master password to decrypt your credentials in local memory.")

    if not allowed:
        st.error(f" Too many failed unlock attempts. Exponential throttling active: please wait **{wait_secs:.0f} seconds**.")
        time.sleep(1)
        st.rerun()

    # Recovery key toggle
    use_recovery = st.toggle("Lost your master password? Use 256-bit Recovery Key", value=False)

    if not use_recovery:
        with st.form("unlock_form"):
            password_input = st.text_input("Master Password", type="password", key="unlock_mpw")
            submit_unlock = st.form_submit_button("Unlock Vault", type="primary")

        if submit_unlock:
            if not password_input:
                st.warning("Please enter your master password.")
                return

            with st.spinner("Deriving key and unlocking..."):
                success, msg = SessionManager.unlock_with_password(store, st.session_state, password_input)
                if success:
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(msg)
    else:
        with st.form("recovery_unlock_form"):
            st.markdown("Paste your 44-character base64 recovery key:")
            rec_input = st.text_input("Recovery Key", type="password", key="unlock_rec_key")
            submit_rec = st.form_submit_button("Unlock with Recovery Key", type="primary")

        if submit_rec:
            if not rec_input:
                st.warning("Please enter your recovery key.")
                return
            try:
                rec_bytes = parse_recovery_key(rec_input)
                success, msg = SessionManager.unlock_with_recovery(store, st.session_state, rec_bytes)
                if success:
                    st.success("Vault unlocked with recovery key! Please update your master password in Settings.")
                    st.rerun()
                else:
                    st.error(msg)
            except Exception as e:
                st.error(f"Invalid recovery key format: {str(e)}")


def render_vault_status_bar(store: VaultStore):
    """Renders persistent top status bar with lock button and inactivity countdown."""
    SessionManager.update_activity(st.session_state)
    
    last_act = st.session_state.get("_cav_last_activity", time.time())
    timeout_min = st.session_state.get("_cav_auto_lock_minutes", 5)
    remaining_secs = max(0, int((timeout_min * 60) - (time.time() - last_act)))
    rem_min = remaining_secs // 60
    rem_s = remaining_secs % 60

    col1, col2, col3 = st.columns([3, 2, 1])
    with col1:
        st.caption(f" **Vault Unlocked** | Auto-locks in {rem_min:02d}:{rem_s:02d}")
    with col2:
        pass
    with col3:
        if st.button(" Lock Vault", key="btn_lock_vault", help="Immediately zeroises keys in memory"):
            SessionManager.lock_vault(st.session_state)
            st.rerun()


def require_unlocked_vault() -> Tuple[VaultStore, bytes]:
    """
    Guarantees the vault is initialized and unlocked before rendering page content.
    Returns (store, dek). Halts execution (st.stop()) if locked.
    """
    apply_custom_styles()
    
    # Run auto-lock ticker every 15s
    st_autorefresh(interval=15000, key="cav_global_autorefresh")

    store = get_store()

    # 1. Check if vault exists
    if not store.vault_exists():
        render_setup_view(store)
        st.stop()

    # 2. Check auto-lock expiration
    was_locked = SessionManager.check_auto_lock(st.session_state)
    if was_locked:
        st.info(" Vault auto-locked due to inactivity.")

    # 3. Check if unlocked
    if not SessionManager.is_unlocked(st.session_state):
        render_unlock_view(store)
        st.stop()

    # 4. Render emergency recovery key banner if freshly initialized
    if "_cav_new_recovery_key" in st.session_state:
        new_key = st.session_state.pop("_cav_new_recovery_key")
        st.warning(
            f" **IMPORTANT: Save Your Emergency Recovery Key Now!**\n\n"
            f"If you lose your master password, this key is the ONLY way to recover your vault:\n\n"
            f"`{new_key}`\n\n"
            "Store it securely offline (e.g. printed or in a safe deposit box)."
        )

    render_vault_status_bar(store)
    dek = SessionManager.get_dek(st.session_state)
    return store, dek
