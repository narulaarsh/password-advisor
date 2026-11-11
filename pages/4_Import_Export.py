"""
pages/4_Import_Export.py
------------------------
Import & Backup Engine:
- CSV password import (Google Chrome, Bitwarden, generic CSV formats)
- Zero-plaintext encrypted backup (.spvault) export and restore
- Plaintext CSV export with explicit disclosure confirmation
"""

import io
import json
import tempfile
from pathlib import Path
import streamlit as st

from vault.ui_common import require_unlocked_vault
from vault.session import SessionManager
from vault.importers import parse_csv_stream
from vault.backup import (
    create_encrypted_backup,
    restore_encrypted_backup,
    backup_is_authenticated,
    export_decrypted_csv,
    SPVAULT_FORMAT_TAG,
    SPVAULT_VERSION
)


def render_import_export_page():
    store, dek = require_unlocked_vault()
    entries = store.list_entries(dek)

    st.title(" Import & Backup")
    st.markdown("Transfer your credentials and maintain cryptographically secure local backups.")

    tab_import, tab_backup, tab_export_csv = st.tabs([
        " Import CSV",
        " Encrypted Backup (.spvault)",
        " Export Plaintext CSV"
    ])

    # ── Tab 1: CSV Import ───────────────────────────────────────────────────────
    with tab_import:
        st.markdown("#### Import from Browser or Password Manager")
        st.markdown(
            "Upload an exported CSV from **Google Chrome / Google Password Manager**, **Bitwarden**, "
            "or a generic password CSV. Entries will be encrypted locally using your vault's AES-256-GCM key."
        )

        uploaded_csv = st.file_uploader("Choose CSV file", type=["csv"], key="uploader_csv")

        if uploaded_csv is not None:
            csv_text = uploaded_csv.getvalue().decode("utf-8-sig", errors="replace")
            parsed_entries, warnings = parse_csv_stream(io.StringIO(csv_text))

            if warnings:
                with st.expander(" Import Warnings", expanded=False):
                    for w in warnings:
                        st.caption(f"- {w}")

            if not parsed_entries:
                st.error("No valid credentials found in this CSV file.")
            else:
                st.success(f"Discovered **{len(parsed_entries)} credentials** ready for encryption.")

                # Preview Table
                preview_data = [
                    {
                        "Site / Service": e.site_name,
                        "URL": e.url,
                        "Username": e.username,
                        "Password Length": f"{len(e.password)} chars"
                    }
                    for e in parsed_entries[:15]
                ]
                st.dataframe(preview_data, use_container_width=True)
                if len(parsed_entries) > 15:
                    st.caption(f"Showing first 15 of {len(parsed_entries)} entries.")

                if st.button(f" Import & Encrypt {len(parsed_entries)} Entries", type="primary"):
                    with st.spinner("Encrypting and writing records to local database..."):
                        for e in parsed_entries:
                            store.put_entry(e, dek)
                    st.success(f"Successfully imported and encrypted {len(parsed_entries)} credentials!")
                    # Invalidate audit cache so new entries get audited
                    if "_cached_audit_report" in st.session_state:
                        del st.session_state._cached_audit_report
                    st.rerun()

    # ── Tab 2: Encrypted Backup (.spvault) ──────────────────────────────────────
    with tab_backup:
        st.markdown("#### Zero-Knowledge Encrypted Backup (.spvault)")
        st.markdown(
            "An `.spvault` backup contains your Argon2id keyslots, cryptographic nonces, and AES-256-GCM ciphertexts. "
            "**No plaintext passwords or secrets exist inside this file.** "
            "You can safely store this backup on a USB drive or cloud storage without compromising security."
        )

        col_b_exp, col_b_imp = st.columns(2)

        with col_b_exp:
            st.markdown("##### 1. Export Vault Backup")
            st.caption(f"Current vault contains **{len(entries)} encrypted records**.")

            if len(entries) == 0:
                st.info("Vault is empty. Add entries before creating a backup.")
            else:
                with tempfile.NamedTemporaryFile(suffix=".spvault", delete=False) as tmp_b:
                    tmp_b_path = tmp_b.name

                try:
                    create_encrypted_backup(store, tmp_b_path, dek=dek)
                    with open(tmp_b_path, "rb") as f:
                        spvault_bytes = f.read()

                    st.download_button(
                        label=" Download Encrypted Backup (.spvault)",
                        data=spvault_bytes,
                        file_name=f"vault_backup_{int(time.time())}.spvault",
                        mime="application/json",
                        type="primary",
                        use_container_width=True
                    )
                finally:
                    if Path(tmp_b_path).exists():
                        Path(tmp_b_path).unlink()

        with col_b_imp:
            st.markdown("##### 2. Restore from .spvault Backup")
            st.caption("Restoring overwrites current database header and imports all records.")

            uploaded_spvault = st.file_uploader("Upload .spvault Backup File", type=["spvault", "json"], key="uploader_spvault")

            backup_password = st.text_input("Backup master password", type="password", key="backup_mpw")
            if uploaded_spvault is not None:
                try:
                    legacy_backup = not backup_is_authenticated(json.loads(uploaded_spvault.getvalue()))
                except (ValueError, TypeError, AttributeError):
                    legacy_backup = False  # malformed files are rejected by the restore checks
                confirm_legacy = True
                if legacy_backup:
                    st.warning(
                        "This is a legacy backup without an authenticated manifest. Each record is still "
                        "authenticated, but deleted records or an edited record count cannot be detected."
                    )
                    confirm_legacy = st.checkbox("Restore this unauthenticated legacy backup anyway", key="chk_confirm_legacy")
                confirm_restore = st.checkbox(" I understand restoring replaces vault keys with the backup's keyslots", key="chk_confirm_restore") and confirm_legacy
                if st.button(" Restore Vault Backup", disabled=not confirm_restore, type="primary"):
                    with tempfile.NamedTemporaryFile(suffix=".spvault", delete=False) as tmp_r:
                        tmp_r.write(uploaded_spvault.getvalue())
                        tmp_r_path = tmp_r.name

                    try:
                        restored_count = restore_encrypted_backup(tmp_r_path, store, master_password=backup_password)
                        SessionManager.lock_vault(st.session_state)
                        st.success(f"Successfully restored {restored_count} records! Vault is now updated.")
                        if "_cached_audit_report" in st.session_state:
                            del st.session_state._cached_audit_report
                        st.rerun()
                    except Exception as e:
                        st.error(f"Restore failed: {str(e)}")
                    finally:
                        if Path(tmp_r_path).exists():
                            Path(tmp_r_path).unlink()

    # ── Tab 3: Decrypted CSV Export ─────────────────────────────────────────────
    with tab_export_csv:
        st.markdown("#### Export Decrypted Plaintext CSV")
        st.warning(
            " **SECURITY WARNING:** Exporting decrypted credentials will produce an unencrypted plain text file on your drive. "
            "Anyone with access to your filesystem or disk will be able to read your passwords. "
            "Delete this file immediately after transferring."
        )

        confirm_csv_exp = st.checkbox("I understand the security risk of exporting plaintext credentials.", key="chk_csv_warning")

        if confirm_csv_exp and len(entries) > 0:
            with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp_csv:
                tmp_csv_path = tmp_csv.name

            try:
                export_decrypted_csv(entries, tmp_csv_path)
                with open(tmp_csv_path, "r", encoding="utf-8") as f:
                    csv_data = f.read()

                st.download_button(
                    label=" Download Plaintext CSV",
                    data=csv_data,
                    file_name=f"vault_decrypted_export_{int(time.time())}.csv",
                    mime="text/csv",
                    type="primary"
                )
            finally:
                if Path(tmp_csv_path).exists():
                    Path(tmp_csv_path).unlink()


if __name__ == "__main__":
    import time
    render_import_export_page()
