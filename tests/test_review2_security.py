"""Review 2 E5: authenticated backup manifest, and explicit tests of the rollback/deletion boundary."""
import json
import shutil

import pytest

from vault.backup import backup_is_authenticated, create_encrypted_backup, restore_encrypted_backup
from vault.crypto import create_vault_header, unlock_dek_with_password
from vault.models import Entry, Profile
from vault.store import VaultStore

PW = "MasterPass#fixture123"


def make_store(tmp_path, name="s.db", entries=3):
    store = VaultStore(str(tmp_path / name))
    header, dek, _ = create_vault_header(PW)
    store.save_header(header)
    store.save_profile(Profile("Fictional", "Person", "Nowhere", 1990), dek)
    for k in range(entries):
        store.put_entry(Entry(f"id{k}", f"site{k}", "", "user", f"fictional-secret-{k}"), dek)
    return store, dek


def backup(tmp_path, store, dek):
    path = tmp_path / "b.spvault"
    create_encrypted_backup(store, str(path), dek=dek)
    return path


def rewrite(path, change):
    data = json.loads(path.read_text())
    change(data)
    path.write_text(json.dumps(data))


def test_backup_with_dek_is_authenticated_and_restores(tmp_path):
    store, dek = make_store(tmp_path)
    path = backup(tmp_path, store, dek)
    data = json.loads(path.read_text())
    assert data["version"] == 2 and backup_is_authenticated(data)
    assert "fictional-secret" not in path.read_text()
    target = VaultStore(str(tmp_path / "t.db"))
    assert restore_encrypted_backup(str(path), target, master_password=PW, require_manifest=True) == 3
    assert target.get_entry("id2", dek).password == "fictional-secret-2"


def test_deleted_backup_record_with_adjusted_count_is_rejected(tmp_path):
    store, dek = make_store(tmp_path)
    path = backup(tmp_path, store, dek)

    def drop(data):
        data["records"].pop(0)
        data["record_count"] -= 1

    rewrite(path, drop)
    target, _ = make_store(tmp_path, "t.db", entries=1)
    with pytest.raises(ValueError, match="manifest authentication failed"):
        restore_encrypted_backup(str(path), target, master_password=PW)
    assert target.count_entries() == 1  # previous vault untouched


@pytest.mark.parametrize("field", ["profile", "header_argon2", "record_order_and_id"])
def test_other_manifest_tampering_is_rejected(tmp_path, field):
    store, dek = make_store(tmp_path)
    path = backup(tmp_path, store, dek)

    def tamper(data):
        if field == "profile":
            data["profile"] = None
        elif field == "header_argon2":
            data["header"]["exported_note"] = "x"
        else:
            data["records"][0]["id"], data["records"][1]["id"] = data["records"][1]["id"], data["records"][0]["id"]

    rewrite(path, tamper)
    with pytest.raises(Exception):
        restore_encrypted_backup(str(path), VaultStore(str(tmp_path / "t.db")), master_password=PW)


def test_v2_backup_with_stripped_manifest_is_rejected(tmp_path):
    store, dek = make_store(tmp_path)
    path = backup(tmp_path, store, dek)
    rewrite(path, lambda d: d.pop("manifest"))
    with pytest.raises(ValueError, match="missing its authenticated manifest"):
        restore_encrypted_backup(str(path), VaultStore(str(tmp_path / "t.db")), master_password=PW)


def test_downgrade_to_legacy_is_only_caught_when_manifest_required(tmp_path):
    """Documented limitation: a legacy (v1) file cannot prove completeness."""
    store, dek = make_store(tmp_path)
    path = backup(tmp_path, store, dek)

    def downgrade(data):
        data.pop("manifest")
        data["version"] = 1
        data["records"].pop(0)
        data["record_count"] -= 1

    rewrite(path, downgrade)
    with pytest.raises(ValueError, match="no authenticated manifest"):
        restore_encrypted_backup(str(path), VaultStore(str(tmp_path / "t.db")), master_password=PW,
                                 require_manifest=True)
    # Without the requirement the deletion goes undetected; the UI warns before this path.
    assert restore_encrypted_backup(str(path), VaultStore(str(tmp_path / "u.db")), master_password=PW) == 2


def test_wrong_password_cannot_forge_or_verify_manifest(tmp_path):
    store, dek = make_store(tmp_path)
    path = backup(tmp_path, store, dek)
    with pytest.raises(Exception):
        restore_encrypted_backup(str(path), VaultStore(str(tmp_path / "t.db")), master_password="wrong-password-123!")


def test_authenticated_backup_requires_password_even_for_fresh_store(tmp_path):
    store, dek = make_store(tmp_path)
    path = backup(tmp_path, store, dek)
    with pytest.raises(ValueError):
        restore_encrypted_backup(str(path), VaultStore(str(tmp_path / "t.db")))


def test_whole_file_rollback_is_not_detected(tmp_path):
    """Documented limitation (E5): replacing the database with an older valid copy succeeds."""
    store, dek = make_store(tmp_path, entries=1)
    snapshot = tmp_path / "old.db"
    store.close() if hasattr(store, "close") else None
    shutil.copy(tmp_path / "s.db", snapshot)
    store = VaultStore(str(tmp_path / "s.db"))
    store.put_entry(Entry("new", "later-site", "", "user", "fictional-later"), dek)
    assert store.count_entries() == 2
    store.close() if hasattr(store, "close") else None
    for suffix in ("", "-wal", "-shm"):
        (tmp_path / f"s.db{suffix}").unlink(missing_ok=True)
    shutil.copy(snapshot, tmp_path / "s.db")
    rolled = VaultStore(str(tmp_path / "s.db"))
    unlock_dek_with_password(rolled.get_header(), PW)  # unlock still succeeds
    assert rolled.count_entries() == 1 and rolled.get_entry("new", dek) is None


def test_live_record_deletion_is_not_detected(tmp_path):
    """Documented limitation (E5): deleting a ciphertext row leaves the rest decryptable."""
    store, dek = make_store(tmp_path)
    with store._get_connection() as conn:
        conn.execute("DELETE FROM records WHERE id='id1'")
    assert [e.id for e in store.list_entries(dek)] == ["id0", "id2"] or len(store.list_entries(dek)) == 2
