from __future__ import annotations

from datetime import timedelta

from app.db import Repository, iso, utc_now


def test_rotation_activates_new_immutable_version_and_retires_old(tmp_path, metadata_material):
    repository = Repository(tmp_path / "test.db")
    key_id = "key-1"
    repository.create_key(key_id, "orders", 120, iso(utc_now() + timedelta(seconds=120)))
    repository.add_version(key_id, metadata_material, iso(utc_now() + timedelta(seconds=120)), "INITIAL_CREATE")
    repository.add_version(key_id, metadata_material, iso(utc_now() + timedelta(seconds=120)), "MANUAL")

    versions = repository.list_versions(key_id)
    assert [(item["version_number"], item["state"]) for item in versions] == [(2, "ACTIVE"), (1, "RETIRED")]
    assert versions[0]["id"] != versions[1]["id"]


def test_destroy_wipes_persisted_secret_fields(tmp_path, metadata_material):
    repository = Repository(tmp_path / "test.db")
    repository.create_key("key-1", "orders", 120, iso(utc_now() + timedelta(seconds=120)))
    repository.add_version("key-1", metadata_material, iso(utc_now() + timedelta(seconds=120)), "INITIAL_CREATE")
    version = repository.get_version("key-1")
    repository.transition_version(version["id"], "DESTROYED")
    destroyed = repository.get_version("key-1", 1)
    assert destroyed["state"] == "DESTROYED"
    assert destroyed["protected_material"] is None
    assert destroyed["wrapped_dek"] is None
    assert destroyed["kem_ciphertext"] is None

