"""Original SQLModel Boolean/default behavior through the full application exit."""
from test_sqlmodel_application import run_application


def test_original_template_boolean_storage_and_current_exit(tmp_path, monkeypatch):
    run_application(tmp_path, monkeypatch, boolean_storage=True)


def test_original_template_boolean_and_searchable_email_share_current_lifecycle(tmp_path, monkeypatch):
    run_application(tmp_path, monkeypatch, boolean_storage=True, searchable_email=True)
