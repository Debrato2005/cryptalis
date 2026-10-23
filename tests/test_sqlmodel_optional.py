"""The optional API reports absent dependencies before any effects."""

import importlib.util

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import registry


def test_optional_sqlmodel_absence_is_typed_and_has_no_database_or_key_effect():
    if importlib.util.find_spec('sqlmodel') is not None:
        pytest.skip('this control requires the plain SQLAlchemy environment without SQLModel')
    from cryptalis.sqlmodel import SQLModelUnavailable, attach
    engine = create_engine('postgresql+psycopg://', hide_parameters=True)
    observed = []
    event.listen(engine, 'connect', lambda *args: observed.append('connected'))
    try:
        with pytest.raises(SQLModelUnavailable) as failure:
            attach(registry(), engine, lock=b'', keys=lambda tenant: pytest.fail('key resolution'))
        assert failure.value.stage == 'SQLModel dependency admission'
        assert '0.0.48' in failure.value.remedy
        assert observed == []
    finally:
        engine.dispose()
