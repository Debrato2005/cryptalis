"""UTC order terms must preserve native timestamptz predicates and displayed results."""
from datetime import datetime, timezone
from uuid import UUID

import pytest
from sqlalchemy import DateTime, and_, bindparam, cast, func, not_, or_, select
from sqlalchemy.orm import Session, aliased
from sqlalchemy.dialects.postgresql import TIMESTAMP

from cryptalis.sqlalchemy import UnsupportedProtectedOperation, attach
from test_migration import application, keys, publish, run, TENANT
from test_timestamptz_storage import VALUES, ZONES, fingerprint, runtime_timezone


def statements(model):
    base = lambda *columns: select(*columns).where(model.tenant_id == TENANT)
    statements = []
    for pivot in VALUES[:-1]:
        for predicate in (model.name == pivot, model.name != pivot, model.name < pivot,
                          model.name <= pivot, model.name > pivot, model.name >= pivot,
                          model.name.in_((pivot, None)), model.name.not_in((pivot, None)),
                          model.name.between(pivot, VALUES[5]),
                          not_(and_(model.name >= pivot, model.name <= VALUES[5])),
                          or_(model.name < pivot, model.name.is_(None))):
            statements.append(base(model.id, model.name).where(predicate).order_by(model.id))
    statements.extend((base(model.id, model.name).order_by(model.name.asc().nulls_last(), model.id),
                       base(model.id, model.name).order_by(model.name.desc().nulls_first(), model.id).offset(1).limit(4),
                       base(func.min(model.name).label('earliest'), func.max(model.name).label('latest')),
                       base(func.min(model.name), func.max(model.name)).where(model.id == UUID(int=999))))
    alias = aliased(model)
    statements.append(select(alias.id, alias.name).where(alias.tenant_id == TENANT)
                      .order_by(alias.name, alias.id))
    return statements


def observed(factory, model):
    with factory() as session:
        return [tuple(tuple(fingerprint(value) if type(value) is datetime else value for value in row)
                      for row in session.execute(statement)) for statement in statements(model)]


@pytest.mark.parametrize('zone', ZONES)
def test_timestamptz_ranges_order_extrema_and_alias_results_match_native(zone):
    with application(value_type=DateTime(timezone=True), unique=False, queries=['equality', 'order'],
                     protected_values=VALUES) as app, runtime_timezone(app, zone):
        expected = observed(lambda: Session(app.runtime), app.Customer)
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
        assert observed(lambda: factory(tenant_id=TENANT), app.Customer) == expected
        with factory(tenant_id=TENANT) as session:
            bad = bindparam('pivot', VALUES[4], type_=DateTime(timezone=False))
            with pytest.raises(UnsupportedProtectedOperation):
                session.execute(select(app.Customer.id).where(app.Customer.tenant_id == TENANT,
                                                             app.Customer.name >= bad))


@pytest.mark.parametrize('aware', [False, True])
def test_timestamp_bind_metadata_and_explicit_precision_cast_keep_native_semantics(aware):
    value = datetime(2000, 1, 1, microsecond=123480, tzinfo=timezone.utc if aware else None)
    pivot = value.replace(microsecond=123499)
    with application(value_type=DateTime(timezone=aware), unique=False, queries=['equality', 'order'],
                     protected_values=(value,), rows=1) as app:
        def statement(explicit=False):
            bound = bindparam('cutoff', pivot, type_=TIMESTAMP(timezone=aware, precision=3))
            if explicit:
                bound = cast(bound, TIMESTAMP(timezone=aware, precision=3))
            return select(app.Customer.id).where(app.Customer.tenant_id == TENANT,
                                                app.Customer.name > bound)
        with Session(app.runtime) as session:
            assert list(session.scalars(statement())) == []
            assert list(session.scalars(statement(True))) == [UUID(int=100)]
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            assert list(session.scalars(statement())) == []
            with pytest.raises(UnsupportedProtectedOperation):
                session.execute(statement(True))
