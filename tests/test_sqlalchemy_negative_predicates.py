"""Native PostgreSQL is the oracle for approved NULL and negative-term shapes.

Finite randomized values are test data, not a real low-cardinality search approval.
"""
import asyncio,random
import pytest
from sqlalchemy import select,bindparam,Text,and_,or_,not_
from sqlalchemy.orm import aliased
from test_sqlalchemy_search import search_application,_row,_async_factory,OTHER

KINDS=['is_not_null','ne','ne_reverse','not_in_empty','not_in_null','not_in_values','not_in_mixed','not_in_late','not_of_in','not_of_eq']
VALUES=[None,'','a','A','é','e\u0301','雪','😀','a ',' ',"quote'and\\slash"]

def predicate(column,kind,value,choices):
    if kind=='is_not_null':return column.is_not(None),{}
    if kind=='ne':return column!=value,{}
    if kind=='ne_reverse':return bindparam('value',type_=Text())!=column,{'value':value}
    if kind=='not_in_empty':return column.not_in([]),{}
    if kind=='not_in_null':return column.not_in([None]),{}
    if kind=='not_in_values':return column.not_in([x for x in choices if x is not None]),{}
    if kind=='not_in_mixed':return column.not_in(choices+[None]),{}
    if kind=='not_in_late':return column.not_in(bindparam('choices',expanding=True,type_=Text())),{'choices':choices}
    if kind=='not_of_in':return not_(column.in_(choices)),{}
    if kind=='not_of_eq':return not_(column==value),{}
    raise AssertionError(kind)

@pytest.mark.parametrize('kind',KINDS)
@pytest.mark.parametrize('mode',['sync','async'])
@pytest.mark.parametrize('single',[False,True])
def test_fixed_seed_negative_query_truth_and_rows_match_native(kind,mode,single):
    rng=random.Random(440901);values=[rng.choice(VALUES) for _ in range(48)]
    inputs=[(rng.choice(VALUES),[rng.choice(VALUES) for _ in range(rng.randrange(5))]) for _ in range(5)]
    outcomes=[]
    for protected in (False,True):
        with search_application(protected,single_tenant=single,attach_now=mode=='sync') as app:
            def rows():
                r=[_row(app,v,i) for i,v in enumerate(values)]
                return r
            def queries():
                c=aliased(app.Customer)
                scope=[] if single else [c.tenant_id==app.tenant]
                for value,choices in inputs:
                    expr,params=predicate(c.name,kind,value,choices)
                    yield select(c.rank,expr.label('truth')).where(*scope).order_by(c.rank),params
                    yield select(c.rank,c.name).where(*scope,expr).order_by(c.rank).offset(1).limit(8),params
                    yield select(c.rank,or_(expr,c.rank==0).label('composed')).where(*scope).order_by(c.rank),params
            if mode=='sync':
                with app.sessions(tenant_id=app.tenant) as s:
                    s.add_all(rows());s.commit()
                    if not single:
                        with app.sessions(tenant_id=OTHER) as foreign:
                            foreign.add_all([_row(app,'other-tenant',100+i,OTHER) for i in range(3)]);foreign.commit()
                    actual=[[tuple(r) for r in s.execute(q,params)] for q,params in queries()]
            else:
                async def scenario():
                    engine,sessions=await _async_factory(app)
                    try:
                        async with sessions(tenant_id=app.tenant) as s:
                            s.add_all(rows());await s.commit()
                            if not single:
                                async with sessions(tenant_id=OTHER) as foreign:
                                    foreign.add_all([_row(app,'other-tenant',100+i,OTHER) for i in range(3)]);await foreign.commit()
                            return [[tuple(r) for r in await s.execute(q,params)] for q,params in queries()]
                    finally:await engine.dispose()
                actual=asyncio.run(scenario())
            outcomes.append(actual)
    assert outcomes[1]==outcomes[0]

@pytest.mark.parametrize('kind',['is_not_null','ne','not_in_empty','not_in_null','not_in_values','not_in_mixed'])
@pytest.mark.parametrize('single',[False,True])
def test_outer_join_absent_and_present_null_negative_truth_matches_native(kind,single):
    outcomes=[]
    for protected in (False,True):
        with search_application(protected,single_tenant=single) as app:
            with app.sessions(tenant_id=app.tenant) as s:
                s.add_all([_row(app,'left',i) for i in range(1,5)]+[_row(app,None,101),_row(app,'a',102),_row(app,'b',103)])
                s.commit()
                left,right=aliased(app.Customer),aliased(app.Customer)
                on=left.rank+100==right.rank
                if not single:on=and_(on,right.tenant_id==app.tenant)
                expr,params=predicate(right.name,kind,'a',['a'])
                q=select(left.rank,expr.label('truth'),right.name).select_from(left).outerjoin(right,on).where(left.rank.between(1,4)).order_by(left.rank)
                if not single:q=q.where(left.tenant_id==app.tenant)
                outcomes.append(([tuple(r) for r in s.execute(q,params)],[tuple(r) for r in s.execute(q.where(expr),params)]))
    assert outcomes[1]==outcomes[0]

from test_sqlalchemy_adapter import app,db,factory,TENANT
from uuid import uuid4

@pytest.mark.parametrize('protected',[False,True])
@pytest.mark.parametrize('negated',[False,True])
def test_storage_only_null_predicates_need_no_equality_representation(app,protected,negated):
    sessions=factory(app,protected)
    with sessions(tenant_id=TENANT) as s:
        for i,value in enumerate([None,'','雪']):
            s.add(app.Customer(id=uuid4(),tenant_id=TENANT,name=f'name-{i}',note=value,secret='',rank=i))
        s.commit()
        expr=app.Customer.note.is_not(None) if negated else app.Customer.note.is_(None)
        values=[tuple(r) for r in s.execute(select(app.Customer.rank,expr).order_by(app.Customer.rank))]
        assert values==[(0,not negated),(1,negated),(2,negated)]

@pytest.mark.parametrize('kind',['ne','not_in_values','not_in_empty'])
def test_negative_predicate_retains_authenticated_tenant_guard(kind):
    with search_application(True) as app:
        for tenant,rank in [(app.tenant,1),(OTHER,2)]:
            with app.sessions(tenant_id=tenant) as s:
                s.add(_row(app,'present',rank,tenant));s.commit()
        expr,params=predicate(app.Customer.name,kind,'absent',['absent'])
        with app.sessions(tenant_id=app.tenant) as s:
            assert list(s.scalars(select(app.Customer.rank).where(expr),params))==[1]
