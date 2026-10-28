"""Explicit fixture host adapters around unchanged original HTTP/auth functions.

This is application integration code, not a generic Cryptalis API. Global User
authentication remains native. Only authenticated, preauthorized Item requests
select tenant sessions. Global pagination uses one exact public metadata page;
account deletion translates the original tenant-only bulk DELETE into scoped
ORM deletions in the same transaction as the unchanged account handler.
"""
from uuid import UUID

from fastapi import HTTPException, Request
from fastapi.security.utils import get_authorization_scheme_param
from sqlalchemy.sql.dml import Delete
from sqlmodel import select


class TenantHost:
    def __init__(self, api, public_factory, scoped_factory, *, approved_tenants, deployment):
        self.api = api
        self.public_factory = public_factory
        self.scoped_factory = scoped_factory
        self.approved_tenants = frozenset(approved_tenants)
        self.deployment = deployment
        self.scopes = []
        self.payload_requests = 0
        self.fail_next_account_commit = False
        self.after_owner_probe = None

    def __enter__(self):
        from app.api.deps import get_db
        from app.models import ItemsPublic
        self.previous = self.api.dependency_overrides.copy()
        self.api.dependency_overrides[get_db] = self.database
        # Newer FastAPI versions retain included routers and build effective
        # contexts lazily. Adapt the actual handler context in either layout.
        candidates = []
        for route in self.api.routes:
            contexts = getattr(route, 'effective_route_contexts', None)
            candidates.extend(contexts() if contexts else (route,))
        self.list_route = next(route for route in candidates if getattr(route, 'name', None) == 'read_items')
        self.original_list = self.list_route.dependant.call
        original = self.original_list
        def global_items(session, current_user, skip=0, limit=100):
            if not current_user.is_superuser:
                return original(session=session, current_user=current_user, skip=skip, limit=limit)
            count = session.global_count()
            return ItemsPublic(data=session.global_page(skip, limit), count=count)
        self.list_route.dependant.call = global_items
        return self

    def __exit__(self, *_):
        self.list_route.dependant.call = self.original_list
        self.api.dependency_overrides.clear()
        self.api.dependency_overrides.update(self.previous)

    def _session(self, tenant):
        if type(tenant) is not UUID or tenant not in self.approved_tenants:
            raise HTTPException(status_code=409, detail='Item owner policy is not approved')
        # The host re-admits its retained current artifact on every request,
        # before key lookup. The journal can deny stale authority, never choose
        # a new tenant or supply the externally published successor artifact.
        from cryptalis import migration
        plan, pin = self.deployment
        with self.public_factory() as public:
            migration.check_deployment(plan, public.get_bind(), pin=pin)
        self.scopes.append(tenant)
        return self.scoped_factory(tenant_id=tenant, expire_on_commit=False)

    def database(self, request: Request):
        from app.api.deps import get_current_active_superuser, get_current_user
        from app.models import Item, User
        path = request.url.path
        items = path.startswith('/api/v1/items/')
        deleting_account = request.method == 'DELETE' and path.startswith('/api/v1/users/')
        with self.public_factory() as native:
            if not items and not deleting_account:
                yield native
                return
            scheme, token = get_authorization_scheme_param(request.headers.get('Authorization'))
            if scheme.lower() != 'bearer' or not token:
                raise HTTPException(status_code=401, detail='Not authenticated',
                    headers={'WWW-Authenticate': 'Bearer'})
            # Use the original JWT signature/expiry, account existence, activity
            # and superuser rules. JWT extra claims never choose tenant keys.
            account = get_current_user(native, token)
            tenant = account.id
            identity = None
            if deleting_account:
                target = request.path_params.get('user_id')
                if target is not None:
                    get_current_active_superuser(account)
                    try:
                        tenant = UUID(target)
                    except ValueError:
                        yield native  # Let unchanged FastAPI path validation report 422.
                        return
                    if tenant == account.id or native.get(User, tenant) is None:
                        yield native  # Original self-delete/missing-user errors precede any item DML.
                        return
                elif account.is_superuser:
                    yield native
                    return
            elif 'id' in request.path_params:
                try:
                    identity = UUID(request.path_params['id'])
                except ValueError:
                    yield native
                    return
                tenant = native.exec(select(Item.owner_id).where(Item.id == identity)).first()
                if tenant is None:
                    raise HTTPException(status_code=404, detail='Item not found')
                if not account.is_superuser and tenant != account.id:
                    raise HTTPException(status_code=403, detail='Not enough permissions')
                if self.after_owner_probe is not None:
                    self.after_owner_probe(identity, tenant)
            with self._session(tenant) as scoped:
                if identity is not None:
                    # A public owner probe grants no payload authority by itself.
                    # Lock/recheck on the scoped transaction before loading Item.
                    actual = scoped.exec(select(Item.owner_id).where(Item.id == identity).with_for_update()).first()
                    if actual is None:
                        raise HTTPException(status_code=404, detail='Item not found')
                    if actual != tenant:
                        raise HTTPException(status_code=409, detail='Item owner changed; retry the request')
                yield _RequestSession(self, scoped, native, tenant, deleting_account)


class _RequestSession:
    """Finite original-handler adaptation, with ordinary native session results."""
    def __init__(self, host, scoped, public, tenant, deleting_account):
        self.host, self.scoped, self.public = host, scoped, public
        self.tenant, self.deleting_account = tenant, deleting_account

    def __getattr__(self, name):
        return getattr(self.scoped, name)

    def get(self, model, identity, **options):
        from app.models import Item
        if model is Item:
            self.host.payload_requests += 1
        return self.scoped.get(model, identity, **options)

    def exec(self, statement, *args, **options):
        from app.models import Item
        if isinstance(statement, Delete):
            expected = Item.owner_id == self.tenant
            if (not self.deleting_account or args or options or statement.table.name != Item.__tablename__
                    or statement.whereclause is None or not statement.whereclause.compare(expected)
                    or statement._returning):
                raise RuntimeError('Unadmitted host account cascade statement')
            rows = self.scoped.exec(select(Item).where(Item.owner_id == self.tenant).with_for_update()).all()
            for row in rows:
                self.scoped.delete(row)
            self.scoped.flush()
            # The original handler intentionally ignores its bulk-delete result.
            return None
        return self.scoped.exec(statement, *args, **options)

    def commit(self):
        if self.deleting_account and self.host.fail_next_account_commit:
            self.host.fail_next_account_commit = False
            raise RuntimeError('Injected fixture account commit failure')
        return self.scoped.commit()

    def global_count(self):
        from sqlmodel import func
        from app.models import Item
        return self.public.exec(select(func.count()).select_from(Item)).one()

    def global_page(self, skip, limit):
        from app.models import Item
        # Only public identity/owner/order metadata is selected globally. The
        # original native ORDER/OFFSET/LIMIT is applied once, before decryption.
        metadata = self.public.exec(select(Item.id, Item.owner_id)
            .order_by(Item.created_at.desc()).offset(skip).limit(limit).with_for_update()).all()
        result = []
        for identity, owner in metadata:
            with self.host._session(owner) as scoped:
                row = scoped.get(Item, identity)
                self.host.payload_requests += 1
                if row is None or row.owner_id != owner:
                    raise RuntimeError('Administrator page changed during protected loading')
                scoped.expunge(row)
                result.append(row)
        return result
