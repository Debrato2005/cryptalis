"""One key-free declaration shared by application and operator entry points."""

from dataclasses import dataclass

from sqlalchemy.orm import registry

from .manifest.compiler import SearchReview, WriterInventory
from .manifest.declaration import parse_protection_declaration


class ConfigurationInvalid(ValueError):
    """Invalid configuration or intent inconsistent with the supplied deployment."""

    effects = 'NONE'

    def __init__(self, code='Application.InvalidConfiguration'):
        self.code = code
        super().__init__(code + ': supply explicit configuration matching the trusted deployment.')


@dataclass(frozen=True, repr=False)
class ApplicationConfig:
    """Public intent without engines, keys, credentials or deployment authority.

    Construction only parses the manifest; it performs no database/provider work.
    Python operations borrow their engine. CLI contexts transfer a fresh engine
    to the command, which disposes it. Host authentication remains explicit.
    """

    manifest: bytes
    mapping: registry
    writers: WriterInventory
    search_reviews: tuple[SearchReview, ...] = ()
    queries: tuple = ()

    def __post_init__(self):
        if (type(self.manifest) is not bytes or not isinstance(self.mapping, registry)
                or not isinstance(self.writers, WriterInventory)
                or type(self.search_reviews) is not tuple
                or any(not isinstance(review, SearchReview) for review in self.search_reviews)
                or type(self.queries) is not tuple or len(self.queries) > 128):
            raise ConfigurationInvalid()
        object.__setattr__(self, 'manifest', parse_protection_declaration(self.manifest).canonical_bytes())

    def initialization_context(self, engine):
        """Return the key-free context used by init and pre-adoption Doctor."""
        from .cli_host import InitializationContext
        return InitializationContext(engine, self.mapping, self.manifest, self.writers,
                                     self.search_reviews, self.queries)

    def diagnose(self, engine):
        """Inspect native schema and supplied SELECT samples without rows or keys."""
        from .doctor import preflight
        return preflight(self.manifest, self.mapping, engine, writers=self.writers,
                         search_reviews=self.search_reviews, queries=self.queries)

    def planning_context(self, engine, *, keys, runtime_role, target_id,
                         backfill_rows_per_second, verify_rows_per_second,
                         temporary_bytes_per_row, wal_bytes_per_row):
        """Bind CLI planning to this intent; keys and measured estimates are explicit."""
        from .cli_host import PlanningContext
        return PlanningContext(engine=engine, mapping=self.mapping, writers=self.writers,
            search_reviews=self.search_reviews, keys=keys, runtime_role=runtime_role,
            target_id=target_id, backfill_rows_per_second=backfill_rows_per_second,
            verify_rows_per_second=verify_rows_per_second, temporary_bytes_per_row=temporary_bytes_per_row,
            wal_bytes_per_row=wal_bytes_per_row, declaration=self.manifest, queries=self.queries)

    def plan(self, engine, *, keys, runtime_role, target_id, backfill_rows_per_second,
             verify_rows_per_second, temporary_bytes_per_row, wal_bytes_per_row, layout=None):
        """Plan protection using the same declaration and query admission as Doctor."""
        from .migration import plan
        return plan(self.manifest, self.mapping, engine, writers=self.writers,
            search_reviews=self.search_reviews, queries=self.queries, keys=keys,
            runtime_role=runtime_role, target_id=target_id,
            backfill_rows_per_second=backfill_rows_per_second, verify_rows_per_second=verify_rows_per_second,
            temporary_bytes_per_row=temporary_bytes_per_row, wal_bytes_per_row=wal_bytes_per_row, layout=layout)

    def attach(self, engine, *, keys, deployment, adapter='sqlalchemy'):
        """Attach to an explicitly pinned deployment matching this declaration.

        The plan supplies its own lock. No migration or policy publication occurs.
        Await the result for an AsyncEngine. Select adapter='sqlmodel' for native
        SQLModel Session.exec behavior. Existing adapter checks remain authoritative.
        """
        from .migration import DeploymentPin, MigrationPlan
        from .manifest.compiler import _canonical, _host_evidence
        if (type(deployment) is not tuple or len(deployment) not in (2, 3)
                or type(deployment[0]) is not MigrationPlan or type(deployment[1]) is not DeploymentPin):
            raise ConfigurationInvalid('Application.InvalidDeployment')
        if type(adapter) is not str or adapter not in ('sqlalchemy', 'sqlmodel'):
            raise ConfigurationInvalid('Application.InvalidAdapter')
        plan = deployment[0]
        lock = plan.document['lock']
        declared = parse_protection_declaration(_canonical(lock['declaration']))
        if declared.canonical_bytes() != self.manifest:
            raise ConfigurationInvalid('Application.ManifestMismatch')
        issues = []
        writers, reviews = _host_evidence(declared, self.writers, self.search_reviews, issues)
        if issues or writers != lock['writer_inventory'] or reviews != lock['search_reviews']:
            raise ConfigurationInvalid('Application.HostEvidenceMismatch')
        if adapter == 'sqlmodel':
            from .sqlmodel import attach
        else:
            from .sqlalchemy import attach
        return attach(self.mapping, engine, lock=plan.lock_bytes, keys=keys, deployment=deployment)
