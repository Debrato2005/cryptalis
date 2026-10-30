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
        self._deployment(deployment, allow_restore=True)
        if type(adapter) is not str or adapter not in ('sqlalchemy', 'sqlmodel'):
            raise ConfigurationInvalid('Application.InvalidAdapter')
        plan = deployment[0]
        if adapter == 'sqlmodel':
            from .sqlmodel import attach
        else:
            from .sqlalchemy import attach
        return attach(self.mapping, engine, lock=plan.lock_bytes, keys=keys, deployment=deployment)

    def apply(self, engine, *, deployment, keys, approval, chunk_size=1000, until='PENDING'):
        """Apply or resume protection; publication remains an explicit host step."""
        from .migration import apply
        self._deployment(deployment)
        plan, pin = deployment
        return apply(plan, engine, keys=keys, pin=pin, approval=approval,
                     chunk_size=chunk_size, until=until)

    def status(self, engine, *, deployment):
        """Observe protection, online capture, rotation or removal without keys."""
        from . import deprotection, migration, online, rotation
        if type(deployment) is tuple and len(deployment) == 2 and type(deployment[0]) is online.OnlineProtectionPlan:
            self._online_deployment(deployment)
            return online.status(deployment[0], engine, pin=deployment[1])
        if (type(deployment) is tuple and len(deployment) == 2
                and type(deployment[0]) in (rotation.PayloadRotationPlan, rotation.SearchRotationPlan)):
            purpose = self._rotation_deployment(deployment)
            operation = rotation.status_payload_rotation if purpose == 'payload' else rotation.status_search_rotation
            return operation(deployment[0], engine, pin=deployment[1])
        reverse = (type(deployment) is tuple and len(deployment) == 2
                   and type(deployment[0]) is deprotection.DeprotectionPlan)
        self._deployment(deployment, reverse=reverse, allow_restore=not reverse)
        plan, pin, *restored = deployment
        if reverse:
            return deprotection.status(plan, engine, pin=pin)
        return migration.status(plan, engine, pin=pin, restore=restored[0] if restored else None)

    def plan_deprotection(self, engine, *, deployment, keys, plaintext_runtime_role,
                          backfill_rows_per_second, verify_rows_per_second,
                          temporary_bytes_per_row, wal_bytes_per_row):
        """Plan restoration of current values; this grants no plaintext consent."""
        from .deprotection import plan
        self._deployment(deployment, allow_restore=True)
        source, pin, *restored = deployment
        return plan(source, engine, source_pin=pin, keys=keys,
            plaintext_runtime_role=plaintext_runtime_role,
            backfill_rows_per_second=backfill_rows_per_second, verify_rows_per_second=verify_rows_per_second,
            temporary_bytes_per_row=temporary_bytes_per_row, wal_bytes_per_row=wal_bytes_per_row,
            restore=restored[0] if restored else None)

    def decrypt_back(self, engine, *, deployment, keys, approval, consent,
                     chunk_size=1000, until='PLAINTEXT_PENDING'):
        """Resume verified current-value decryption under explicit exposure consent."""
        from .deprotection import apply
        self._deployment(deployment, reverse=True)
        plan, pin = deployment
        return apply(plan, engine, keys=keys, pin=pin, approval=approval, consent=consent,
                     chunk_size=chunk_size, until=until)

    def remove(self, engine, *, deployment, approval, consent, removal):
        """Retire eligible database objects after approved plaintext activation.

        This does not uninstall the package, retire keys or erase retained backups.
        """
        from .deprotection import remove
        self._deployment(deployment, reverse=True)
        plan, pin = deployment
        return remove(plan, engine, pin=pin, approval=approval, consent=consent, removal=removal)

    def plan_online(self, engine, *, keys, source_role, runtime_role, target_id,
                    backfill_rows_per_second, verify_rows_per_second,
                    temporary_bytes_per_row, wal_bytes_per_row,
                    max_rows=1000, max_bytes=64*1024*1024, native_tenants=None):
        """Plan bounded native-write capture with explicit roles and tenant scopes."""
        from .online import plan
        return plan(self.manifest, self.mapping, engine, writers=self.writers,
            search_reviews=self.search_reviews, queries=self.queries, keys=keys,
            source_role=source_role, runtime_role=runtime_role, target_id=target_id,
            backfill_rows_per_second=backfill_rows_per_second, verify_rows_per_second=verify_rows_per_second,
            temporary_bytes_per_row=temporary_bytes_per_row, wal_bytes_per_row=wal_bytes_per_row,
            max_rows=max_rows, max_bytes=max_bytes, native_tenants=native_tenants)

    def capture_online(self, engine, *, deployment, keys, approval, max_chunks=1,
                       fence=False, workers=1, target_chunk_seconds=None):
        """Apply/resume bounded capture; an empty backlog does not authorize cutover."""
        from .online import apply
        self._online_deployment(deployment)
        return apply(deployment[0], engine, keys=keys, pin=deployment[1], approval=approval,
            max_chunks=max_chunks, fence=fence, workers=workers, target_chunk_seconds=target_chunk_seconds)

    def seal_online(self, engine, *, deployment, keys, approval):
        """Verify fenced current values and return the exact successor to retain."""
        from .online import seal
        self._online_deployment(deployment)
        return seal(deployment[0], engine, keys=keys, pin=deployment[1], approval=approval)

    def switch_online(self, engine, *, deployment, successor, keys, approval):
        """Transfer native access under capture authority; return the PENDING plan."""
        from .migration import MigrationPlan
        from .online import switch
        self._online_deployment(deployment)
        if type(successor) is not MigrationPlan:
            raise ConfigurationInvalid('Application.InvalidDeployment')
        self._intent(successor)
        return switch(deployment[0], engine, successor=successor, keys=keys,
                      pin=deployment[1], approval=approval)

    def abort_online(self, engine, *, deployment, approval):
        """Remove uncommitted protection/capture while preserving native edits."""
        from .online import abort
        self._online_deployment(deployment)
        return abort(deployment[0], engine, pin=deployment[1], approval=approval)

    def plan_tenant(self, engine, *, deployment, keys, tenant_id, key_policy, verify_rows_per_second):
        """Plan one explicitly approved empty tenant; never infer signup authority."""
        from .tenancy import plan
        self._deployment(deployment, allow_restore=True)
        source, pin, *restored = deployment
        return plan(source, engine, source_pin=pin, keys=keys, tenant_id=tenant_id,
            key_policy=key_policy, verify_rows_per_second=verify_rows_per_second,
            restore=restored[0] if restored else None)

    def provision_tenant(self, engine, *, proposal, deployment, keys, approval):
        """Fence writers and retain the exact tenant successor as PENDING."""
        from .tenancy import apply
        self._tenant_deployment(proposal, deployment)
        return apply(proposal, engine, keys=keys, pin=deployment[1], approval=approval)

    def abort_tenant(self, engine, *, proposal, deployment, keys, approval):
        """Cancel a pending tenant addition under republished source authority."""
        from .tenancy import abort
        self._tenant_deployment(proposal, deployment, source=True)
        return abort(proposal, engine, keys=keys, pin=deployment[1], approval=approval)

    def _online_deployment(self, deployment):
        from .migration import DeploymentPin
        from .online import OnlineProtectionPlan
        if (type(deployment) is not tuple or len(deployment) != 2
                or type(deployment[0]) is not OnlineProtectionPlan or type(deployment[1]) is not DeploymentPin):
            raise ConfigurationInvalid('Application.InvalidDeployment')
        self._intent(deployment[0])

    def _tenant_deployment(self, proposal, deployment, *, source=False):
        from .tenancy import TenantProvisionPlan
        if type(proposal) is not TenantProvisionPlan:
            raise ConfigurationInvalid('Application.InvalidTenantPlan')
        self._intent(proposal.source)
        self._deployment(deployment)
        expected = proposal.source if source else proposal.activation_plan
        if deployment[0].artifact != expected.artifact:
            raise ConfigurationInvalid('Application.InvalidDeployment')

    def plan_rewrap(self, engine, *, deployment, keys, target_keys, verify_rows_per_second):
        """Plan a custody change with unchanged roots and ciphertext."""
        from .rotation import plan_rewrap
        self._deployment(deployment, allow_restore=True)
        source, pin, *restored = deployment
        return plan_rewrap(source, engine, source_pin=pin, keys=keys, target_keys=target_keys,
            verify_rows_per_second=verify_rows_per_second, restore=restored[0] if restored else None)

    def rewrap(self, engine, *, proposal, deployment, keys, target_keys, approval):
        """Verify a rewrap and commit its exact successor as PENDING; no publication."""
        from .rotation import apply_rewrap
        self._rewrap_deployment(proposal, deployment)
        return apply_rewrap(proposal, engine, keys=keys, target_keys=target_keys,
                            pin=deployment[1], approval=approval)

    def abort_rewrap(self, engine, *, proposal, deployment, keys, approval):
        """Cancel pending custody changes under the republished source authority."""
        from .rotation import abort_rewrap
        self._rewrap_deployment(proposal, deployment, source=True)
        return abort_rewrap(proposal, engine, keys=keys, pin=deployment[1], approval=approval)

    def plan_rotation(self, engine, *, purpose, deployment, keys, target_keys,
                      backfill_rows_per_second, verify_rows_per_second,
                      temporary_bytes_per_row, wal_bytes_per_row,
                      max_batch_rows=1000, max_batch_bytes=64*1024*1024):
        """Plan an explicit payload or search generation change; no database effects."""
        from . import rotation
        if type(purpose) is not str or purpose not in ('payload', 'search'):
            raise ConfigurationInvalid('Application.InvalidRotationPurpose')
        self._deployment(deployment, allow_restore=True)
        source, pin, *restored = deployment
        operation = rotation.plan_payload_rotation if purpose == 'payload' else rotation.plan_search_rotation
        return operation(source, engine, source_pin=pin, keys=keys, target_keys=target_keys,
            backfill_rows_per_second=backfill_rows_per_second, verify_rows_per_second=verify_rows_per_second,
            temporary_bytes_per_row=temporary_bytes_per_row, wal_bytes_per_row=wal_bytes_per_row,
            max_batch_rows=max_batch_rows, max_batch_bytes=max_batch_bytes,
            restore=restored[0] if restored else None)

    def prepare_rotation(self, engine, *, deployment, keys, target_keys, approval,
                         until='BACKFILLED', max_chunks=None):
        """Stage or resume authenticated chunks without switching public data."""
        from . import rotation
        purpose = self._rotation_deployment(deployment)
        operation = rotation.apply_payload_rotation if purpose == 'payload' else rotation.apply_search_rotation
        return operation(deployment[0], engine, keys=keys, target_keys=target_keys,
            pin=deployment[1], approval=approval, until=until, max_chunks=max_chunks)

    def seal_rotation(self, engine, *, deployment, keys, target_keys, approval,
                      copy_rows_per_second, copy_wal_bytes_per_row):
        """Verify staged bytes and return the exact artifact for host retention."""
        from . import rotation
        purpose = self._rotation_deployment(deployment)
        operation = rotation.seal_payload_rotation if purpose == 'payload' else rotation.seal_search_rotation
        return operation(deployment[0], engine, keys=keys, target_keys=target_keys,
            pin=deployment[1], approval=approval, copy_rows_per_second=copy_rows_per_second,
            copy_wal_bytes_per_row=copy_wal_bytes_per_row)

    def switch_rotation(self, engine, *, proposal, deployment, keys, target_keys, approval):
        """Switch verified ciphertext under the sealed successor's PREPARED pin."""
        from . import rotation
        purpose = self._rotation_proposal(proposal)
        self._deployment(deployment)
        operation = rotation.switch_payload_rotation if purpose == 'payload' else rotation.switch_search_rotation
        return operation(proposal, deployment[0], engine, keys=keys, target_keys=target_keys,
                         pin=deployment[1], approval=approval)

    def abort_rotation(self, engine, *, proposal, deployment, keys, approval):
        """Cancel staging using source custody and the republished source pin."""
        from . import rotation
        purpose = self._rotation_proposal(proposal)
        self._deployment(deployment)
        if deployment[0].artifact != proposal.source.artifact:
            raise ConfigurationInvalid('Application.InvalidDeployment')
        operation = rotation.abort_payload_rotation if purpose == 'payload' else rotation.abort_search_rotation
        return operation(proposal, engine, keys=keys, source_pin=deployment[1], approval=approval)

    def _rewrap_deployment(self, proposal, deployment, *, source=False):
        from .rotation import RewrapPlan
        if type(proposal) is not RewrapPlan:
            raise ConfigurationInvalid('Application.InvalidRotationPlan')
        self._intent(proposal.source)
        self._deployment(deployment)
        expected = proposal.source if source else proposal.activation_plan
        if deployment[0].artifact != expected.artifact:
            raise ConfigurationInvalid('Application.InvalidDeployment')

    def _rotation_deployment(self, deployment):
        from .migration import DeploymentPin
        if (type(deployment) is not tuple or len(deployment) != 2
                or type(deployment[1]) is not DeploymentPin):
            raise ConfigurationInvalid('Application.InvalidDeployment')
        return self._rotation_proposal(deployment[0])

    def _rotation_proposal(self, proposal):
        from .rotation import PayloadRotationPlan, SearchRotationPlan
        if type(proposal) not in (PayloadRotationPlan, SearchRotationPlan):
            raise ConfigurationInvalid('Application.InvalidRotationPlan')
        self._intent(proposal.source)
        return 'payload' if type(proposal) is PayloadRotationPlan else 'search'

    def _deployment(self, deployment, *, reverse=False, allow_restore=False):
        from .migration import DeploymentPin, MigrationPlan
        from .deprotection import DeprotectionPlan
        plan_type = DeprotectionPlan if reverse else MigrationPlan
        if (type(deployment) is not tuple or len(deployment) not in ((2, 3) if allow_restore else (2,))
                or type(deployment[0]) is not plan_type or type(deployment[1]) is not DeploymentPin):
            raise ConfigurationInvalid('Application.InvalidDeployment')
        plan = deployment[0].source if reverse else deployment[0]
        self._intent(plan)

    def _intent(self, plan):
        from .manifest.compiler import _canonical, _host_evidence
        lock = plan.document['lock']
        declared = parse_protection_declaration(_canonical(lock['declaration']))
        if declared.canonical_bytes() != self.manifest:
            raise ConfigurationInvalid('Application.ManifestMismatch')
        issues = []
        writers, reviews = _host_evidence(declared, self.writers, self.search_reviews, issues)
        if issues or writers != lock['writer_inventory'] or reviews != lock['search_reviews']:
            raise ConfigurationInvalid('Application.HostEvidenceMismatch')
