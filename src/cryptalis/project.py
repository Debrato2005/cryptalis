"""The small front door: one manifest, one key provider, one state directory.

``Project`` drives the existing lifecycle executors and adds no cryptography,
SQL or transition logic of its own. It takes over the bookkeeping a host would
otherwise repeat: generating wrapped roots, retaining plans, publishing pins and
resuming after a crash. Decisions about security stay visible as required
arguments and are recorded in the plan.

``state_dir`` is the deployment authority, so keep it outside database backups.
A restored old database then cannot authorize itself. It holds only wrapped
(provider-encrypted) roots, plans and phases, never plaintext keys or values.
Every worker must read the same state; run one lifecycle operation at a time.
Hosts needing their own publication system can use ``ApplicationConfig`` directly.
"""

import base64
import json
import os
import stat
import tempfile
from pathlib import Path
from uuid import UUID, uuid4

from . import deprotection, migration, online, restore, rotation
from .application import ApplicationConfig, ConfigurationInvalid
from .crypto._rewrap import prepare_rewrap
from .crypto.keys import KeyContext, KeyPolicy, Keyring, KeyUnavailable, WrappedRoot, create_root
from .doctor import check_keys
from .manifest.compiler import SearchReview, Writer, WriterInventory
from .manifest.declaration import parse_protection_declaration
from .migration import DeploymentPin, MaintenanceApproval, MigrationPlan, TransitionFailure
from .modification import ModificationPlan
from .tenancy import TenantProvisionPlan

_FORMAT = 'cryptalis.project/v1'
# Used for the pause estimate only. Override with measured staging values.
_ESTIMATES = {'backfill_rows_per_second': 1000, 'verify_rows_per_second': 1000,
              'temporary_bytes_per_row': 4096, 'wal_bytes_per_row': 8192}
_COPY_ESTIMATES = {'copy_rows_per_second': 1000, 'copy_wal_bytes_per_row': 8192}
_KEYRINGS_PER_CHECK = 16  # The limit of doctor.check_keys.
_PROPOSALS = {'payload': rotation.PayloadRotationPlan, 'search': rotation.SearchRotationPlan,
              'wrapping': rotation.RewrapPlan, 'modify': ModificationPlan, 'tenant': TenantProvisionPlan,
              'online': online.OnlineProtectionPlan, 'decrypt': deprotection.DeprotectionPlan}


class ProjectError(ConfigurationInvalid):
    """The requested step does not fit the recorded state; ``remedy`` says what does."""

    def __init__(self, code, remedy):
        super().__init__('Project.' + code)
        self.remedy = remedy
        self.args = (f'Project.{code}: {remedy}',)


def _statement(name, value):
    if type(value) is not str or not value.strip():
        raise ProjectError('StatementRequired', f'Supply {name}: a plain statement recorded in the plan.')
    return value


def _pin(plan, phase):
    target = plan.target_id if hasattr(plan, 'target_id') else plan.source.target_id
    return DeploymentPin(target, plan.operation_id, plan.digest, phase)


def _text(plan):
    return plan.artifact.decode('utf8')


def _plan(text):
    return MigrationPlan(text.encode('utf8'))


def _proposal(pending):
    return _PROPOSALS[pending['op']](pending['proposal'].encode('utf8'))


def _declared(lock):
    return parse_protection_declaration(json.dumps(lock['declaration']).encode()).canonical_bytes()


def _recorded_writers(lock):
    return WriterInventory(True, tuple(Writer(UUID(w['table_id']), w['name'], w['route'], w['excluded'], w['evidence'])
                                       for w in lock['writer_inventory']['writers']))


def _recorded_reviews(lock):
    return tuple(SearchReview(UUID(r['field_id']), r['small_domain'], r['evidence']) for r in lock['search_reviews'])


def _entry(policy):
    return {'payload': policy.payload_generation, 'search': policy.search_generation, 'wrappers': [
        {'provider': str(w.provider_id), 'purpose': w.context.purpose, 'root': str(w.context.root_id),
         'generation': w.context.generation, 'sealed': base64.b64encode(w.sealed).decode('ascii')}
        for w in policy.wrappers]}


class Project:
    """Protect, attach, rotate, recover and remove from one manifest.

    ``manifest`` is a path or bytes. ``provider`` is any external ``KeyProvider``.
    Repeat a lifecycle call that failed to resume it. Calling ``rotate`` again after
    it finished starts a new rotation; other calls report the finished result.
    """

    def __init__(self, manifest, mapping, *, provider, state_dir, writers=None, queries=(), estimates=None):
        raw = manifest if type(manifest) is bytes else Path(manifest).read_bytes()
        self._declaration = parse_protection_declaration(raw)
        self._manifest = self._declaration.canonical_bytes()
        self._mapping = mapping
        self._provider = provider
        self._providers = {provider.provider_id: provider}
        self._state_dir = Path(state_dir)
        self._writers = writers
        self._queries = queries
        self._estimates = {**_ESTIMATES, **(estimates or {})}
        self._copy = {name: self._estimates.pop(name, default) for name, default in _COPY_ESTIMATES.items()}
        self._rings = {}

    # State ---------------------------------------------------------------

    def _check_private(self, path):
        info = path.lstat()
        if (stat.S_ISLNK(info.st_mode) or info.st_uid not in (os.geteuid(), 0)
                or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise ProjectError('StateNotPrivate', f'Make {path} a regular path you own, without group or world write.')

    def _load(self):
        path = self._state_dir / 'state.json'
        if not path.exists():
            return {'format': _FORMAT, 'keys': {}, 'plan': None, 'phase': None, 'restore': None,
                    'pending': None, 'decrypted': None, 'removed': False}
        self._check_private(path)
        document = json.loads(path.read_bytes())
        if document.get('format') != _FORMAT:
            raise ProjectError('StateUnreadable', f'Restore a {_FORMAT} state file to {path}.')
        return document

    def _save(self, document):
        self._state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._check_private(self._state_dir)
        descriptor, temporary = tempfile.mkstemp(dir=self._state_dir, prefix='.state-')
        try:
            with os.fdopen(descriptor, 'wb') as output:
                output.write(json.dumps(document, sort_keys=True).encode('utf8'))
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self._state_dir / 'state.json')
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        directory = os.open(self._state_dir, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _begin(self, document, op, proposal, **details):
        document['pending'] = {'op': op, 'proposal': _text(proposal), 'phase': 'PREPARED', **details}
        self._save(document)
        return document['pending']

    def _switch_once(self, document, pending, switch, next_phase='ACTIVATING'):
        """Run the database switch once; the phase records that it finished."""
        if pending['phase'] == 'PREPARED':
            switch()
            pending['phase'] = next_phase
            self._save(document)

    def _activate(self, owner, document, config, successor, table, approval):
        progress = config.apply(owner, deployment=(successor, _pin(successor, 'ACTIVATING')),
                                keys=self._keys(table), approval=approval, until='ACTIVE')
        document.update(plan=_text(successor), phase='ACTIVE', keys=table, pending=None, restore=None)
        self._save(document)
        return progress

    def _staged(self, owner, document, pending, config, *, prepare, seal, switch, table, approval):
        """Stage new frames, retain the sealed successor, switch, then activate."""
        if pending['successor'] is None:
            prepare()
            pending['successor'] = _text(seal())
            self._save(document)
        successor = _plan(pending['successor'])
        self._switch_once(document, pending, lambda: switch(successor))
        return self._activate(owner, document, config, successor, table, approval)

    # Keys ----------------------------------------------------------------

    def _new_root(self, tenant, purpose, generation):
        context = KeyContext(self._declaration.domain_id, tenant, purpose, uuid4(), generation)
        wrapper = create_root(self._provider, context)
        return {'provider': str(wrapper.provider_id), 'purpose': purpose, 'root': str(context.root_id),
                'generation': generation, 'sealed': base64.b64encode(wrapper.sealed).decode('ascii')}

    def _new_keys(self, tenant):
        # Search roots are created up front so search can be enabled later.
        return {'payload': 1, 'search': 1,
                'wrappers': [self._new_root(tenant, purpose, 1) for purpose in ('payload', 'search')]}

    def _next_generation(self, tenant, entry, purpose):
        generation = entry[purpose] + 1
        return {**entry, purpose: generation,
                'wrappers': entry['wrappers'] + [self._new_root(tenant, purpose, generation)]}

    def _ring(self, tenant, entry):
        cache_key = json.dumps([str(tenant), entry], sort_keys=True)
        ring = self._rings.get(cache_key)
        if ring is None:
            wrappers = tuple(WrappedRoot(UUID(w['provider']), KeyContext(
                self._declaration.domain_id, tenant, w['purpose'], UUID(w['root']), w['generation']),
                base64.b64decode(w['sealed'])) for w in entry['wrappers'])
            policy = KeyPolicy(self._declaration.domain_id, tenant, wrappers, entry['payload'], entry['search'])
            ring = self._rings[cache_key] = Keyring(policy, self._providers)
        return ring

    def _keys(self, table):
        def resolve(tenant):
            entry = table.get(str(tenant))
            if entry is None:
                raise KeyUnavailable()
            return self._ring(tenant, entry)
        return resolve

    def _keys_creating(self, document):
        """Create and durably retain roots for tenants found while planning."""
        def resolve(tenant):
            if str(tenant) not in document['keys']:
                document['keys'][str(tenant)] = self._new_keys(tenant)
                self._save(document)
            return self._ring(tenant, document['keys'][str(tenant)])
        return resolve

    # Configuration -------------------------------------------------------

    def _new_config(self, writers_stopped, search_reviewed, *, prior_lock=None):
        """Configuration for new intent, reusing evidence already recorded."""
        known = {} if prior_lock is None else {review.field_id: review for review in _recorded_reviews(prior_lock)}
        reviews = tuple(known.get(f.field_id) or SearchReview(f.field_id, False, _statement('search_reviewed', search_reviewed))
                        for model in self._declaration.models for f in model.fields if f.queries)
        if prior_lock is not None:
            writers = _recorded_writers(prior_lock)
        else:
            writers = self._writers or WriterInventory(True, tuple(
                Writer(model.table_id, 'application', 'sqlalchemy', evidence=_statement('writers_stopped', writers_stopped))
                for model in self._declaration.models))
        return ApplicationConfig(self._manifest, self._mapping, writers, reviews, self._queries)

    def _recorded_config(self, plan):
        """Rebuild configuration from the evidence a plan already recorded."""
        document = plan.document
        lock = (document['target_lock'] if 'target_lock' in document
                else plan.source.document['lock'] if hasattr(plan, 'source') else document['lock'])
        if _declared(lock) != self._manifest:
            raise ProjectError('ManifestChanged', 'Run modify() to apply the changed manifest, or restore the deployed one.')
        return ApplicationConfig(self._manifest, self._mapping, _recorded_writers(lock), _recorded_reviews(lock), self._queries)

    def _source(self, document):
        """Return the recorded ACTIVE deployment, refusing every other state."""
        if document['removed'] or document['decrypted']:
            raise ProjectError('Decrypted', 'Cryptalis no longer protects this data. Use your native session factory.')
        if document['plan'] is None or document['phase'] != 'ACTIVE':
            raise ProjectError('NotProtected', 'Run protect() to completion first.')
        plan = _plan(document['plan'])
        deployment = (plan, _pin(plan, 'ACTIVE'))
        if document['restore'] is not None:
            deployment += (restore.RestoreBinding(document['restore'].encode('utf8')),)
        return deployment

    @staticmethod
    def _claim(document, operation):
        """Allow only the unfinished operation, if any, to continue."""
        pending = document['pending']
        if pending is not None and pending['op'] != operation:
            raise ProjectError('OperationInProgress', f"Finish or abort() the unfinished {pending['op']} operation first.")
        return pending

    @staticmethod
    def _approval(writers_stopped, max_pause_seconds):
        return MaintenanceApproval(_statement('writers_stopped', writers_stopped), max_pause_seconds)

    # Application ---------------------------------------------------------

    def attach(self, engine, *, adapter='sqlalchemy'):
        """Return the session factory. Await the result for an AsyncEngine."""
        document = self._load()
        deployment = self._source(document)
        self._claim(document, None)
        return self._recorded_config(deployment[0]).attach(
            engine, keys=self._keys(document['keys']), deployment=deployment, adapter=adapter)

    def doctor(self, engine):
        """Read-only diagnosis. Pass the runtime engine once protected.

        Before protection this checks schema and query samples without keys.
        Afterwards it checks attachment metadata and cold provider access.
        Unobserved boundaries stay UNKNOWN.
        """
        document = self._load()
        if document['plan'] is None:
            placeholder = 'Doctor inspection; no operator statement made yet.'
            return self._new_config(placeholder, placeholder).diagnose(engine)
        plan, pin, *restored = self._source(document)
        migration.diagnose_deployment(plan, engine, pin=pin, restore=restored[0] if restored else None)
        rings = [self._ring(UUID(tenant), entry) for tenant, entry in sorted(document['keys'].items())]
        reports = [check_keys(tuple(rings[start:start + _KEYRINGS_PER_CHECK]))
                   for start in range(0, len(rings), _KEYRINGS_PER_CHECK)]
        failed = any(report['status'] == 'FAIL' for report in reports)
        return {'status': 'FAIL' if failed else 'UNKNOWN', 'deployment': 'PASS', 'keys': reports}

    def status(self, owner):
        """Observe recorded progress. Returns None before protection starts."""
        document = self._load()
        if document['pending'] is not None:
            return self._pending_status(owner, document, document['pending'])
        if document['decrypted']:
            reverse = deprotection.DeprotectionPlan(document['decrypted']['proposal'].encode('utf8'))
            phase = 'REMOVED' if document['removed'] else 'PLAINTEXT_ACTIVE'
            return self._recorded_config(reverse).status(owner, deployment=(reverse, _pin(reverse, phase)))
        if document['plan'] is None:
            return None
        plan = _plan(document['plan'])
        phase = 'PREPARED' if document['phase'] == 'ACTIVATING' else document['phase']
        deployment = self._source(document) if phase == 'ACTIVE' else (plan, _pin(plan, phase))
        return self._recorded_config(plan).status(owner, deployment=deployment)

    def _pending_status(self, owner, document, pending):
        proposal = _proposal(pending)
        if pending['op'] in ('wrapping', 'tenant'):
            # These have no staging of their own; report the source until they start.
            successor = proposal.activation_plan
            try:
                return self._recorded_config(successor).status(owner, deployment=(successor, _pin(successor, 'PREPARED')))
            except TransitionFailure as failure:
                if failure.code != 'journal_identity_mismatch':
                    raise
                return self._recorded_config(proposal).status(owner, deployment=self._source(document))
        plan = _plan(pending['successor']) if pending['phase'] == 'ACTIVATING' else proposal
        return self._recorded_config(plan).status(owner, deployment=(plan, _pin(plan, 'PREPARED')))

    # Protection ----------------------------------------------------------

    def protect(self, owner, *, runtime_role, writers_stopped, search_reviewed=None,
                max_pause_seconds=3600, chunk_size=1000):
        """Protect existing rows with writers stopped. Repeat the call to resume.

        ``writers_stopped`` states that every writer is stopped and the attached
        application will be the only writer. ``search_reviewed`` states that each
        searchable field's values are not enumerable; it is required only when the
        manifest declares search. Both statements are recorded in the plan.
        """
        document = self._load()
        self._claim(document, None)
        approval = self._approval(writers_stopped, max_pause_seconds)
        if document['plan'] is None:
            plan = self._new_config(writers_stopped, search_reviewed).plan(
                owner, keys=self._keys_creating(document), runtime_role=runtime_role, target_id=uuid4(), **self._estimates)
            document.update(plan=_text(plan), phase='PREPARED')
            self._save(document)
        plan = _plan(document['plan'])
        config = self._recorded_config(plan)
        keys = self._keys(document['keys'])
        if document['phase'] == 'ACTIVE':
            return config.status(owner, deployment=self._source(document))
        if document['phase'] == 'PREPARED':
            config.apply(owner, deployment=(plan, _pin(plan, 'PREPARED')), keys=keys, approval=approval, chunk_size=chunk_size)
            document['phase'] = 'ACTIVATING'
            self._save(document)
        progress = config.apply(owner, deployment=(plan, _pin(plan, 'ACTIVATING')), keys=keys, approval=approval,
                                chunk_size=chunk_size, until='ACTIVE')
        document['phase'] = 'ACTIVE'
        self._save(document)
        return progress

    def protect_online(self, owner, *, runtime_role, source_role, writers_excluded, accept_plaintext_capture,
                       search_reviewed=None, native_tenants=None, max_pause_seconds=3600):
        """Protect existing rows while the native application keeps writing.

        Rows are copied under capture, then writes pause at the final fence until
        you start the attached application. ``source_role`` is the running native
        application's role. ``writers_excluded`` states that owner, DDL and other
        writers stay out. Plaintext remains in place until the final switch, which
        ``accept_plaintext_capture`` must acknowledge. Repeat the call to resume.
        """
        document = self._load()
        pending = self._claim(document, 'online')
        if accept_plaintext_capture is not True:
            raise ProjectError('PlaintextCaptureNotAccepted', 'Pass accept_plaintext_capture=True to continue.')
        if pending is None:
            if document['plan'] is not None:
                return self.protect(owner, runtime_role=runtime_role, writers_stopped=writers_excluded,
                                    search_reviewed=search_reviewed, max_pause_seconds=max_pause_seconds)
            capture = self._new_config(writers_excluded, search_reviewed).plan_online(
                owner, keys=self._keys_creating(document), source_role=source_role, runtime_role=runtime_role,
                target_id=uuid4(), native_tenants=native_tenants, **self._estimates)
            pending = self._begin(document, 'online', capture, successor=None)
        capture = _proposal(pending)
        config = self._recorded_config(capture)
        inputs = dict(keys=self._keys(document['keys']),
                      approval=online.OnlineApproval(_statement('writers_excluded', writers_excluded), True, max_pause_seconds))
        staged = (capture, _pin(capture, 'PREPARED'))
        def prepare():
            config.capture_online(owner, deployment=staged, max_chunks=100000, fence=True, **inputs)
            # Rows written just before the fence drain here; writers are now refused.
            config.capture_online(owner, deployment=staged, max_chunks=100000, **inputs)
        return self._staged(owner, document, pending, config, prepare=prepare,
            seal=lambda: config.seal_online(owner, deployment=staged, **inputs),
            switch=lambda successor: config.switch_online(owner, deployment=staged, successor=successor, **inputs),
            table=document['keys'], approval=self._approval(writers_excluded, max_pause_seconds))

    # Changes -------------------------------------------------------------

    def rotate(self, owner, purpose, *, writers_stopped, provider=None, max_pause_seconds=3600):
        """Run one rotation with writers stopped. Repeat a failed call to resume.

        ``payload`` re-encrypts values under a new key. ``search`` rebuilds search
        terms under a new key. Both keep earlier generations in state for retained
        backups. ``wrapping`` moves every root to ``provider``, leaving stored bytes
        unchanged. Afterwards construct ``Project`` with the new provider.
        """
        if purpose == 'wrapping':
            return self._rewrap(owner, provider, writers_stopped, max_pause_seconds)
        if purpose not in ('payload', 'search'):
            raise ProjectError('InvalidRotation', "Use 'payload', 'search' or 'wrapping'.")
        document = self._load()
        deployment = self._source(document)
        pending = self._claim(document, purpose)
        config = self._recorded_config(deployment[0])
        approval = self._approval(writers_stopped, max_pause_seconds)
        source = self._keys(document['keys'])
        if pending is None:
            table = {tenant: self._next_generation(UUID(tenant), entry, purpose)
                     for tenant, entry in document['keys'].items()}
            proposal = config.plan_rotation(owner, purpose=purpose, deployment=deployment, keys=source,
                                            target_keys=self._keys(table), **self._estimates)
            pending = self._begin(document, purpose, proposal, keys=table, successor=None)
        proposal = _proposal(pending)
        inputs = dict(keys=source, target_keys=self._keys(pending['keys']), approval=approval)
        staged = (proposal, _pin(proposal, 'PREPARED'))
        return self._staged(owner, document, pending, config,
            prepare=lambda: config.prepare_rotation(owner, deployment=staged, **inputs),
            seal=lambda: config.seal_rotation(owner, deployment=staged, **inputs, **self._copy),
            switch=lambda successor: config.switch_rotation(owner, proposal=proposal,
                deployment=(successor, _pin(successor, 'PREPARED')), **inputs),
            table=pending['keys'], approval=approval)

    def _rewrap(self, owner, provider, writers_stopped, max_pause_seconds):
        if provider is None:
            raise ProjectError('ProviderRequired', 'Pass provider=<the new KeyProvider> for a wrapping rotation.')
        self._providers[provider.provider_id] = provider
        document = self._load()
        deployment = self._source(document)
        pending = self._claim(document, 'wrapping')
        config = self._recorded_config(deployment[0])
        approval = self._approval(writers_stopped, max_pause_seconds)
        source = self._keys(document['keys'])
        if pending is None:
            table = {tenant: _entry(prepare_rewrap(source(UUID(tenant)), provider)) for tenant in document['keys']}
            proposal = config.plan_rewrap(owner, deployment=deployment, keys=source, target_keys=self._keys(table),
                                          verify_rows_per_second=self._estimates['verify_rows_per_second'])
            pending = self._begin(document, 'wrapping', proposal, keys=table)
        proposal = _proposal(pending)
        successor = proposal.activation_plan
        self._switch_once(document, pending, lambda: config.rewrap(
            owner, proposal=proposal, deployment=(successor, _pin(successor, 'PREPARED')),
            keys=source, target_keys=self._keys(pending['keys']), approval=approval))
        progress = self._activate(owner, document, config, successor, pending['keys'], approval)
        self._provider = provider
        return progress

    def modify(self, owner, *, writers_stopped, search_reviewed=None, max_pause_seconds=3600):
        """Apply a changed manifest's search settings. Repeat the call to resume.

        ``search_reviewed`` is required when the change enables search on a field.
        """
        document = self._load()
        pending = self._claim(document, 'modify')
        approval = self._approval(writers_stopped, max_pause_seconds)
        keys = self._keys(document['keys'])
        if pending is None:
            deployment = self._source(document)
            lock = deployment[0].document['lock']
            if _declared(lock) == self._manifest:
                return self._recorded_config(deployment[0]).status(owner, deployment=deployment)
            proposal = self._new_config(writers_stopped, search_reviewed, prior_lock=lock).plan_modification(
                owner, deployment=deployment[:2], keys=keys, **self._estimates)
            pending = self._begin(document, 'modify', proposal, successor=None)
        proposal = _proposal(pending)
        config = self._recorded_config(proposal)
        inputs = dict(keys=keys, approval=approval)
        staged = (proposal, _pin(proposal, 'PREPARED'))
        return self._staged(owner, document, pending, config,
            prepare=lambda: config.prepare_modification(owner, deployment=staged, **inputs),
            seal=lambda: config.seal_modification(owner, deployment=staged, **inputs, **self._copy),
            switch=lambda successor: config.switch_modification(owner, proposal=proposal,
                deployment=(successor, _pin(successor, 'PREPARED')), **inputs),
            table=document['keys'], approval=approval)

    def add_tenant(self, owner, tenant_id, *, writers_stopped, max_pause_seconds=3600):
        """Add one empty tenant, with writers stopped. Restart workers afterwards."""
        document = self._load()
        deployment = self._source(document)
        pending = self._claim(document, 'tenant')
        config = self._recorded_config(deployment[0])
        if pending is None and str(tenant_id) in document['keys']:
            return config.status(owner, deployment=deployment)
        approval = self._approval(writers_stopped, max_pause_seconds)
        if pending is None:
            entry = self._new_keys(tenant_id)
            proposal = config.plan_tenant(owner, deployment=deployment, keys=self._keys(document['keys']),
                                          tenant_id=tenant_id, key_policy=self._ring(tenant_id, entry),
                                          verify_rows_per_second=self._estimates['verify_rows_per_second'])
            pending = self._begin(document, 'tenant', proposal, keys={**document['keys'], str(tenant_id): entry})
        proposal = _proposal(pending)
        successor = proposal.activation_plan
        self._switch_once(document, pending, lambda: config.provision_tenant(
            owner, proposal=proposal, deployment=(successor, _pin(successor, 'PREPARED')),
            keys=self._keys(pending['keys']), approval=approval))
        return self._activate(owner, document, config, successor, pending['keys'], approval)

    # Recovery and exit ---------------------------------------------------

    def recover(self, owner, *, host, quarantine, source_fenced):
        """Adopt a database restored from backup. Only the restored target qualifies.

        ``quarantine`` states how the copy is isolated until adoption finishes.
        ``source_fenced`` confirms the original deployment can no longer write.
        Use the state directory copy from the time of that backup.
        """
        document = self._load()
        self._claim(document, None)
        plan, pin, *_ = self._source(document)
        binding = restore.plan(plan, owner, pin=pin, keys=self._keys(document['keys']),
                               approval=restore.RestoreApproval(host, 'adopt restored copy', quarantine, source_fenced))
        document['restore'] = binding.artifact.decode('utf8')
        self._save(document)
        return binding

    def decrypt(self, owner, *, plaintext_role, writers_stopped, accept_plaintext, retained_backups,
                max_pause_seconds=3600, chunk_size=1000):
        """Restore current values to plaintext columns. Repeat the call to resume.

        ``accept_plaintext`` must be True: values become plaintext at rest, in WAL
        and in later backups. ``retained_backups`` states how existing encrypted
        backups stay recoverable. Start your native application next, then call
        ``remove``. Keys and wrappers stay in state; nothing is destroyed.
        """
        document = self._load()
        pending = self._claim(document, 'decrypt')
        if accept_plaintext is not True:
            raise ProjectError('PlaintextNotAccepted', 'Pass accept_plaintext=True to store values as plaintext.')
        if document['decrypted']:
            return self.status(owner)
        approval = self._approval(writers_stopped, max_pause_seconds)
        keys = self._keys(document['keys'])
        if pending is None:
            deployment = self._source(document)
            proposal = self._recorded_config(deployment[0]).plan_deprotection(
                owner, deployment=deployment, keys=keys, plaintext_runtime_role=plaintext_role, **self._estimates)
            pending = self._begin(document, 'decrypt', proposal)
        reverse = _proposal(pending)
        config = self._recorded_config(reverse)
        inputs = dict(keys=keys, approval=approval, chunk_size=chunk_size, consent=deprotection.PlaintextApproval(
            reverse.target_id, reverse.operation_id, reverse.digest, True, _statement('retained_backups', retained_backups)))
        self._switch_once(document, pending, lambda: config.decrypt_back(
            owner, deployment=(reverse, _pin(reverse, 'PREPARED')), **inputs), 'PLAINTEXT_ACTIVATING')
        progress = config.decrypt_back(owner, deployment=(reverse, _pin(reverse, 'PLAINTEXT_ACTIVATING')),
                                       until='PLAINTEXT_ACTIVE', **inputs)
        document.update(pending=None, decrypted={'proposal': _text(reverse), 'retained_backups': retained_backups})
        self._save(document)
        return progress

    def remove(self, owner, *, writers_stopped, application_verified, old_workers_stopped, max_pause_seconds=3600):
        """Drop generated database objects after decrypt. Uninstall the package last.

        ``application_verified`` states how the native application was checked.
        This destroys no keys and leaves state in place for retained backups.
        """
        document = self._load()
        if not document['decrypted']:
            raise ProjectError('NotDecrypted', 'Run decrypt() to completion first.')
        reverse = deprotection.DeprotectionPlan(document['decrypted']['proposal'].encode('utf8'))
        retained = document['decrypted']['retained_backups']
        identity = (reverse.target_id, reverse.operation_id, reverse.digest)
        def run(phase):
            return self._recorded_config(reverse).remove(
                owner, deployment=(reverse, _pin(reverse, phase)),
                approval=self._approval(writers_stopped, max_pause_seconds),
                consent=deprotection.PlaintextApproval(*identity, True, retained),
                removal=deprotection.RemovalApproval(*identity, _statement('application_verified', application_verified),
                                                     retained, old_workers_stopped))
        if document['removed']:
            return run('REMOVED')
        try:
            progress = run('REMOVING')
        except TransitionFailure as failure:
            if failure.code != 'restored_or_missing_reverse_transition':
                raise
            progress = run('REMOVED')  # An earlier run removed it before recording that.
        document['removed'] = True
        self._save(document)
        return progress

    def abort(self, owner, *, writers_stopped, max_pause_seconds=3600):
        """Cancel an unfinished operation. A completed switch refuses; resume it instead."""
        document = self._load()
        pending = document['pending']
        approval = self._approval(writers_stopped, max_pause_seconds)
        keys = self._keys(document['keys'])
        if pending is None:
            if document['phase'] not in ('PREPARED', 'ACTIVATING'):
                raise ProjectError('NothingToAbort', 'No unfinished operation is recorded.')
            plan = _plan(document['plan'])
            migration.abort(plan, owner, pin=_pin(plan, document['phase']), approval=approval)
            document.update(plan=None, phase=None)
            self._save(document)
            return None
        proposal = _proposal(pending)
        config = self._recorded_config(proposal)
        result = None
        if pending['op'] == 'online':
            result = config.abort_online(owner, deployment=(proposal, _pin(proposal, 'PREPARED')),
                approval=online.OnlineApproval(writers_stopped, True, max_pause_seconds))
        elif pending['op'] == 'decrypt':
            result = deprotection.abort(proposal, owner, pin=_pin(proposal, 'PREPARED'), approval=approval,
                consent=deprotection.PlaintextApproval(proposal.target_id, proposal.operation_id, proposal.digest,
                                                       True, 'Aborted before plaintext activation.'))
        else:
            method = {'payload': config.abort_rotation, 'search': config.abort_rotation, 'wrapping': config.abort_rewrap,
                      'modify': config.abort_modification, 'tenant': config.abort_tenant}[pending['op']]
            try:
                result = method(owner, proposal=proposal, deployment=self._source(document)[:2], keys=keys, approval=approval)
            except TransitionFailure as failure:
                # A rewrap or tenant addition that never reached the database has nothing to cancel.
                if pending['op'] not in ('wrapping', 'tenant') or failure.code != 'journal_identity_mismatch':
                    raise
        document['pending'] = None
        self._save(document)
        return result
