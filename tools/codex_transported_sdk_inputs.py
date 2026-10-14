"""Complete packed SDK/JDK -> fresh physical custody, never original inodes.

Only the current content-source family selects this owner. Historical original
SDK provenance stays in the authenticated carrier; every fresh member receives
full byte/NAR and named/held identity proof under the original invocation clock.
"""
from contextlib import ExitStack
import os
from pathlib import Path
import sys
import stat
import threading
from types import MappingProxyType

import codex_original_sdk_inputs as original
import codex_native_file_writer_model_source as family

core = original.carrier
KIND = 'omux-fresh-transported-sdk-content-v1'


class HeldTransportedSDK:
    def __init__(self, carrier_root, carrier_pin, entry_ns, outer_until_ns, context,
                 temporary, aliases, declaration, alias_owner):
        actual = original.validate_context(context)
        core.need(type(entry_ns) is int and type(outer_until_ns) is int
            and int(actual['ENTRY_NS']) == entry_ns and int(actual['DEADLINE_NS']) == outer_until_ns
            and outer_until_ns-entry_ns == 1200*10**9, 'transported-original-envelope')
        self.until_ns = entry_ns+600*10**9
        self.clock = core.Clock(self.until_ns/10**9)
        self.clock.until_ns = self.until_ns
        self.context = core.encoded(actual)
        self.carrier_root, self.carrier_pin = core.absolute(carrier_root), core.digest(carrier_pin)
        self.temporary = core.absolute(temporary)
        core.need(type(alias_owner) is family.HeldControls and family.source.DEADLINE == self.clock.deadline
            and type(aliases) is tuple and len(aliases) == 5, 'transported-declared-owner')
        self.alias_owner = alias_owner
        self.aliases = tuple(aliases)
        core.need(tuple(physical for alias, physical in self.aliases[:4]) == tuple(
            self.carrier_root/name for name in core.FILES)
            and all(alias.name == physical.name for alias, physical in self.aliases), 'transported-four-alias-roles')
        self.declaration = core.encoded(declaration)
        core.need(type(declaration) is dict and set(declaration) == {'selection', 'selection_path', 'selection_sha256'}
            and declaration['selection_path'] == str(self.aliases[-1][1])
            and set(declaration['selection']) == {'carrier_root', 'digests'}
            and declaration['selection']['carrier_root'] == str(self.carrier_root)
            and set(declaration['selection']['digests']) == set(core.FILES)
            and declaration['selection']['digests']['receipt.json'] == self.carrier_pin,
            'transported-declaration-roles')
        core.digest(declaration['selection_sha256'])
        for pin in declaration['selection']['digests'].values(): core.digest(pin)
        self.alias_records = tuple(row for row in alias_owner.aliases if
            any(row[0] == alias and row[1] == physical for alias, physical in self.aliases))
        core.need(len(self.alias_records) == 5 and all(sum(row[0] == alias and row[1] == physical
            for row in self.alias_records) == 1 for alias, physical in self.aliases), 'transported-held-alias-closure')
        self.stack, self.roots = ExitStack(), {}
        self.active = self.entered = self.finished = False
        self.pid, self.thread, self.self = os.getpid(), threading.get_ident(), self
        self.extracted = self.temporary/'extracted'
        self.sdk_root = self.extracted/'sdk'

    def check(self):
        core.need(self.self is self and self.active and os.getpid() == self.pid
            and threading.get_ident() == self.thread and self.clock.until_ns == self.until_ns
            and self.clock.deadline == self.until_ns/10**9, 'transported-owner-clock')
        self.clock.tick()
        actual = {name: os.environ.get('OMUX_NATIVE_FILE_WRITER_MODELS_'+name) for name in original.CONTEXT_FIELDS}
        core.need(core.encoded(original.validate_context(actual)) == self.context, 'transported-current-envelope')
        core.need(all(row in self.alias_owner.aliases for row in self.alias_records), 'transported-same-alias-owner')
        self.alias_owner.fence()
        self.transport.join(self.carrier_root, self.carrier_pin, self.clock.deadline)
        self.scratch.check()
        if self.roots: self._output_fence()
        for role, root in self.roots.items():
            core.need(root.path == self.extracted/role and root.clock is self.clock, 'transported-same-fresh-root')
            root.check()

    def _output_fence(self):
        # These three anchors are outside the SDK/JDK member namespace. Join
        # their actual original FULL-nine after every long domain sweep too.
        self.clock.tick()
        self.output.check(); self.scratch.check()
        core.need(core.identity(os.fstat(self.output.fd)) == self.output_anchor == core.identity(
                os.stat('extracted',dir_fd=self.scratch.fd,follow_symlinks=False))
            and core.identity(os.fstat(self.scratch.fd)) == self.scratch_anchor == core.identity(
                os.stat(self.temporary.name,dir_fd=self.scratch.chain[-2][1],follow_symlinks=False))
            and core.identity(os.fstat(self.receipt_fd)) == self.receipt_anchor == core.identity(
                os.stat('extraction-receipt.json',dir_fd=self.output.fd,follow_symlinks=False)),
            'transported-output-receipt-current-full-witness')
        self.clock.tick()

    def _budget_phase(self, stage):
        observer = getattr(self.alias_owner, '_source_phase_observer', None)
        if observer is None: return
        import codex_native_siwc_source as controller
        core.need(type(observer) is controller._SourcePhaseObserver
            and observer.owner is self.alias_owner and observer.entry+600*10**9 == self.until_ns
            and observer.cutoff == self.clock.deadline
            and observer.until == int(core.decode(self.context)['DEADLINE_NS'])
            and observer.entry == int(core.decode(self.context)['ENTRY_NS']),
            'transported-phase-observer-owner-envelope')
        observer.emit(stage)

    def __enter__(self):
        core.need(not self.entered and self.self is self, 'transported-reentry')
        self.entered = self.active = True
        try:
            self._budget_phase('transported-entry')
            self.alias_owner.fence()
            core.need(not self.temporary.exists(), 'transported-exclusive-scratch')
            # The caller supplies a fixed child of its declared TEST_TMPDIR;
            # mkdir remains exclusive. The retained Root owns current ancestry.
            self.temporary.mkdir(mode=0o700)
            self.scratch = self.stack.enter_context(core.Root(self.temporary, self.clock, sealed=False, owned=True))
            transport = core.HeldCarrier(self.carrier_root, self.carrier_pin, self.clock.deadline)
            transport._clock.until_ns = transport._until_ns = self.until_ns
            self.transport = self.stack.enter_context(transport)
            self._budget_phase('held-leaves-open')
            report, proof, rows, unused = self.transport._binding()
            self._budget_phase('initial-binding-complete')
            core.need(report['origin']['root'] == str(original.ORIGIN)
                and report['origin']['receipt_sha256'] == original.ORIGIN_PIN, 'transported-independent-origin')
            self.expected = MappingProxyType({key: MappingProxyType(dict(row)) for key,row in rows.items()})
            self.nars = core.encoded(proof['nars'])
            self.provenance = core.encoded(report)
            published = core.publication_report(self.carrier_root, self.carrier_pin, self.clock.deadline,
                                               _held_carrier=self.transport)
            declared = core.decode(self.declaration)['selection']['digests']
            core.need({row['name']: row['sha256'] for row in published['files']} == declared,
                      'transported-declared-digests')
            self._budget_phase('declaration-joined')
            self._budget_phase('extraction-dispatch')
            self.extraction = core.encoded(core.extract_action_scratch(self.carrier_root, self.carrier_pin, self.extracted,
                self.clock.deadline, _held_carrier=self.transport, consumer_context=core.decode(self.context)))
            self.extraction_pin = core.sha(self.extraction)
            self.output = self.stack.enter_context(core.Root(self.extracted,self.clock))
            self.output_anchor = core.identity(os.fstat(self.output.fd))
            self.scratch_anchor = core.identity(os.fstat(self.scratch.fd))
            self.receipt_fd = os.open('extraction-receipt.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,
                                      dir_fd=self.output.fd)
            self.stack.callback(os.close,self.receipt_fd)
            self.receipt_anchor = core.identity(os.fstat(self.receipt_fd))
            core.need(stat.S_ISREG(self.receipt_anchor[4]) and self.receipt_anchor[2] == os.getuid()
                and self.receipt_anchor[5] == 1 and stat.S_IMODE(self.receipt_anchor[4]) == 0o444,
                'transported-fresh-receipt-custody')
            core.need(core.identity(os.stat('extraction-receipt.json',dir_fd=self.output.fd,follow_symlinks=False))
                == self.receipt_anchor and core.read(self.output,'extraction-receipt.json',65536,self.extraction_pin)
                == self.extraction, 'transported-held-extraction-receipt')
            self.roots = {role: self.stack.enter_context(core.Root(self.extracted/role, self.clock))
                          for role in ('sdk','jdk')}
            observed, witnesses, nars = core._scan_nar(self.roots, self.expected, self.clock)
            core.need(observed == self.expected and core.encoded(nars) == self.nars,
                      'transported-initial-full-content-nar')
            self.witnesses = MappingProxyType({key: tuple(value) for key,value in witnesses.items()})
            self.raw_original = self.read_regular('sdk','receipt.json',core.MAX_METADATA)
            core.need(core.sha(self.raw_original) == original.ORIGIN_PIN, 'transported-original-recipe-pin')
            recipe = core.decode(self.raw_original)
            reconstructed = core.expected_entries(recipe, self.raw_original, self.clock,
                self.expected[('sdk','receipt.json')]['mode'],
                {name:self.expected[('sdk','graph/'+name)]['mode'] for name in core.sdk.GRAPH})
            core.need(set(reconstructed) == set(self.expected) and all(all(
                self.expected[key].get(field) == value for field,value in row.items())
                for key,row in reconstructed.items()), 'transported-complete-original-reconstruction')
            self.original_mapping = core.encoded(original._semantic_export(self,recipe))
            self.fresh_mapping = core.encoded(self._mapping(recipe))
            self.fence()
            return self
        except BaseException as error:
            self.active = False
            try: self.stack.__exit__(*sys.exc_info())
            except BaseException as cleanup:
                prior = BaseException.__cause__.__get__(error)
                raise error from (cleanup if prior is None else prior)
            raise

    def _mapping(self, recipe):
        # Semantic reads above came only through the exact fresh member reader.
        # Build a new mapping from the closed original recipe, never substitute
        # arbitrary strings in an externally supplied mapping document.
        old = core.decode(self.original_mapping)
        names = [row['canonical_name'] for row in recipe['repositories']]
        core.need(len(names) == len(set(names)) and set(names) == set(old['repositories']),
                  'transported-exact-repository-closure')
        repositories = {}
        for name in names:
            core.need(core.relative(name) == [name]
                and old['repositories'][name] == str(original.ORIGIN/'repositories'/name),
                'transported-original-repository-binding')
            repositories[name] = str(self.sdk_root/'repositories'/name)
        modules = {module:repositories[row['canonical_name']] for module,row in recipe['modules'].items()}
        core.need(set(modules) == set(old['module_overrides']) and all(
            old['module_overrides'][module] == str(original.ORIGIN/'repositories'/recipe['modules'][module]['canonical_name'])
            for module in modules) and old['registry_cache'] == str(original.ORIGIN/'registry-cache'),
            'transported-original-module-registry-binding')
        return {'repositories':repositories, 'module_overrides':modules,
            'inventory_sha256':old['inventory_sha256'], 'mapping_sha256':old['mapping_sha256'],
            'graph_files':old['graph_files'], 'registry_cache':str(self.sdk_root/'registry-cache'),
            'registry_inventory_sha256':old['registry_inventory_sha256']}

    def read_regular(self, role, path, limit):
        self.check()
        core.need(role in self.roots and (role,path) in self.expected
            and self.expected[(role,path)]['kind'] == 'file' and type(limit) is int
            and 0 < limit <= core.MAX_METADATA and self.expected[(role,path)]['size'] <= limit,
            'transported-selected-read')
        row = self.expected[(role,path)]
        raw = core.read(self.roots[role],path,limit,row['sha256'])
        core.need(len(raw) == row['size'], 'transported-selected-size')
        self.check()
        return raw

    def mapping(self):
        self.check()
        result = core.decode(self.fresh_mapping)
        self.check()
        return result

    def record(self):
        self.check()
        return {'kind':KIND, 'custody':'fresh-complete-transported-sdk-jdk-content',
            'original_provenance':core.decode(self.provenance), 'original_mapping':core.decode(self.original_mapping),
            'mapping':self.mapping(), 'fresh_mapping_document_sha256':core.sha(self.fresh_mapping),
            'original_mapping_document_sha256':core.sha(self.original_mapping),
            'mapping_commitment_scope':'original-logical-recipe-preserved', 'fresh_sdk_root':str(self.sdk_root), 'fresh_jdk_root':str(self.extracted/'jdk'),
            'extraction':core.decode(self.extraction), 'extraction_receipt_sha256':self.extraction_pin,
            'carrier_receipt_sha256':self.carrier_pin, 'complete_members':len(self.expected),
            'consumer_context':core.decode(self.context), 'physical_paths_scope':'current-held-action-only',
            'downstream_requires_fresh_extraction':True, 'durability_scope':'ephemeral-current-action',
            'crash_durable_delivery':False, 'downstream_custody_authority':False, 'original_inodes_reused':False,
            'ambient_original_roots_read':False, 'sdk_execution_qualified':False,
            'external_executable_references_qualified':False, 'portable_execution_qualified':False}

    def fence(self):
        self.check()
        current = core._fresh_namespace(self.roots,self.expected,self.clock)
        core.need({key:tuple(row) for key,row in current.items()} == self.witnesses,
                  'transported-current-every-member-witness')
        self.alias_owner.fence()
        self.transport.check()
        self.scratch.check()
        for root in self.roots.values(): root.check()
        self._output_fence()
        self.clock.tick()

    def finish(self):
        self.check()
        core.need(not self.finished, 'transported-final-once')
        raw = self.read_regular('sdk','receipt.json',core.MAX_METADATA)
        core.need(raw == self.raw_original and core.encoded(original._semantic_export(self,core.decode(raw)))
            == self.original_mapping and core.encoded(self._mapping(core.decode(raw))) == self.fresh_mapping,
            'transported-final-semantic-mapping')
        self.transport.full_final()
        # Long complete transport proof precedes LAST fresh complete bytes/NAR.
        core.need(core.encoded(core.revalidate_action_scratch(self.carrier_root,self.carrier_pin,self.extracted,
            self.clock.deadline,pinned_extraction_receipt_sha256=self.extraction_pin,_held_carrier=self.transport,
            consumer_context=core.decode(self.context)))
            == self.extraction, 'transported-final-extraction-join')
        observed, witnesses, nars = core._scan_nar(self.roots,self.expected,self.clock)
        core.need(observed == self.expected and core.encoded(nars) == self.nars and
            {key:tuple(row) for key,row in witnesses.items()} == self.witnesses,
            'transported-last-full-content-namespace-nar')
        self.fence()
        self.finished = True

    def __exit__(self, exc_type, exc, traceback):
        try:
            if exc_type is None:
                core.need(self.finished, 'transported-final-required')
                self.fence()
        except BaseException:
            self.active = False
            self.stack.__exit__(*sys.exc_info())
            raise
        else:
            self.active = False
            self.stack.__exit__(exc_type,exc,traceback)
            if exc_type is None: self.clock.tick()

    def __copy__(self): raise ValueError('transported SDK nontransferable')
    def __deepcopy__(self,memo): raise ValueError('transported SDK nontransferable')
    def __reduce_ex__(self,protocol): raise ValueError('transported SDK nontransferable')


def open_sdk(root,pin,entry,until,context,aliases,declaration,retained):
    temporary = Path(os.environ['TEST_TMPDIR']).resolve(strict=True)
    core.need(temporary.is_dir(), 'transported-workload-temporary')
    return HeldTransportedSDK(root,pin,entry,until,context,temporary/'siwc-transported-sdk',
                              aliases,declaration,retained)


def record(session):
    core.need(type(session) is HeldTransportedSDK, 'transported-record-owner')
    return session.record()


def regenerate(files,session,work,output,query_repository):
    import codex_native_carrier_metadata as metadata
    core.need(type(session) is HeldTransportedSDK, 'transported-regeneration-owner')
    family.source.require(isinstance(query_repository,Path) and not work.exists())
    work.mkdir(mode=0o700)
    fd = family.source.write_source(work/'workspace',files)
    os.close(fd)
    for name in ('home','home/cargo','home/cache','home/config','home/state'):
        (work/name).mkdir(mode=0o700)
    tools = family.query_tools.verify_repository(query_repository,family.source.DEADLINE)
    family.source.require(tools['status'] == 'declared-fixed-query-tools-byte-qualified'
        and tools['inputs_rechecked'] is True)
    old_hub = family.original_hub(session)
    mapping = session.mapping()
    plan = metadata.query_plan(work,work/'workspace/source',mapping,session.sdk_root)
    family.source.require(family.query.execute_query(plan,output) == 0)
    generated = family.query.read_hub(work/'output-base/external'/family.binding.metadata.HUB)
    family.verify_hub(old_hub,generated)
    family.source.verify_written(work/'workspace/source',files)
    family.source.require(family.query_tools.verify_repository(query_repository,family.source.DEADLINE) == tools
        and session.mapping() == mapping)
    return generated,plan,tools
