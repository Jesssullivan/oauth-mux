"""Inert unless exact contained component profile selects a verified manifest."""
_BASE = '/srv/fast-local/jess/state/codex/omux-codex-component-inputs-20261008/'
_COORDS = ['/home/jess/.local/state/omux-execution-20261005', '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005']
_BACKEND = '0b82d7f1535ab98ca2854dad0ac908912c9df56f29bb70c664e18e9956dc4a3f'
_RUNTIME = ['runtime/bin/codex','runtime/lib/codex/lib/ld-linux-x86-64.so.2',
    'runtime/lib/codex/lib/libc.so.6','runtime/lib/codex/lib/libdl.so.2',
    'runtime/lib/codex/lib/libm.so.6','runtime/lib/codex/lib/libpthread.so.0',
    'runtime/lib/codex/lib/librt.so.1','runtime/lib/codex/lib/libutil.so.1',
    'runtime/lib/codex/libexec/codex.bin','runtime/lib/codex/share/ca-bundle.crt']

def _physical(ctx, value):
    path = ctx.path(value)
    if not path.exists or str(path.realpath) != value or path.is_dir:
        fail('component physical declared input required')
    ctx.watch(path)
    return path

def _implementation(ctx):
    selected = ctx.os.environ.get('OMUX_CODEX_COMPONENT_MANIFEST', '')
    pin = ctx.os.environ.get('OMUX_CODEX_COMPONENT_MANIFEST_SHA256', '')
    if not selected and not pin:
        ctx.file('unavailable', 'No qualified optional component selected.\n', executable = False)
        ctx.file('BUILD.bazel', 'package(default_visibility=["//visibility:public"])\nfilegroup(name="inputs",srcs=["unavailable"])\n', executable = False)
        return
    parts = selected.split('/')
    if not selected.startswith(_BASE) or len(parts[-2]) != 32 or parts[-1] != 'input.json' or selected != _BASE + parts[-2] + '/input.json' or any([c not in '0123456789abcdef' for c in parts[-2].elems()]) or len(pin) != 64 or any([c not in '0123456789abcdef' for c in pin.elems()]):
        fail('closed component manifest selection required')
    # Guard has already held/hash-qualified this exact private metadata and all
    # physical input ancestors before repository materialization. realpath is a
    # metadata check here, not a replacement for action/guard custody/hash checks.
    manifest = _physical(ctx, selected)
    value = json.decode(ctx.read(manifest))
    if value.get('scope') != 'omux-codex-device-component-input-v1' or value.get('action') not in ['produce','install','remove']:
        fail('component input purpose required')
    producing = value['action'] == 'produce'
    proof = value['qualification'] if producing else value['producer']
    receipt_path = proof['path']
    receipt_parts = receipt_path.split('/')
    base = '/'.join(receipt_parts[:-2])
    if base not in _COORDS or receipt_parts[-1] != 'receipt.json' or len(receipt_parts[-2]) != 36:
        fail('component exact public producer receipt required')
    receipt_file = _physical(ctx, receipt_path)
    receipt = json.decode(ctx.read(receipt_file))
    epoch = receipt_parts[-2]
    expected_label = '//tools:codex_retained_device_api_qualification' if producing else '//delivery:codex_device_acquisition_component'
    if receipt.get('id') != epoch or receipt.get('artifact_epoch') != epoch or receipt.get('verb') != 'test' or receipt.get('targets') != [expected_label] or receipt.get('source_commit') != proof['source_commit'] or receipt.get('graph_sha256') != proof['graph_sha256'] or receipt.get('source_dirty') != 'false':
        fail('component selected producer declaration mismatch')
    if receipt.get('cache_reuse_requested') == True:
        key = receipt.get('cache_key', '')
        if len(key) != 64 or any([c not in '0123456789abcdef' for c in key.elems()]) or receipt.get('cache_policy') != 2:
            fail('component cache output identity required')
        output = base + '/cache-v2-' + key + '/output-base'
    else:
        if receipt.get('cache_reuse_requested') != False or receipt.get('cache_key') != None or receipt.get('cache_policy') != None:
            fail('component uncached output identity required')
        output = base + '/' + epoch + '/output-base'
    if receipt.get('output_base') != output:
        fail('component actual output-base required')
    root = output + '/execroot/_main/bazel-out/k8-fastbuild/testlogs/' + expected_label[2:].replace(':','/') + '/test.outputs/' + ('' if producing else 'component/') + _BACKEND
    if value['runtime_directory' if producing else 'component_directory'] != root:
        fail('component exact producer output leaf required')
    names = ['codex','native-source-receipt.json'] + _RUNTIME + ([] if producing else ['component.json','qualification.json'])
    for name in names:
        member = _physical(ctx, root + '/' + name)
        ctx.symlink(member, name)
    ctx.symlink(receipt_file, 'producer-receipt.json')
    ctx.symlink(manifest, 'input.json')
    ctx.file('BUILD.bazel', 'package(default_visibility=["//visibility:public"])\nexports_files(' + repr(names + ['input.json','producer-receipt.json']) + ')\nfilegroup(name="inputs",srcs=' + repr(names + ['input.json','producer-receipt.json']) + ')\n', executable = False)

codex_device_component_repository = repository_rule(implementation = _implementation,
    environ = ['OMUX_CODEX_COMPONENT_MANIFEST','OMUX_CODEX_COMPONENT_MANIFEST_SHA256'], local = True)
