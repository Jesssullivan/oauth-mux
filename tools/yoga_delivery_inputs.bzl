"""Fixed public terminal receipt; consumer additionally verifies exact SHA256."""
def _inputs(ctx):
    receipt = ctx.path('/home/jess/.local/state/omux-execution-20261005/d6311994-5212-4034-ac93-49b06405db88/receipt.json')
    if not receipt.exists:
        fail('fixed d631 terminal receipt unavailable')
    ctx.symlink(receipt, 'd631-receipt.json')
    bootstrap = ctx.path('/nix/store/j5dnm7vp4w41x7rjia61c1hd6s7yszvd-omux-bazel-bootstrap-closure/native.json')
    if not bootstrap.exists:
        fail('fixed d631 bootstrap manifest unavailable')
    ctx.symlink(bootstrap, 'bootstrap-native.json')
    # Existing Neo pin persisted and strict-SSH used in the Oct4 Lab receipts.
    # Consumer commits exact97bytes/SHA and holds/rechecks source custody.
    known_hosts = ctx.path('/home/jess/.claude/agent-notes-rescue/2026-10-04/lab-yoga-known-hosts')
    if not known_hosts.exists:
        fail('existing receipted Yoga public host pin unavailable')
    ctx.watch(known_hosts)
    ctx.symlink(known_hosts, 'yoga-ssh-known-hosts')
    authority = ctx.os.environ.get('OMUX_YOGA_DELIVERY_QUALIFICATION')
    if authority:
        if not authority.startswith('/home/jess/.local/state/omux-yoga-delivery-20261006/') or '/..' in authority or '\n' in authority or '\r' in authority:
            fail('authority must be a guard-bound prior local qualification output')
        selected = ctx.path(authority)
        if not selected.exists:
            fail('guard-bound Yoga OS qualification unavailable')
        ctx.watch(selected)
        ctx.symlink(selected, 'authority.json')
    else:
        # Qualify has no prior authority. Inspect/verify require hash+schema before SSH.
        ctx.file('authority.json', '')
    ctx.file('BUILD.bazel', 'exports_files(["d631-receipt.json", "bootstrap-native.json", "authority.json", "yoga-ssh-known-hosts"], visibility=["//visibility:public"])\n')

yoga_delivery_inputs = repository_rule(
    implementation = _inputs,
    local = True,
    environ = ['OMUX_YOGA_DELIVERY_QUALIFICATION'],
)
