"""Two actual public 25a files, inert declarations; action validates full custody."""
_ROOT='/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/25a0acfd-8ba2-46d2-ac33-c99973b25eee'
def _inputs(ctx):
    rows={
        'receipt.json':_ROOT+'/receipt.json',
        'default_instance_archive.tar.gz':_ROOT+'/output-base/execroot/_main/bazel-out/k8-fastbuild/bin/delivery/default_instance_archive.tar.gz',
    }
    for name,physical in rows.items():
        selected=ctx.path(physical)
        if not selected.exists or selected.is_dir or str(selected.realpath)!=physical:
            fail('fixed physical public 25a input unavailable')
        ctx.watch(selected)
        ctx.symlink(selected,name)
    ctx.file('BUILD.bazel','exports_files(["receipt.json","default_instance_archive.tar.gz"],visibility=["//visibility:public"])\n')
yoga_public_install_inputs=repository_rule(implementation=_inputs,local=True)
