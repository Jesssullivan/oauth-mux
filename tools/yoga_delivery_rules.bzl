"""Three fixed read-only modes; caller arguments are not executable selectors."""
load(':rules.bzl', 'host_python_binary')

def yoga_delivery_binaries():
    common = [
        '--ssh', '/nix/store/aq5s91svywqgs5l9zyhp1wcjqvnfa0ss-openssh-with-gssapi-10.2p1/bin/ssh',
        '--inventory', '$(location @omux_yoga_controller_nars//:inventory.json)',
        '--receipt', '$(location @omux_yoga_delivery_inputs//:d631-receipt.json)',
        '--bootstrap-manifest', '$(location @omux_yoga_delivery_inputs//:bootstrap-native.json)',
        '--known-hosts', '$(location @omux_yoga_delivery_inputs//:yoga-ssh-known-hosts)',
    ]
    for mode in ['qualify', 'inspect', 'verify']:
        host_python_binary(
            name = 'yoga_controller_' + mode,
            main = 'yoga_controller_delivery.py',
            srcs = ['yoga_executable_qualification.py', 'verify_cached_nars.py',
                    'host_closure_transfer.py', 'ssh_policy.py'],
            data = ['@omux_yoga_controller_nars//:inventory.json',
                    '@omux_yoga_delivery_inputs//:d631-receipt.json',
                    '@omux_yoga_delivery_inputs//:bootstrap-native.json',
                    '@omux_yoga_delivery_inputs//:yoga-ssh-known-hosts'] +
                   ([] if mode == 'qualify' else ['@omux_yoga_delivery_inputs//:authority.json']),
            args = common + ['--mode', mode] + ([] if mode == 'qualify' else
                   ['--authority', '$(location @omux_yoga_delivery_inputs//:authority.json)']),
            tags = ['manual', 'no-remote', 'no-cache'],
            target_compatible_with = ['@platforms//os:linux', '@platforms//cpu:x86_64'],
        )
