# Retained browser tool qualification inputs

These are exact public test-log bytes, retained as declared action inputs.
They are data, including the standard Bazel pager preamble; never execute them.
They do not prove browser installation, account acquisition or continuity.

| File | Original epoch and target | SHA256 |
| --- | --- | --- |
| `mapping-01c11682.log` | `01c11682-8389-4519-9b1a-dc7403066431`, `//tools:site_tool_mapping_qualification` | `ae9a2c94aaf7f6db46460a9b8c54be2cb5051b46b6fb75b1bc826be9fbb2376d` |
| `nar-120f8b34.log` | `120f8b34-c1b2-48c0-a533-97ebd8ebbb93`, `//tools:cached_site_byte_verification` | `42688569613bb69896d4c07f601a543c6b73f89efd27d340158462fb7fd27375` |

Both invocations exited zero with verified empty descendants. Their retained
test-evidence manifest digests are respectively
`ca1f79b5a1670469723c939f25847170421e276055c147f1c551494e0c06a199`
and `d408560b176c350b05eae9dc466aae7161c27afbdf0d9a09464c4669c0c953e2`.
The NAR proof verified 401 store paths, 29765 declared regular inputs and
2081764648 NAR bytes. Symlink targets were inert data, not followed.

`//delivery:qualified_browser_runtime` validates these fixed receipts against
the fixed inventory and five exact execution exclusions: three BlueZ
configuration links and two systemd environment-configuration links. The installed Chromium
fixture additionally requires the supervisor's browser-specific masks for
`/etc/bluetooth` and `/etc/environment`.
Neither a source receipt nor this generated join establishes provider authority.

See the [durable sprint note](../../docs/agent-notes/2026-10-05-sess-omux-integrated-delivery.md),
[implementation plan](../../docs/plans/omux-integrated-delivery-sprint-2026-10-05.md)
and [TIN-5442](https://linear.app/tinyland/issue/TIN-5442).
