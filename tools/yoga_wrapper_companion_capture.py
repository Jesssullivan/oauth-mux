"""Current-controller adapter preserving the exact historical pure validator."""
import hashlib
import json
import yoga_python_role_alias as alias


class AliasValidator:
    def __init__(self, validator, role):
        self.validator, self.role = validator, role

    def validate(self, *arguments, **keywords):
        self.role.check()
        native = json.loads(keywords['native_manifest_bytes'])
        alias.require(native['packages']['python']['out'] == alias.ROOT)
        keywords['controller_tools'] = self.role.logical_tools(keywords['controller_tools'])
        result = self.validator.validate(*arguments, **keywords)
        self.role.check()
        return result


class Capture:
    def __init__(self, selected, paths, shas, deadline, *, validator, custody,
                 native_manifest_path=None):
        self.role, self.inner = None, None
        try:
            # A retained, selected native manifest precedes alias admission.
            native = custody.Captured(native_manifest_path or selected['nativeManifest']['path'],
                selected['nativeManifest']['sha256'], 1024*1024, deadline, custody.time.monotonic_ns)
            try:
                self.role = alias.RoleIdentity(selected['controllerTools']['python'],
                    custody.decode(native.data), deadline)
                native.check()
                self.inner = custody.AuthorityCapture(selected, paths, shas, deadline,
                    validator=AliasValidator(validator, self.role), native_manifest_path=native_manifest_path)
                native.check()
            finally:
                native.close()
            self.result = self.inner.result
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        alias.require(self.inner is not None and self.role is not None)
        self.role.check(); self.inner.check(); self.role.check()

    def close(self):
        failed = False
        for resource in (self.inner, self.role):
            if resource is not None:
                try:
                    resource.close()
                except (OSError, ValueError):
                    failed = True
        self.inner, self.role = None, None
        alias.require(not failed)

    def __enter__(self):
        return self

    def __exit__(self, kind, value, trace):
        try:
            if kind is None:
                self.check()
        finally:
            self.close()
