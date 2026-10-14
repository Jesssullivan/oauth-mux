"""Exact ninth plan entry; no argv or alternative target admission."""
import codex_native_acquisition_preflight as preflight
if __name__=='__main__':
    try:preflight.main('plan')
    except (ValueError,OSError,KeyError,TypeError,UnicodeError):
        raise SystemExit('native acquisition plan refused') from None
