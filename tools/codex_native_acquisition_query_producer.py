"""Exact ninth query entry; no build/compiler or alternative target admission."""
import codex_native_acquisition_preflight as preflight
if __name__=='__main__':
    try:preflight.main('query')
    except (ValueError,OSError,KeyError,TypeError,UnicodeError):
        raise SystemExit('native acquisition query refused') from None
