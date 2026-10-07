"""Bazel launcher fixture: checks actual repeated argv and declared bytes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate public JSON fixture key')
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', action='append', required=True)
    parser.add_argument('--expected-sha256', action='append', required=True)
    parser.add_argument('--physical-selection', required=True)
    parser.add_argument('--literal-json', required=True)
    args = parser.parse_args()
    # Compare literal argv; this deliberately nonexistent physical selector is
    # never opened and must not be rewritten into the declared main's runfiles.
    if args.physical_selection != '/srv/omux-fixture/tools/file_args_test.py':
        raise ValueError('physical selection argument was rewritten')
    observed_json = json.loads(args.literal_json, object_pairs_hook=unique_pairs)
    expected_json = {'outer': {'name': 'public fixture', 'enabled': True}, 'items': [1, 2]}
    # Canonical JSON comparison distinguishes booleans from integers while
    # accepting the operator's explicit shell quoting and JSON whitespace.
    if json.dumps(observed_json, sort_keys=True, allow_nan=False) != json.dumps(expected_json, sort_keys=True):
        raise ValueError('nested public JSON argument differs')
    if len(args.file) != 2 or len(args.expected_sha256) != 2:
        raise ValueError('exactly two repeated declared file arguments required')
    observed = []
    root = Path(os.environ['TEST_SRCDIR'])
    for value in args.file:
        path = Path(value)
        if not path.is_absolute() or not path.is_relative_to(root):
            raise ValueError('file must use exact declared runfiles namespace')
        with path.open('rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
                raise ValueError('small regular fixture required')
            content = stream.read(4097)
        observed.append(hashlib.sha256(content).hexdigest())
    if observed != args.expected_sha256:
        raise ValueError('declared file order or content differs')


if __name__ == '__main__':
    main()
