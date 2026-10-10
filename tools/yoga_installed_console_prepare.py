"""Declared attended-console preparer; no browser launch or consent assertion."""
import json
import sys
import time

import yoga_installed_console_selection as selection
import yoga_local_parent_envelope as envelope


def main(arguments=None):
    # Start one clock before parsing, input capture or envelope preparation.
    # A caller never supplies or renews it; qualification and toolbar share it.
    entry = time.monotonic_ns()
    deadline = entry + 1200 * 10**9
    prepared = None
    try:
        parser = selection.qualification.Parser(description=__doc__)
        parser.add_argument('--request', required=True)
        parser.add_argument('--request-sha256', required=True)
        parser.add_argument('--selection-output', required=True)
        parser.add_argument('--qualification-output', required=True)
        args = parser.parse_args(sys.argv[1:] if arguments is None else arguments)
        prepared = selection.PreparedSelection(args.request, args.request_sha256,
            args.selection_output, args.qualification_output, entry, deadline,
            terminal_descriptor=sys.stdin.fileno())
        produced = prepared.publish()
        prepared.verify()
        result = envelope.run(produced['selection'], produced['selectionSha256'],
            produced['qualification'], entry, deadline, terminal_descriptor=sys.stdin.fileno())
        selection.require(type(result) is dict and type(result.get('exit')) is int)
        if result['exit'] == 0:
            selection.require(result.get('originalEntryMonotonicNs') == entry
                and result.get('deadlineMonotonicNs') == deadline
                and type(result.get('cleanupDeadlineMonotonicNs')) is int
                and entry < result['cleanupDeadlineMonotonicNs'] <= deadline
                and result.get('cleanupCompletionQualified') is True)
            envelope.cleanup_remaining(entry, deadline, result['cleanupDeadlineMonotonicNs'])
            prepared.verify()
            envelope.cleanup_remaining(entry, deadline, result['cleanupDeadlineMonotonicNs'])
        # Envelope's success is effective console qualification and cleanup.
        # Live toolbar worker owns a separate admission and effective bounds.
        selection.require(type(result) is dict and type(result.get('exit')) is int)
        prepared.close()
        prepared = None
        if result['exit'] == 0:
            envelope.cleanup_remaining(entry, deadline, result['cleanupDeadlineMonotonicNs'])
        projection = {'scope': 'yoga-installed-console-preparation-v1',
            'selectionSha256': produced['selectionSha256'],
            'originalEntryMonotonicNs': entry, 'deadlineMonotonicNs': deadline,
            'exit': result['exit'], 'operationId': result.get('operationId'),
            'cleanupDeadlineMonotonicNs': result.get('cleanupDeadlineMonotonicNs'),
            'cleanupCompletionQualified': result.get('cleanupCompletionQualified') is True,
            'unresolvedOperationRecorded': result.get('unresolvedOperationRecorded') is True,
            'cleanupState': result.get('cleanupState', 'unproved'), 'executionAuthority': False, 'toolbarConsentProved': False}
        print(json.dumps(projection, sort_keys=True, separators=(',', ':')))
        if result['exit'] == 0:
            envelope.cleanup_remaining(entry, deadline, result['cleanupDeadlineMonotonicNs'])
        return result['exit'] if result['exit'] >= 0 else 125
    except (Exception, KeyboardInterrupt):
        print('installed-console-preparation-refused', file=sys.stderr)
        return 125
    finally:
        if prepared is not None:
            try:
                prepared.close()
            except BaseException:
                print('installed-console-custody-release-incomplete', file=sys.stderr)


if __name__ == '__main__':
    sys.exit(main())
