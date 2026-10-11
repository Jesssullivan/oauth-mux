"""Distinct held original-clock qualification for the reserved installed toolbar."""
import sys
import yoga_session_qualification as qualification


def produce(selection, digest, output, deadline, *, terminal_descriptor=0):
    return qualification._produce(selection, digest, output, deadline,
                                  terminal_descriptor=terminal_descriptor, reserved=True)


def main():
    parser = qualification.Parser(description=__doc__)
    parser.add_argument('--selection', required=True)
    parser.add_argument('--selection-sha256', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--deadline-monotonic-ns', required=True, type=int)
    args = parser.parse_args()
    result = produce(args.selection, args.selection_sha256, args.output, args.deadline_monotonic_ns,
                     terminal_descriptor=sys.stdin.fileno())
    print(qualification.canonical(result).decode('ascii'))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (qualification.QualificationError, ValueError, OSError):
        print('reserved-yoga-qualification-refused', file=sys.stderr)
        sys.exit(125)
