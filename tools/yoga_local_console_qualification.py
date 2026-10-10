"""Operator-local exact qualification launcher; inherited stdin is mandatory."""
import json
import sys
import yoga_local_console_scope as scope


def main(arguments=None):
    try:
        result = scope.run(list(sys.argv[1:] if arguments is None else arguments), terminal_descriptor=sys.stdin.fileno())
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
        return result['exit'] if result['exit'] >= 0 else 125
    except scope.Refusal as error:
        print(json.dumps(error.projection, sort_keys=True, separators=(',', ':')))
        print('local-console-qualification-refused', file=sys.stderr)
        return 125
    except (Exception, KeyboardInterrupt):
        print('local-console-qualification-refused', file=sys.stderr)
        return 125


if __name__ == '__main__':
    sys.exit(main())
