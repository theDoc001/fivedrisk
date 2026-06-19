"""Allow `python -m fivedrisk` to invoke the CLI.

When the first positional argument is ``gateway`` we dispatch into the
plugin-IPC gateway (``python -m fivedrisk gateway stdio --policy ...``)
rather than the standard CLI. Everything else falls through to ``cli.main``.
"""
import sys

from .cli import main

if len(sys.argv) > 1 and sys.argv[1] == "gateway":
    from .gateway import main as gateway_main

    sys.exit(gateway_main(sys.argv[2:]))

main()
