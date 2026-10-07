"""Analysis-time identity and declared files for a flake-owned executable.

This module stays independent of generated repositories so tool definitions can
load it while a repository is being initialized without a dependency cycle.
"""

OmuxNixToolInfo = provider(
    doc = "An immutable Nix executable and the files declaring its complete tool closure.",
    fields = {
        "executable_path": "Absolute /nix/store path to the underlying executable.",
        "closure_files": "depset<File> declaring the executable's transitive Nix closure.",
    },
)
