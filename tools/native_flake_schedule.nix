{ projectSource, nixpkgsSource, utilsSource, systemsSource }:
let
  # Call the unchanged functions; no registry/getFlake/network resolution.
  utilities = (import (utilsSource + "/flake.nix")).outputs {
    self = { outPath = utilsSource; };
    systems = systemsSource;
  };
  actual = (import (projectSource + "/flake.nix")).outputs {
    self = { outPath = projectSource; };
    nixpkgs = nixpkgsSource;
    flake-utils = utilities;
  };
  target = actual.packages.x86_64-linux.bazel-closure;
in {
  # JSON treats a top-level outPath as coercion to a store-path string.
  inherit (target) drvPath system;
  outputPath = target.outPath;
  sourcePaths = {
    project = projectSource; nixpkgs = nixpkgsSource;
    flake-utils = utilsSource; systems = systemsSource;
  };
}
