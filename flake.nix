# Copyright 2023 Rufus Maurice Schäfing (wirklichniemand, nichtsundniemand)
#
# This file is part of `gnome-keyring-decryptor` and thus licensed under the terms
# of the GNU General Public License Version 3.
# A copy of this license can be found in the project's `LICENSE`-file.

{
  description = "Development environment for `gnome-keyring-decryptor`";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      docopt-c = pkgs.python311Packages.buildPythonPackage {
        name = "docopt-c";

        src = builtins.fetchGit {
          url = "https://github.com/docopt/docopt.c.git";
          ref = "master";
          rev = "a8cdecfd6e6a15b19748222a2b9438a964bb3b58";
        };

        patchPhase = ''
          substituteInPlace setup.py --replace \
            "py_modules=[\"docopt_c\"]," \
            "py_modules=[\"docopt_c\", \"docopt\"],"

          substituteInPlace setup.py --replace \
            "scripts=[\"docopt.py\", \"docopt_c.py\"]," \
            "scripts=[\"docopt_c.py\"]," \
        '';

        pythonImportsCheck = ["docopt_c"];
      };

      devShells.default = pkgs.mkShell {
        packages = [
          pkgs.cmocka
          pkgs.ninja
          pkgs.pkg-config
          (pkgs.python311.withPackages
            (ps: with ps; [
              self.docopt-c.${system}
              gcovr
              meson
            ]))
          pkgs.valgrind
        ];
      };
    });
}
