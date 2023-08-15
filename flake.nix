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
      devShells.default = pkgs.mkShell {
        packages = [
          pkgs.meson
          pkgs.ninja
        ];
      };
    });
}
