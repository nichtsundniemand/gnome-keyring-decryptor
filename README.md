# gnome-keyring-decryptor

This repository contains a simple utility to decode and decrypt the `.keystore`-files
used by the `gnome-keyring` utility and daemon.

The decrypted keystore's contents are then output in JSON format.

I am really surprised this didn't exist. There is a keyring-dump utility in the
`gnome-keyring`-repo, but since the output-format of that utility is not really suitable
for further processing, I decided to create this tool.

## Building & Hacking

This project is built using [`meson`](https://mesonbuild.com/), so you will need that.
In order to use `meson` you will also need a build-backend. I simply use [`ninja`](https://ninja-build.org/)
which is the default.

The provided `nix`-flake will yield a dev-environment containing all the necessary
dependencies, so using it is recommended.

Since this project also includes an `.envrc` using [`nix-direnv`](https://github.com/nix-community/nix-direnv)
for use with the provided flake, I strongly recommend setting up [`direnv`](https://direnv.net/)
as well.

Build depencies:
 * [`docopt.c`](https://github.com/docopt/docopt.c): For generating the argument parser
   in accordance with the [`docopt`](http://docopt.org/)-specification.

   Meson needs to be able to find this in your Python's search-path.
 * [`cmocka`](https://cmocka.org/): Test-framework used by the unit-tests.

   This should be available through most distribution's repositories. Meson needs to
   be able to find this as a dependency.

To build this project simply follow the usual `meson`-procedure:
```sh
$ meson setuo build
$ ninja -C build
```

Afterwards, if everything went well, the executable can be found under `build/gnome-keyring-decryptor`.

## Usage

To use this tool simply call `gnome-keyring-decryptor --keyring=<file>` with `<file>`
being the path to the keyring-file on the command line.

The contents of the keyring will then be output on `stdout`.

## References

 * The file format is documented in the `gnome-keyring`-repository under
   [`docs/file-format.txt`](https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/master/docs/file-format.txt).

   A copy of that file can be found in this repository - also under `docs/file-format.txt` -
   in case the upstream version gets removed or moved in any way.
 * This tool is - in general - inspired by/copied from the aforementioned tool in the
   `gnome-keyring`-repo:
   [dump-keyring0-format.c](https://gitlab.gnome.org/GNOME/gnome-keyring/-/blob/master/pkcs11/secret-store/dump-keyring0-format.c)

`gnome-keyring` in general and the dump-utility as well as the file format documentation
specifically are licensed under the GNU General Public License Version 2.

## License

This file is part of `gnome-keyring-decryptor`.

`gnome-keyring-decryptor` is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

`gnome-keyring-decryptor` is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with `gnome-keyring-decryptor`.
If not, see <https://www.gnu.org/licenses/>.

Copyright 2023 Rufus Maurice Schäfing (wirklichniemand, nichtsundniemand)
