# gnome-keyring-decryptor

This repository contains a simple utility to decode and decrypt the `.keystore`-files
used by the `gnome-keyring` utility and daemon.

The decrypted keystore's contents are then output in JSON format.

I am really surprised this didn't exist. There is a keyring-dump utility in the
`gnome-keyring`-repo, but since the output-format of that utility is not really suitable
for further processing, I decided to create this tool.

## Usage

TBD.

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
