# Copyright 2023 Rufus Maurice Schäfing (wirklichniemand, nichtsundniemand)
#
# This file is part of `gnome-keyring-decryptor` and thus licensed under the terms
# of the GNU General Public License Version 3.
# A copy of this license can be found in the project's `LICENSE`-file.

keyring_lib = both_libraries(
	'keyring',
	'keyring.c', 'error.c',
	c_args: '-D_DEFAULT_SOURCE'
)

subdir('test')
