# Copyright 2023 Rufus Maurice Schäfing (wirklichniemand, nichtsundniemand)
#
# This file is part of `gnome-keyring-decryptor` and thus licensed under the terms
# of the GNU General Public License Version 3.
# A copy of this license can be found in the project's `LICENSE`-file.

project(
	'gnome-keyring-decryptor',
	'c',
	version: '0.1',
	default_options: [
		'buildtype=release',
		'c_std=c11',
		'warning_level=3'
	]
)

subdir('src')

executable(
	meson.project_name(),
	link_with: main_lib,
	install: true
)
