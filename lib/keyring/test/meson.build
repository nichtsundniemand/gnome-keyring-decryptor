# Copyright 2023 Rufus Maurice Schäfing (wirklichniemand, nichtsundniemand)
#
# This file is part of `gnome-keyring-decryptor` and thus licensed under the terms
# of the GNU General Public License Version 3.
# A copy of this license can be found in the project's `LICENSE`-file.

test_cases = [
	'read_test'
]

foreach test_case: test_cases
	test(
		test_case,
		executable(
			test_case,
			test_case + '.c', 'common.c',
			dependencies: dependency('cmocka'),
			link_with: keyring_lib,
			install: false
		),
		env: 'CMOCKA_MESSAGE_OUTPUT=TAP',
		protocol: 'tap'
	)
endforeach
