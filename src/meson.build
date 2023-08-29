# Copyright 2023 Rufus Maurice Schäfing (wirklichniemand, nichtsundniemand)
#
# This file is part of `gnome-keyring-decryptor` and thus licensed under the terms
# of the GNU General Public License Version 3.
# A copy of this license can be found in the project's `LICENSE`-file.

# Basically we only want to generate a meson-dependency for the docopt-parser.
# This is simply done by calling the `docopt_c`-module with the config-file.
#
# The additional magic with `grep` and `configure_file()` is not really necessary,
# but I wanted to have comments, which `docopt` does not support and to be able
# to set the program's name dynamically...
pymod = import('python')
python_prog = pymod.find_installation(
	'python3',
	modules: ['docopt_c']
)

docopt_dep = declare_dependency(
	sources: custom_target(
		'docopt_generate',
		input: custom_target(
			'docopt_input_strip',
			input: configure_file(
				input: 'docopt.in',
				output: 'docopt.configured',
				configuration: {
					'exe_name': meson.project_name()
				}
			),
			output: 'main.docopt',
			command: [find_program('grep'), '-v', '^#', '@INPUT@'],
			capture: true
		),
		output: ['docopt.c', 'docopt.h'],
		# This (specifically the part with `@OUTPUT0@`) only works, because `docopt_c` is kinda
		# lax about the filename you pass with `-o`. Extensions are apparently stripped and then
		# two files with `.c` and `.h` endings are created...
		command: [python_prog, '-m', 'docopt_c', '@INPUT@', '-o', '@OUTPUT0@']
	)
)

# Well, this is the place to put any build-time configuration/information, so use it :)
config_header = configure_file(
	input: 'config.h.in',
	output: 'config.h',
	configuration: {
		'version_string': meson.project_version()
	}
)

main_lib = static_library(
	'main',
	'main.c', config_header,
	dependencies: [docopt_dep, keyring_dep]
)
