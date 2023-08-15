/* Copyright 2023 Rufus Maurice Schäfing (wirklichniemand, nichtsundniemand)
 *
 * This file is part of `gnome-keyring-decryptor` and thus licensed under the terms
 * of the GNU General Public License Version 3.
 * A copy of this license can be found in the project's `LICENSE`-file.
 */

#include <config.h>
#include <docopt.h>

int main(int argc, char *argv[]) {
	docopt(argc, argv, true, conf_version_string);

	return 0;
}
