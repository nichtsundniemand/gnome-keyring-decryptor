/* Copyright 2023 Rufus Maurice Schäfing (wirklichniemand, nichtsundniemand)
 *
 * This file is part of `gnome-keyring-decryptor` and thus licensed under the terms
 * of the GNU General Public License Version 3.
 * A copy of this license can be found in the project's `LICENSE`-file.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <config.h>
#include <docopt.h>
#include <keyring/keyring.h>

int main(int argc, char *argv[]) {
	struct DocoptArgs args = docopt(argc, argv, true, conf_version_string);

	int fd;
	if((fd = open(args.keyring, O_RDONLY)) == -1) {
		fprintf(stderr, "Could not open \"%s\": %s\n", args.keyring, strerror(errno));

		return 1;
	}

	int err = 0;
	struct keyring keyring = keyring_unmarshal(fd, &err);

	if(err < 0) {
		fprintf(stderr, "Failed to unmarshal \"%s\": %s\n", args.keyring, strerror(err));

		close(fd);
		return 1;
	}

	if(err > 0) {
		char *err_str = NULL;
		switch(err) {
			case 1:
				err_str = "Not enough bytes in input";
				break;
			case 2:
				err_str = "Signature mismatch\n";
				break;
		}

		fprintf(stderr, "Failed to unmarshal \"%s\": %s\n", args.keyring, err_str);

		close(fd);
		return 1;
	}

	printf("{");
	keyring_marshal(&keyring);
	printf("}\n");

	keyring_free(&keyring);
	close(fd);
	return 0;
}
