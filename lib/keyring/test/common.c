/* Copyright 2023 Rufus Maurice Schäfing (wirklichniemand, nichtsundniemand)
 *
 * This file is part of `gnome-keyring-decryptor` and thus licensed under the terms
 * of the GNU General Public License Version 3.
 * A copy of this license can be found in the project's `LICENSE`-file.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "common.h"

int setup_no_input(void **state) {
	struct no_input_state *test_state = test_malloc(sizeof(struct no_input_state));
	assert_non_null(test_state);
	*test_state = (struct no_input_state){
		.empty_fd = memfd_create("", MFD_CLOEXEC),
	};

	assert_int_not_equal(-1, test_state->empty_fd);

	*state = test_state;
	return 0;
}

int teardown_no_input(void **state) {
	assert_non_null(*state);
	struct no_input_state *test_state = *state;

	assert_int_not_equal(-1, test_state->empty_fd);
	assert_int_equal(0, close(test_state->empty_fd));

	test_free(test_state);
	return 0;
}
