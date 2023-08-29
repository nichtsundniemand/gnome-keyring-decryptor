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
#include "../internal/keyring.h"

struct read_uint_state {
	uint64_t magic;
	int full_fd;
};

int setup_read_uint(void **state) {
	struct read_uint_state *test_state = test_malloc(sizeof(struct read_uint_state));
	assert_non_null(test_state);
	*test_state = (struct read_uint_state){
		.magic = 0x4242424242424242,
		.full_fd = memfd_create("", MFD_CLOEXEC)
	};

	assert_int_not_equal(-1, test_state->full_fd);
	assert_int_equal(
		sizeof(test_state->magic),
		write(test_state->full_fd, &test_state->magic, sizeof(test_state->magic))
	);
	assert_int_equal(0, lseek(test_state->full_fd, 0, SEEK_SET));

	*state = test_state;
	return 0;
}

int teardown_read_uint(void **state) {
	assert_non_null(*state);
	struct read_uint_state *test_state = *state;

	assert_int_not_equal(-1, test_state->full_fd);
	assert_int_equal(0, close(test_state->full_fd));

	test_free(test_state);
	return 0;
}

struct read_bytes_state {
	uint8_t bytes[4];
	int byte_fd;
};

int setup_read_bytes(void **state) {
	struct read_bytes_state *test_state = test_malloc(sizeof(struct read_bytes_state));
	assert_non_null(test_state);
	*test_state = (struct read_bytes_state){
		.bytes = {0xDE, 0xAD, 0xBE, 0xEF},
		.byte_fd = memfd_create("", MFD_CLOEXEC)
	};

	assert_int_not_equal(-1, test_state->byte_fd);
	assert_int_equal(
		sizeof(test_state->bytes),
		write(test_state->byte_fd, test_state->bytes, sizeof(test_state->bytes))
	);
	assert_int_equal(0, lseek(test_state->byte_fd, 0, SEEK_SET));

	*state = test_state;
	return 0;
}

int teardown_read_bytes(void **state) {
	assert_non_null(*state);
	struct read_bytes_state *test_state = *state;

	assert_int_not_equal(-1, test_state->byte_fd);
	assert_int_equal(0, close(test_state->byte_fd));

	test_free(test_state);
	return 0;
}

struct read_string_state {
	int null_string_fd;
	int short_string_fd;
	int proper_string_fd;
	char proper_string[5];
};

int setup_read_string(void **state) {
	struct read_string_state *test_state = test_malloc(sizeof(struct read_string_state));
	assert_non_null(test_state);
	*test_state = (struct read_string_state){
		.null_string_fd = memfd_create("", MFD_CLOEXEC),
		.short_string_fd = memfd_create("", MFD_CLOEXEC),
		.proper_string_fd = memfd_create("", MFD_CLOEXEC),
		.proper_string = "test"
	};

	assert_int_not_equal(-1, test_state->null_string_fd);
	assert_int_not_equal(-1, test_state->short_string_fd);
	assert_int_not_equal(-1, test_state->proper_string_fd);

	static const uint32_t null_string_marker = 0xffffffff;
	assert_int_equal(sizeof(null_string_marker), write(test_state->null_string_fd, &null_string_marker, sizeof(null_string_marker)));
	assert_int_equal(0, lseek(test_state->null_string_fd, 0, SEEK_SET));

	uint32_t short_string_size = htobe32(0x000000ff);
	assert_int_equal(sizeof(short_string_size), write(test_state->short_string_fd, &short_string_size, sizeof(short_string_size)));
	assert_int_equal(0, lseek(test_state->short_string_fd, 0, SEEK_SET));

	uint32_t proper_string_size = htobe32(sizeof(test_state->proper_string) - 1);
	assert_int_equal(sizeof(proper_string_size), write(test_state->proper_string_fd, &proper_string_size, sizeof(proper_string_size)));
	assert_int_equal(
		sizeof(test_state->proper_string) - 1,
		write(test_state->proper_string_fd, test_state->proper_string, sizeof(test_state->proper_string) - 1)
	);
	assert_int_equal(0, lseek(test_state->proper_string_fd, 0, SEEK_SET));

	*state = test_state;
	return 0;
}

int teardown_read_string(void **state) {
	assert_non_null(*state);
	struct read_string_state *test_state = *state;

	assert_int_not_equal(-1, test_state->null_string_fd);
	assert_int_not_equal(-1, test_state->short_string_fd);
	assert_int_not_equal(-1, test_state->proper_string_fd);

	assert_int_equal(0, close(test_state->null_string_fd));
	assert_int_equal(0, close(test_state->short_string_fd));
	assert_int_equal(0, close(test_state->proper_string_fd));

	test_free(test_state);
	return 0;
}

void keystore_read_uint8_should_fail_on_invalid_fd() {
	error_t err = 0;
	keystore_read_uint8(-1, &err);
	assert_non_null(err);
	error_free(err);
}

void keystore_read_uint8_should_fail_on_no_input(void **state) {
	struct no_input_state *test_state = *state;

	error_t err = 0;
	keystore_read_uint8(test_state->empty_fd, &err);
	assert_non_null(err);
	error_free(err);
}

void keystore_read_uint8_should_succeed_with_input(void **state) {
	struct read_uint_state *test_state = *state;

	error_t err = 0;
	uint8_t value = keystore_read_uint8(test_state->full_fd, &err);
	assert_null(err);
	assert_int_equal((uint8_t)test_state->magic, value);
}

void keystore_read_uint16_should_fail_on_invalid_fd() {
	error_t err = 0;
	keystore_read_uint16(-1, &err);
	assert_non_null(err);
	error_free(err);
}

void keystore_read_uint16_should_fail_on_no_input(void **state) {
	struct no_input_state *test_state = *state;

	error_t err = 0;
	keystore_read_uint16(test_state->empty_fd, &err);
	assert_non_null(err);
	error_free(err);
}

void keystore_read_uint16_should_succeed_with_input(void **state) {
	struct read_uint_state *test_state = *state;

	error_t err = 0;
	uint16_t value = keystore_read_uint16(test_state->full_fd, &err);
	assert_null(err);
	assert_int_equal((uint16_t)test_state->magic, value);
}

void keystore_read_uint32_should_fail_on_invalid_fd() {
	error_t err = 0;
	keystore_read_uint32(-1, &err);
	assert_non_null(err);
	error_free(err);
}

void keystore_read_uint32_should_fail_on_no_input(void **state) {
	struct no_input_state *test_state = *state;

	error_t err = 0;
	keystore_read_uint32(test_state->empty_fd, &err);
	assert_non_null(err);
	error_free(err);
}

void keystore_read_uint32_should_succeed_with_input(void **state) {
	struct read_uint_state *test_state = *state;

	error_t err = 0;
	uint32_t value = keystore_read_uint32(test_state->full_fd, &err);
	assert_null(err);
	assert_int_equal((uint32_t)test_state->magic, value);
}

void keystore_read_uint64_should_fail_on_invalid_fd() {
	error_t err = 0;
	keystore_read_uint64(-1, &err);
	assert_non_null(err);
	error_free(err);
}

void keystore_read_uint64_should_fail_on_no_input(void **state) {
	struct no_input_state *test_state = *state;

	error_t err = 0;
	keystore_read_uint64(test_state->empty_fd, &err);
	assert_non_null(err);
	error_free(err);
}

void keystore_read_uint64_should_succeed_with_input(void **state) {
	struct read_uint_state *test_state = *state;

	error_t err = 0;
	uint64_t value = keystore_read_uint64(test_state->full_fd, &err);
	assert_null(err);
	assert_int_equal((uint64_t)test_state->magic, value);
}

void keystore_read_bytes_should_fail_on_invalid_fd() {
	error_t err = 0;
	uint8_t value[8] = {0};
	keystore_read_bytes(-1, value, sizeof(value), &err);
	assert_non_null(err);
	error_free(err);
}

void keystore_read_bytes_should_fail_on_no_input(void **state) {
	struct no_input_state *test_state = *state;

	error_t err = 0;
	uint8_t value[8] = {0};
	keystore_read_bytes(test_state->empty_fd, value, sizeof(value), &err);
	assert_non_null(err);
	error_free(err);
}

void keystore_read_bytes_should_succeed_with_input(void **state) {
	struct read_bytes_state *test_state = *state;

	error_t err = 0;
	uint8_t *value = test_malloc(sizeof(test_state->bytes));
	keystore_read_bytes(test_state->byte_fd, value, sizeof(test_state->bytes), &err);
	assert_null(err);
	assert_memory_equal(test_state->bytes, value, sizeof(test_state->bytes));

	test_free(value);
}

void keystore_read_string_should_fail_on_invalid_fd() {
	error_t err = 0;
	char *value = keystore_read_string(-1, &err);
	assert_non_null(err);
	error_free(err);
	assert_null(value);
}

void keystore_read_string_should_fail_on_no_input(void **state) {
	struct no_input_state *test_state = *state;

	error_t err = 0;
	char *value = keystore_read_string(test_state->empty_fd, &err);
	assert_non_null(err);
	error_free(err);
	assert_null(value);
}

void keystore_read_string_should_succeed_and_return_null_on_ffffffff(void **state) {
	struct read_string_state *test_state = *state;

	error_t err = 0;
	char *value = keystore_read_string(test_state->null_string_fd, &err);
	assert_null(err);
	assert_null(value);
}

void keystore_read_string_should_fail_on_input_too_short_for_size(void **state) {
	struct read_string_state *test_state = *state;

	error_t err = 0;
	char *value = keystore_read_string(test_state->short_string_fd, &err);
	assert_non_null(err);
	error_free(err);
	assert_null(value);
}

void keystore_read_string_should_succeed_and_return_string_on_proper_input(void **state) {
	struct read_string_state *test_state = *state;

	error_t err = 0;
	char *value = keystore_read_string(test_state->proper_string_fd, &err);
	assert_null(err);
	assert_string_equal(test_state->proper_string, value);

	free(value);
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(keystore_read_uint8_should_fail_on_invalid_fd),
		cmocka_unit_test_setup_teardown(keystore_read_uint8_should_fail_on_no_input, setup_no_input, teardown_no_input),
		cmocka_unit_test_setup_teardown(keystore_read_uint8_should_succeed_with_input, setup_read_uint, teardown_read_uint),

		cmocka_unit_test(keystore_read_uint16_should_fail_on_invalid_fd),
		cmocka_unit_test_setup_teardown(keystore_read_uint16_should_fail_on_no_input, setup_no_input, teardown_no_input),
		cmocka_unit_test_setup_teardown(keystore_read_uint16_should_succeed_with_input, setup_read_uint, teardown_read_uint),

		cmocka_unit_test(keystore_read_uint32_should_fail_on_invalid_fd),
		cmocka_unit_test_setup_teardown(keystore_read_uint32_should_fail_on_no_input, setup_no_input, teardown_no_input),
		cmocka_unit_test_setup_teardown(keystore_read_uint32_should_succeed_with_input, setup_read_uint, teardown_read_uint),

		cmocka_unit_test(keystore_read_uint64_should_fail_on_invalid_fd),
		cmocka_unit_test_setup_teardown(keystore_read_uint64_should_fail_on_no_input, setup_no_input, teardown_no_input),
		cmocka_unit_test_setup_teardown(keystore_read_uint64_should_succeed_with_input, setup_read_uint, teardown_read_uint),

		cmocka_unit_test(keystore_read_bytes_should_fail_on_invalid_fd),
		cmocka_unit_test_setup_teardown(keystore_read_bytes_should_fail_on_no_input, setup_no_input, teardown_no_input),
		cmocka_unit_test_setup_teardown(keystore_read_bytes_should_succeed_with_input, setup_read_bytes, teardown_read_bytes),

		cmocka_unit_test(keystore_read_string_should_fail_on_invalid_fd),
		cmocka_unit_test_setup_teardown(keystore_read_string_should_fail_on_no_input, setup_no_input, teardown_no_input),
		cmocka_unit_test_setup_teardown(keystore_read_string_should_succeed_and_return_null_on_ffffffff, setup_read_string, teardown_read_string),
		cmocka_unit_test_setup_teardown(keystore_read_string_should_fail_on_input_too_short_for_size, setup_read_string, teardown_read_string),
		cmocka_unit_test_setup_teardown(keystore_read_string_should_succeed_and_return_string_on_proper_input, setup_read_string, teardown_read_string)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
