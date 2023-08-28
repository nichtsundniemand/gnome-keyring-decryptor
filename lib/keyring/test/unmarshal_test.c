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
#include "../keyring.h"
#include "../internal/keyring.h"

void assert_keystore_attribute_empty(struct keystore_attribute *attribute) {
	assert_non_null(attribute);
	assert_null(attribute->name);
	assert_int_equal(0, attribute->type);
	assert_null(attribute->hash.string);
	assert_int_equal(0, attribute->hash.uint32);
}

void keystore_attribute_unmarshal_should_fail_on_invalid_fd() {
	error_t err = 0;
	struct keystore_attribute value = keystore_attribute_unmarshal(-1, &err);
	assert_non_null(err);
	error_free(err);
	assert_keystore_attribute_empty(&value);
}

void keystore_attribute_unmarshal_should_fail_on_no_input(void **state) {
	struct no_input_state *test_state = *state;

	error_t err = 0;
	struct keystore_attribute value = keystore_attribute_unmarshal(test_state->empty_fd, &err);
	assert_non_null(err);
	error_free(err);
	assert_keystore_attribute_empty(&value);
}

struct proper_attribute_state {
	struct keystore_attribute string_attribute;
	struct keystore_attribute uint32_attribute;
	int string_fd;
	int uint32_fd;
};

int setup_proper_attribute(void **state) {
	struct proper_attribute_state *test_state = test_malloc(sizeof(struct proper_attribute_state));
	*test_state = (struct proper_attribute_state){
		.string_attribute = {
			.name = "string_attribute",
			.type = KEYSTORE_ATTRIBUTE_TYPE_STRING,
			.hash.string = "string_value"
		},
		.uint32_attribute = {
			.name = "uint32_attribute",
			.type = KEYSTORE_ATTRIBUTE_TYPE_UINT32,
			.hash.uint32 = 42
		},
		.string_fd = memfd_create("", MFD_CLOEXEC),
		.uint32_fd = memfd_create("", MFD_CLOEXEC)
	};

	assert_int_not_equal(-1, test_state->string_fd);
	assert_int_not_equal(-1, test_state->uint32_fd);

	char string_attribute_buf[] = "\x00\x00\x00\x10"
	                              "string_attribute"
	                              "\x00\x00\x00\x00"
	                              "\x00\x00\x00\x0C"
	                              "string_value";
	assert_int_equal(sizeof(string_attribute_buf) - 1, write(test_state->string_fd, string_attribute_buf, sizeof(string_attribute_buf) - 1));
	assert_int_equal(0, lseek(test_state->string_fd, 0, SEEK_SET));

	char uint32_attribute_buf[] = "\x00\x00\x00\x10"
	                              "uint32_attribute"
	                              "\x00\x00\x00\x01"
	                              "\x00\x00\x00\x2A";
	assert_int_equal(sizeof(uint32_attribute_buf) - 1, write(test_state->uint32_fd, uint32_attribute_buf, sizeof(uint32_attribute_buf) - 1));
	assert_int_equal(0, lseek(test_state->uint32_fd, 0, SEEK_SET));

	*state = test_state;
	return 0;
}

int teardown_proper_attribute(void **state) {
	assert_non_null(*state);
	struct proper_attribute_state *test_state = *state;

	assert_int_not_equal(-1, test_state->string_fd);
	assert_int_not_equal(-1, test_state->uint32_fd);

	assert_int_equal(0, close(test_state->string_fd));
	assert_int_equal(0, close(test_state->uint32_fd));

	test_free(test_state);
	return 0;
}

void keystore_attribute_unmarshal_should_succeed_and_return_value_on_proper_input(void **state) {
	struct proper_attribute_state *test_state = *state;

	error_t err = 0;
	struct keystore_attribute string_attribute = keystore_attribute_unmarshal(test_state->string_fd, &err);
	assert_null(err);
	assert_string_equal(test_state->string_attribute.name, string_attribute.name);
	assert_int_equal(test_state->string_attribute.type, string_attribute.type);
	assert_string_equal(test_state->string_attribute.hash.string, string_attribute.hash.string);

	struct keystore_attribute uint32_attribute = keystore_attribute_unmarshal(test_state->uint32_fd, &err);
	assert_null(err);
	assert_string_equal(test_state->uint32_attribute.name, uint32_attribute.name);
	assert_int_equal(test_state->uint32_attribute.type, uint32_attribute.type);
	assert_int_equal(test_state->uint32_attribute.hash.uint32, uint32_attribute.hash.uint32);

	keystore_attribute_free(&string_attribute);
	keystore_attribute_free(&uint32_attribute);
}

void assert_keystore_keyring_item_empty(struct keystore_keyring_item *item) {
	assert_non_null(item);
	assert_int_equal(0, item->id);
	assert_int_equal(0, item->type);
	assert_int_equal(0, item->num_attributes);
	assert_null(item->attributes);
}

void keystore_keyring_item_unmarshal_should_fail_on_invalid_fd() {
	error_t err = 0;
	struct keystore_keyring_item value = keystore_keyring_item_unmarshal(-1, &err);
	assert_non_null(err);
	error_free(err);
	assert_keystore_keyring_item_empty(&value);
}

void keystore_keyring_item_unmarshal_should_fail_on_no_input(void **state) {
	struct no_input_state *test_state = *state;

	error_t err = 0;
	struct keystore_keyring_item value = keystore_keyring_item_unmarshal(test_state->empty_fd, &err);
	assert_non_null(err);
	error_free(err);
	assert_keystore_keyring_item_empty(&value);
}

struct proper_item_state {
	struct keystore_attribute attribute;
	struct keystore_keyring_item item;
	int fd;
};

int setup_proper_item(void **state) {
	struct proper_item_state *test_state = test_malloc(sizeof(struct proper_item_state));
	*test_state = (struct proper_item_state){
		.attribute = {
			.name = "uint32_attribute",
			.type = KEYSTORE_ATTRIBUTE_TYPE_UINT32,
			.hash.uint32 = 42
		},
		.item = {
			.id = 42,
			.type = 42,
			.num_attributes = 1,
			.attributes = &test_state->attribute
		},
		.fd = memfd_create("", MFD_CLOEXEC)
	};

	assert_int_not_equal(-1, test_state->fd);

	char item_buf[] = "\x00\x00\x00\x2A"
	                  "\x00\x00\x00\x2A"
	                  "\x00\x00\x00\x01"
	                  "\x00\x00\x00\x10"
	                  "uint32_attribute"
	                  "\x00\x00\x00\x01"
	                  "\x00\x00\x00\x2A";
	assert_int_equal(sizeof(item_buf) - 1, write(test_state->fd, item_buf, sizeof(item_buf) - 1));
	assert_int_equal(0, lseek(test_state->fd, 0, SEEK_SET));

	*state = test_state;
	return 0;
}

int teardown_proper_item(void **state) {
	assert_non_null(*state);
	struct proper_item_state *test_state = *state;

	assert_int_not_equal(-1, test_state->fd);
	assert_int_equal(0, close(test_state->fd));

	test_free(test_state);
	return 0;
}

void keystore_keyring_item_unmarshal_should_succeed_and_return_value_on_proper_input(void **state) {
	struct proper_item_state *test_state = *state;

	error_t err = 0;
	struct keystore_keyring_item value = keystore_keyring_item_unmarshal(test_state->fd, &err);
	assert_null(err);
	assert_int_equal(test_state->item.id, value.id);
	assert_int_equal(test_state->item.type, value.type);
	assert_int_equal(test_state->item.num_attributes, value.num_attributes);

	for(uint32_t i = 0; i < test_state->item.num_attributes; i++) {
		assert_string_equal(test_state->item.attributes[i].name, value.attributes[i].name);
		assert_int_equal(test_state->item.attributes[i].type, value.attributes[i].type);
		assert_int_equal(test_state->item.attributes[i].hash.uint32, value.attributes[i].hash.uint32);
	}

	keystore_keyring_item_free(&value);
}

void assert_keyring_version_empty(struct keyring_version *version) {
	assert_non_null(version);
	assert_int_equal(0, version->version);
	assert_int_equal(0, version->crypto);
	assert_int_equal(0, version->hash);
}

void assert_keyring_empty(struct keyring *keyring) {
	assert_non_null(keyring);
	assert_keyring_version_empty(&keyring->version);
	assert_null(keyring->name);
	assert_int_equal(0, keyring->ctime);
	assert_int_equal(0, keyring->mtime);
	assert_int_equal(0, keyring->flags);
	assert_int_equal(0, keyring->lock_timeout);
	assert_int_equal(0, keyring->hash_iterations);
	uint8_t empty_salt[8] = {0};
	assert_memory_equal(empty_salt, keyring->salt, sizeof(empty_salt));
	assert_int_equal(0, keyring->num_items);
	assert_null(keyring->items);
}

void keyring_unmarshal_should_fail_on_invalid_fd() {
	error_t err = 0;
	struct keyring value = keyring_unmarshal(-1, &err);
	assert_non_null(err);
	error_free(err);
	assert_keyring_empty(&value);
}

void keyring_unmarshal_should_fail_on_no_input(void **state) {
	struct no_input_state *test_state = *state;

	error_t err = 0;
	struct keyring value = keyring_unmarshal(test_state->empty_fd, &err);
	assert_non_null(err);
	error_free(err);
	assert_keyring_empty(&value);
}

struct proper_keyring_state {
	struct keystore_attribute attribute;
	struct keystore_keyring_item item;
	struct keyring keyring;
	int fd;
};

int setup_proper_keyring(void **state) {
	struct proper_keyring_state *test_state = test_malloc(sizeof(struct proper_keyring_state));
	*test_state = (struct proper_keyring_state){
		.attribute = {
			.name = "uint32_attribute",
			.type = KEYSTORE_ATTRIBUTE_TYPE_UINT32,
			.hash.uint32 = 42
		},
		.item = {
			.id = 42,
			.type = 42,
			.num_attributes = 1,
			.attributes = &test_state->attribute
		},
		.keyring = {
			.version.version = 1,
			.version.crypto = 1,
			.version.hash = 1,
			.name = "keyring",
			.ctime = 1,
			.mtime = 1,
			.flags = 1,
			.lock_timeout = 1,
			.hash_iterations = 1,
			.salt = {0, 1, 2, 3, 4, 5, 6, 7},
			.num_items = 1,
			.items = &test_state->item
		},
		.fd = memfd_create("", MFD_CLOEXEC)
	};

	assert_int_not_equal(-1, test_state->fd);

	char keyring_buf[] = "GnomeKeyring\n\r\0\n"
	                     "\x00\x01\x01\x01"
	                     "\x00\x00\x00\x07"
	                     "keyring"
	                     "\x00\x00\x00\x00\x00\x00\x00\x01"
	                     "\x00\x00\x00\x00\x00\x00\x00\x01"
	                     "\x00\x00\x00\x01"
	                     "\x00\x00\x00\x01"
	                     "\x00\x00\x00\x01"
	                     "\x00\x01\x02\x03\x04\x05\x06\x07"
	                     "\x00\x00\x00\x00"
	                     "\x00\x00\x00\x00"
	                     "\x00\x00\x00\x00"
	                     "\x00\x00\x00\x00"
	                     "\x00\x00\x00\x01"
	                     "\x00\x00\x00\x2A"
	                     "\x00\x00\x00\x2A"
	                     "\x00\x00\x00\x01"
	                     "\x00\x00\x00\x10"
	                     "uint32_attribute"
	                     "\x00\x00\x00\x01"
	                     "\x00\x00\x00\x2A";
	assert_int_equal(sizeof(keyring_buf) - 1, write(test_state->fd, keyring_buf, sizeof(keyring_buf) - 1));
	assert_int_equal(0, lseek(test_state->fd, 0, SEEK_SET));

	*state = test_state;
	return 0;
}

int teardown_proper_keyring(void **state) {
	assert_non_null(*state);
	struct proper_keyring_state *test_state = *state;

	assert_int_not_equal(-1, test_state->fd);
	assert_int_equal(0, close(test_state->fd));

	test_free(test_state);
	return 0;
}

void keyring_unmarshal_should_succeed_and_return_value_on_proper_input(void **state) {
	struct proper_keyring_state *test_state = *state;

	error_t err = 0;
	struct keyring value = keyring_unmarshal(test_state->fd, &err);
	assert_null(err);
	assert_int_equal(test_state->keyring.version.version, value.version.version);
	assert_int_equal(test_state->keyring.version.crypto, value.version.crypto);
	assert_int_equal(test_state->keyring.version.hash, value.version.hash);
	assert_string_equal(test_state->keyring.name, value.name);
	assert_int_equal(test_state->keyring.ctime, value.ctime);
	assert_int_equal(test_state->keyring.mtime, value.mtime);
	assert_int_equal(test_state->keyring.flags, value.flags);
	assert_int_equal(test_state->keyring.lock_timeout, value.lock_timeout);
	assert_int_equal(test_state->keyring.hash_iterations, value.hash_iterations);
	assert_memory_equal(test_state->keyring.salt, value.salt, sizeof(test_state->keyring.salt));
	assert_int_equal(test_state->keyring.num_items, value.num_items);

	for(uint32_t i = 0; i < test_state->keyring.num_items; i++) {
		assert_int_equal(test_state->keyring.items[i].id, value.items[i].id);
		assert_int_equal(test_state->keyring.items[i].type, value.items[i].type);
		assert_int_equal(test_state->keyring.items[i].num_attributes, value.items[i].num_attributes);

		for(uint32_t j = 0; j < test_state->keyring.items[i].num_attributes; j++) {
			assert_string_equal(test_state->keyring.items[i].attributes[j].name, value.items[i].attributes[j].name);
			assert_int_equal(test_state->keyring.items[i].attributes[j].type, value.items[i].attributes[j].type);
			assert_int_equal(test_state->keyring.items[i].attributes[j].hash.uint32, value.items[i].attributes[j].hash.uint32);
		}
	}

	keyring_free(&value);
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(keystore_attribute_unmarshal_should_fail_on_invalid_fd),
		cmocka_unit_test_setup_teardown(keystore_attribute_unmarshal_should_fail_on_no_input, setup_no_input, teardown_no_input),
		cmocka_unit_test_setup_teardown(keystore_attribute_unmarshal_should_succeed_and_return_value_on_proper_input, setup_proper_attribute, teardown_proper_attribute),
		cmocka_unit_test(keystore_keyring_item_unmarshal_should_fail_on_invalid_fd),
		cmocka_unit_test_setup_teardown(keystore_keyring_item_unmarshal_should_fail_on_no_input, setup_no_input, teardown_no_input),
		cmocka_unit_test_setup_teardown(keystore_keyring_item_unmarshal_should_succeed_and_return_value_on_proper_input, setup_proper_item, teardown_proper_item),
		cmocka_unit_test(keyring_unmarshal_should_fail_on_invalid_fd),
		cmocka_unit_test_setup_teardown(keyring_unmarshal_should_fail_on_no_input, setup_no_input, teardown_no_input),
		cmocka_unit_test_setup_teardown(keyring_unmarshal_should_succeed_and_return_value_on_proper_input, setup_proper_keyring, teardown_proper_keyring),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
