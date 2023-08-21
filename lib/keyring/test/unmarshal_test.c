/* Copyright 2023 Rufus Maurice Schäfing (wirklichniemand, nichtsundniemand)
 *
 * This file is part of `gnome-keyring-decryptor` and thus licensed under the terms
 * of the GNU General Public License Version 3.
 * A copy of this license can be found in the project's `LICENSE`-file.
 */

#include <stdlib.h>

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
	int err = 0;
	struct keystore_attribute value = keystore_attribute_unmarshal(-1, &err);
	assert_int_not_equal(0, err);
	assert_keystore_attribute_empty(&value);
}

void assert_keystore_keyring_item_empty(struct keystore_keyring_item *item) {
	assert_non_null(item);
	assert_int_equal(0, item->id);
	assert_int_equal(0, item->type);
	assert_int_equal(0, item->num_attributes);
	assert_null(item->attributes);
}

void keystore_keyring_item_unmarshal_should_fail_on_invalid_fd() {
	int err = 0;
	struct keystore_keyring_item value = keystore_keyring_item_unmarshal(-1, &err);
	assert_int_not_equal(0, err);
	assert_keystore_keyring_item_empty(&value);
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
	int err = 0;
	struct keyring value = keyring_unmarshal(-1, &err);
	assert_int_not_equal(0, err);
	assert_keyring_empty(&value);
}

int main() {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(keystore_attribute_unmarshal_should_fail_on_invalid_fd),
		cmocka_unit_test(keystore_keyring_item_unmarshal_should_fail_on_invalid_fd),
		cmocka_unit_test(keyring_unmarshal_should_fail_on_invalid_fd)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
