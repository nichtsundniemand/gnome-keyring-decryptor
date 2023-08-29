/* Copyright 2023 Rufus Maurice Schäfing (wirklichniemand, nichtsundniemand)
 *
 * This file is part of `gnome-keyring-decryptor` and thus licensed under the terms
 * of the GNU General Public License Version 3.
 * A copy of this license can be found in the project's `LICENSE`-file.
 */

#ifndef KEYRING_INTERNAL_H
#define KEYRING_INTERNAL_H

#include <stdint.h>

#include "../error.h"

uint8_t keystore_read_uint8(int fd, error_t *err);
uint16_t keystore_read_uint16(int fd, error_t *err);
uint32_t keystore_read_uint32(int fd, error_t *err);
uint64_t keystore_read_uint64(int fd, error_t *err);
void keystore_read_bytes(int fd, void *buf, uint32_t size, error_t *err);
char *keystore_read_string(int fd, error_t *err);

enum keystore_attribute_type {
	KEYSTORE_ATTRIBUTE_TYPE_STRING,
	KEYSTORE_ATTRIBUTE_TYPE_UINT32
};

struct keystore_attribute {
	char *name;
	enum keystore_attribute_type type;
	union {
		char *string;
		uint32_t uint32;
	} hash;
};

struct keystore_attribute keystore_attribute_unmarshal(int fd, error_t *err);
void keystore_attribute_marshal(struct keystore_attribute *attribute);
void keystore_attribute_free(struct keystore_attribute *attribute);

struct keystore_keyring_item {
	uint32_t id;
	uint32_t type;
	uint32_t num_attributes;
	struct keystore_attribute *attributes;
};

struct keystore_keyring_item keystore_keyring_item_unmarshal(int fd, error_t *err);
void keystore_keyring_item_marshal(struct keystore_keyring_item *item);
void keystore_keyring_item_free(struct keystore_keyring_item *item);

#endif
