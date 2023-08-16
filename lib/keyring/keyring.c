/* Copyright 2023 Rufus Maurice Schäfing (wirklichniemand, nichtsundniemand)
 *
 * This file is part of `gnome-keyring-decryptor` and thus licensed under the terms
 * of the GNU General Public License Version 3.
 * A copy of this license can be found in the project's `LICENSE`-file.
 */

#include "keyring.h"
#include "internal/keyring.h"

#include <endian.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void keyring_version_marshal(struct keyring_version *version) {
	if(version == NULL) {
		return;
	}

	printf("\"version\":%hu,", version->version);
	printf("\"crypto\":%hhu,", version->crypto);
	printf("\"hash\":%hhu", version->hash);
}

void keystore_attribute_marshal(struct keystore_attribute *attribute) {
	printf("\"%s\":{", attribute->name);
	switch(attribute->type) {
		case KEYSTORE_ATTRIBUTE_TYPE_STRING:
			printf("\"type\":\"string\",");
			// Maybe implement dumping the hash-value as base64?
			printf("\"hash\":\"%s\"", attribute->hash.string);
			break;
		case KEYSTORE_ATTRIBUTE_TYPE_UINT32:
			printf("\"type\":\"uint32\",");
			printf("\"hash\":\"0x%08x\"", attribute->hash.uint32);
			break;
	}
	printf("}");
}

void keystore_attribute_free(struct keystore_attribute *attribute) {
	free(attribute->name);
	attribute->name = NULL;

	if(attribute->type == KEYSTORE_ATTRIBUTE_TYPE_STRING) {
		free(attribute->hash.string);
		attribute->hash.string = NULL;
	}
}

void keystore_keyring_item_marshal(struct keystore_keyring_item *item) {
	printf("\"id\":%u,", item->id);
	printf("\"type\":%u,", item->type);
	printf("\"attributes\":{");
	for(uint32_t i = 0; i < item->num_attributes; i++) {
		keystore_attribute_marshal(item->attributes + i);
		printf("%s", (i + 1 < item->num_attributes)?",":"");
	}
	printf("}");
}

void keystore_keyring_item_free(struct keystore_keyring_item *item) {
	for(uint32_t i = 0; i < item->num_attributes; i++) {
		keystore_attribute_free(item->attributes + i);
	}

	free(item->attributes);
	item->attributes = NULL;
}

void keyring_marshal(struct keyring *keyring) {
	if(keyring == NULL) {
		return;
	}

	printf("\"version:\":{");
	keyring_version_marshal(&keyring->version);
	printf("},");
	printf("\"name\":");
	if(keyring->name == NULL) {
		printf("null");
	} else {
		printf("\"%s\"", keyring->name);
	}
	printf(",");
	printf("\"ctime\":%lu,", keyring->ctime);
	printf("\"mtime\":%lu,", keyring->mtime);
	printf("\"flags\":%u,", keyring->flags);
	printf("\"lock_timeout\":%u,", keyring->lock_timeout);
	printf("\"hash_iterations\":%u,", keyring->hash_iterations);
	printf("\"salt\":\"%p\",", keyring->salt);
	printf("\"items\":[");
	for(uint32_t i = 0; i < keyring->num_items; i++) {
		printf("{");
		keystore_keyring_item_marshal(keyring->items + i);
		printf("}%s", (i + 1 < keyring->num_items)?",":"");
	}
	printf("]");
}

void keyring_free(struct keyring *keyring) {
	free(keyring->name);
	keyring->name = NULL;

	for(uint32_t i = 0; i < keyring->num_items; i++) {
		keystore_keyring_item_free(keyring->items + i);
	}

	free(keyring->items);
	keyring->items = NULL;
}

uint8_t keystore_read_uint8(int fd, int *err) {
	uint8_t value = 0;
	ssize_t read_size = read(fd, &value, sizeof(value));

	if(err == NULL) {
		return value;
	}

	if(read_size == -1) {
		*err = errno;
	} else if(read_size != sizeof(uint8_t)) {
		*err = 1;
	} else {
		*err = 0;
	}

	return value;
}

uint16_t keystore_read_uint16(int fd, int *err) {
	uint16_t read_buf = 0;
	ssize_t read_size = read(fd, &read_buf, sizeof(read_buf));

	uint16_t value = be16toh(read_buf);

	if(err == NULL) {
		return value;
	}

	if(read_size == -1) {
		*err = errno;
	} else if(read_size != sizeof(uint16_t)) {
		*err = 1;
	} else {
		*err = 0;
	}

	return value;
}

uint32_t keystore_read_uint32(int fd, int *err) {
	uint32_t read_buf = 0;
	ssize_t read_size = read(fd, &read_buf, sizeof(read_buf));

	uint32_t value = be32toh(read_buf);

	if(err == NULL) {
		return value;
	}

	if(read_size == -1) {
		*err = errno;
	} else if(read_size != sizeof(uint32_t)) {
		*err = 1;
	} else {
		*err = 0;
	}

	return value;
}

uint64_t keystore_read_uint64(int fd, int *err) {
	uint64_t read_buf = 0;
	ssize_t read_size = read(fd, &read_buf, sizeof(read_buf));

	uint64_t value = be64toh(read_buf);

	if(err == NULL) {
		return value;
	}

	if(read_size == -1) {
		*err = errno;
	} else if(read_size != sizeof(uint64_t)) {
		*err = 1;
	} else {
		*err = 0;
	}

	return value;
}

void keystore_read_bytes(int fd, void *buf, uint32_t size, int *err) {
	ssize_t read_size = read(fd, buf, size);

	if(err == NULL) {
		return;
	}

	if(read_size == -1) {
		*err = errno;
	} else if(read_size != size) {
		*err = 1;
	} else {
		*err = 0;
	}
}

char *keystore_read_string(int fd, int *err) {
	int size_err = 0;
	uint32_t size = keystore_read_uint32(fd, &size_err);
	if(size_err != 0) {
		if(err != NULL) {
			*err = size_err;
		}

		return NULL;
	}

	// Magic value for NULL-strings (see docs/file-format.txt)
	if(size == 0xffffffff) {
		*err = 0;
		return NULL;
	}

	// keystore-strings are not null-terminated (see docs/file-format.txt)
	char *string = malloc(size + 1);
	int string_err = 0;
	keystore_read_bytes(fd, string, size, &string_err);

	if(string_err != 0) {
		if(err != NULL) {
			*err = string_err;
		}

		free(string);
		return NULL;
	}

	string[size] = 0;

	if(err != NULL) {
		*err = 0;
	}

	return string;
}

struct keystore_attribute keystore_attribute_unmarshal(int fd, int *err) {
	int local_err = 0;
	struct keystore_attribute attribute = {0};

	attribute.name = keystore_read_string(fd, &local_err);
	if(local_err != 0) {
		goto fail;
	}

	attribute.type = keystore_read_uint32(fd, &local_err);
	if(local_err != 0) {
		goto fail;
	}

	switch(attribute.type) {
		case KEYSTORE_ATTRIBUTE_TYPE_STRING:
			attribute.hash.string = keystore_read_string(fd, &local_err);
			break;
		case KEYSTORE_ATTRIBUTE_TYPE_UINT32:
			attribute.hash.uint32 = keystore_read_uint32(fd, &local_err);
			break;
		default:
			fprintf(
				stderr, "Failed to parse attribute: Invalid attribute type (%u)\n",
				attribute.type
			);

			local_err = 1;
	}
	if(local_err != 0) {
		goto fail;
	}

	if(err != NULL) {
		*err = 0;
	}

	return attribute;

fail:
	if(err != NULL) {
		*err = local_err;
	}

	return (struct keystore_attribute){0};
}

struct keystore_keyring_item keystore_keyring_item_unmarshal(int fd, int *err) {
	int local_err = 0;
	struct keystore_keyring_item item = {0};

	item.id = keystore_read_uint32(fd, &local_err);
	if(local_err != 0) {
		goto fail;
	}

	item.type = keystore_read_uint32(fd, &local_err);
	if(local_err != 0) {
		goto fail;
	}

	item.num_attributes = keystore_read_uint32(fd, &local_err);
	if(local_err != 0) {
		goto fail;
	}

	item.attributes = malloc(item.num_attributes * sizeof(struct keystore_attribute));
	for(uint32_t i = 0; i < item.num_attributes; i++) {
		item.attributes[i] = keystore_attribute_unmarshal(fd, &local_err);

		if(local_err != 0) {
			for(uint32_t j = 0; j < i; j++) {
				keystore_attribute_free(item.attributes + j);
			}
			free(item.attributes);

			goto fail;
		}
	}

	return item;

fail:
	if(err != NULL) {
		*err = local_err;
	}

	return (struct keystore_keyring_item){0};
}

struct keyring keyring_unmarshal(int fd, int *err) {
	int local_err = 0;
	struct keyring keyring = {0};

	char signature[16] = {0};
	keystore_read_bytes(fd, signature, 16, &local_err);
	if(local_err != 0) {
		goto fail;
	}

	if(memcmp("GnomeKeyring\n\r\0\n", signature, 16) != 0) {
		local_err = 2;
		goto fail;
	}

	keyring.version.version = keystore_read_uint16(fd, &local_err);
	if(local_err != 0) {
		goto fail;
	}

	keyring.version.crypto = keystore_read_uint8(fd, &local_err);
	if(local_err != 0) {
		goto fail;
	}

	keyring.version.hash = keystore_read_uint8(fd, &local_err);
	if(local_err != 0) {
		goto fail;
	}

	keyring.name = keystore_read_string(fd, &local_err);
	if(local_err != 0) {
		goto fail;
	}

	keyring.ctime = keystore_read_uint64(fd, &local_err);
	if(local_err != 0) {
		goto fail_name;
	}

	keyring.mtime = keystore_read_uint64(fd, &local_err);
	if(local_err != 0) {
		goto fail_name;
	}

	keyring.flags = keystore_read_uint32(fd, &local_err);
	if(local_err != 0) {
		goto fail_name;
	}

	keyring.lock_timeout = keystore_read_uint32(fd, &local_err);
	if(local_err != 0) {
		goto fail_name;
	}

	keyring.hash_iterations = keystore_read_uint32(fd, &local_err);
	if(local_err != 0) {
		goto fail_name;
	}

	keystore_read_bytes(fd, keyring.salt, 8, &local_err);
	if(local_err != 0) {
		goto fail_name;
	}

	// Skip reserved bytes
	for(int i = 0; i < 4; i++) {
		keystore_read_uint32(fd, &local_err);

		if(local_err != 0) {
			goto fail_name;
		}
	}

	keyring.num_items = keystore_read_uint32(fd, &local_err);
	if(local_err != 0) {
		goto fail_name;
	}

	keyring.items = malloc(keyring.num_items * sizeof(struct keystore_keyring_item));
	for(uint32_t i = 0; i < keyring.num_items; i++) {
		keyring.items[i] = keystore_keyring_item_unmarshal(fd, &local_err);

		if(local_err != 0) {
			for(uint32_t j = 0; j < i; j++) {
				keystore_keyring_item_free(keyring.items + j);
			}
			free(keyring.items);

			goto fail_name;
		}
	}

	return keyring;

fail_name:
	free(keyring.name);
fail:
	if(err != NULL) {
		*err = local_err;
	}

	return (struct keyring){0};
}
