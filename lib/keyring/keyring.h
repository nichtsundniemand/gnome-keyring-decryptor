/* Copyright 2023 Rufus Maurice Schäfing (wirklichniemand, nichtsundniemand)
 *
 * This file is part of `gnome-keyring-decryptor` and thus licensed under the terms
 * of the GNU General Public License Version 3.
 * A copy of this license can be found in the project's `LICENSE`-file.
 */

#ifndef KEYRING_H
#define KEYRING_H

#include <stdint.h>

struct keyring_version {
	uint16_t version;
	uint8_t  crypto;
	uint8_t  hash;
};

struct keyring {
	struct keyring_version version;
	char     *name;
	uint64_t ctime;
	uint64_t mtime;
	uint32_t flags;
	uint32_t lock_timeout;
	uint32_t hash_iterations;
	uint8_t  salt[8];
	uint32_t num_items;
	struct keystore_keyring_item *items;
};

struct keyring keyring_unmarshal(int fd, int *err);
void keyring_marshal(struct keyring *keyring);
void keyring_free(struct keyring *keyring);

#endif
