/* Copyright 2023 Rufus Maurice Schäfing (wirklichniemand, nichtsundniemand)
 *
 * This file is part of `gnome-keyring-decryptor` and thus licensed under the terms
 * of the GNU General Public License Version 3.
 * A copy of this license can be found in the project's `LICENSE`-file.
 */

#ifndef ERROR_H
#define ERROR_H

enum error_type {
	ERROR_TYPE_NONE,
	ERROR_TYPE_ERRNO,
	ERROR_TYPE_READ,
	ERROR_TYPE_UNMARSHAL
};

struct error;
typedef struct error *error_t;

char *error_format(error_t err);
void error_trace(error_t err);
void error_free(error_t err);

error_t error_errno_new(const char *file, const char *function, const unsigned int line, error_t prev, int number);
#define error_errno_make(prev, number) error_errno_new(__FILE__, __func__, __LINE__, prev, number)

enum error_read_type {
	ERROR_READ_TYPE_CHILD_ERROR,
	ERROR_READ_TYPE_EOF
};
error_t error_read_new(const char *file, const char *function, const unsigned int line, error_t prev, enum error_read_type type);
#define error_read_make(prev, type) error_read_new(__FILE__, __func__, __LINE__, prev, type)

enum error_unmarshal_type {
	ERROR_UNMARSHAL_TYPE_READ_ERROR,
	ERROR_UNMARSHAL_TYPE_CHILD_ERROR,
	ERROR_UNMARSHAL_TYPE_SIGNATURE_MISMATCH,
	ERROR_UNMARSHAL_TYPE_INVALID_ATTRIBUTE_TYPE
};
error_t error_unmarshal_new(const char *file, const char *function, const unsigned int line, error_t prev, enum error_unmarshal_type type);
#define error_unmarshal_make(prev, type) error_unmarshal_new(__FILE__, __func__, __LINE__, prev, type)

#endif
