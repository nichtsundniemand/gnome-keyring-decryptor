/* Copyright 2023 Rufus Maurice Schäfing (wirklichniemand, nichtsundniemand)
 *
 * This file is part of `gnome-keyring-decryptor` and thus licensed under the terms
 * of the GNU General Public License Version 3.
 * A copy of this license can be found in the project's `LICENSE`-file.
 */

#include "error.h"

#include <stdlib.h>
#include <string.h>

struct error {
	enum error_type type;
	char *file;
	char *function;
	unsigned int line;
	struct error *prev;
	char *error_string;
	char *(*format)(struct error *error);
	void (*free)(struct error *error);
};

char *error_format(struct error *error) {
	return error->format(error);
}

void error_free(struct error *error) {
	if(error->prev != NULL) {
		error_free(error->prev);
		error->prev = NULL;
	}

	error->free(error);
	free(error);
}

struct error_errno {
	struct error base;
	int number;
};

static char *error_errno_format_impl(struct error *error) {
	if(error->type != ERROR_TYPE_ERRNO) {
		return NULL;
	}

	struct error_errno *error_errno = (struct error_errno *)error;
	error = NULL;

	if(error_errno->base.error_string == NULL) {
		error_errno->base.error_string = strerror(error_errno->number);
	}

	return error_errno->base.error_string;
}

static void error_errno_free_impl(struct error *error) {
	// Nothing internal to free
	(void)error;
	return;
}

struct error *error_errno_new(const char *file, const char *function, const unsigned int line, struct error *prev, int number) {
	struct error_errno *err = malloc(sizeof(struct error_errno));
	*err = (struct error_errno){
		.base = {
			.type = ERROR_TYPE_ERRNO,
			.file = file,
			.function = function,
			.line = line,
			.prev = prev,
			.error_string = NULL,
			.format = error_errno_format_impl,
			.free = error_errno_free_impl
		},
		.number = number
	};

	return (struct error *)err;
}

struct error_read {
	struct error base;
	enum error_read_type type;
};

static char *error_read_format_impl(struct error *error) {
	if(error->type != ERROR_TYPE_READ) {
		return NULL;
	}

	struct error_read *error_read = (struct error_read *)error;
	error = NULL;

	if(error_read->base.error_string == NULL) {
		switch(error_read->type) {
			case ERROR_READ_TYPE_CHILD_ERROR:
				error_read->base.error_string = "child read failed";
				break;
			case ERROR_READ_TYPE_EOF:
				error_read->base.error_string = "unexpected end of file";
				break;
		}
	}

	return error_read->base.error_string;
}

static void error_read_free_impl(struct error *error) {
	// Nothing internal to free
	(void)error;
	return;
}

struct error *error_read_new(const char *file, const char *function, const unsigned int line, error_t prev, enum error_read_type type) {
	struct error_read *err = malloc(sizeof(struct error_read));
	*err = (struct error_read){
		.base = {
			.type = ERROR_TYPE_READ,
			.file = file,
			.function = function,
			.line = line,
			.prev = prev,
			.error_string = NULL,
			.format = error_read_format_impl,
			.free = error_read_free_impl
		},
		.type = type
	};

	return (struct error *)err;
}

struct error_unmarshal {
	struct error base;
	enum error_unmarshal_type type;
};

static char *error_unmarshal_format_impl(struct error *error) {
	if(error->type != ERROR_TYPE_UNMARSHAL) {
		return NULL;
	}

	struct error_unmarshal *error_unmarshal = (struct error_unmarshal *)error;
	error = NULL;

	if(error_unmarshal->base.error_string == NULL) {
		switch(error_unmarshal->type) {
			case ERROR_UNMARSHAL_TYPE_READ_ERROR:
				error_unmarshal->base.error_string = "failed to read value";
				break;
			case ERROR_UNMARSHAL_TYPE_CHILD_ERROR:
				error_unmarshal->base.error_string = "failed to unmarshal child";
				break;
			case ERROR_UNMARSHAL_TYPE_SIGNATURE_MISMATCH:
				error_unmarshal->base.error_string = "signature mismatch";
				break;
			case ERROR_UNMARSHAL_TYPE_INVALID_ATTRIBUTE_TYPE:
				error_unmarshal->base.error_string = "invalid attribute_type";
				break;
		}
	}

	return error_unmarshal->base.error_string;
}

static void error_unmarshal_free_impl(struct error *error) {
	// Nothing internal to free
	(void)error;
	return;
}

struct error *error_unmarshal_new(const char *file, const char *function, const unsigned int line, error_t prev, enum error_unmarshal_type type) {
	struct error_unmarshal *err = malloc(sizeof(struct error_unmarshal));
	*err = (struct error_unmarshal){
		.base = {
			.type = ERROR_TYPE_UNMARSHAL,
			.file = file,
			.function = function,
			.line = line,
			.prev = prev,
			.error_string = NULL,
			.format = error_unmarshal_format_impl,
			.free = error_unmarshal_free_impl
		},
		.type = type
	};

	return (struct error *)err;
}
