/* See LICENSE file for copyright and license details. */
#include "common.h"


char *
libar2simplified_encode_hash(const struct libar2_argon2_parameters *params, void *hash)
{
	size_t size = libar2_encode_base64(NULL, hash, params->hashlen);
	char *ret = malloc(size);
	if (!ret) {
		errno = ENOMEM;
		return NULL;
	}
	if (libar2_encode_base64(ret, hash, params->hashlen) != size)
		abort();
	return ret;
}
