/* See LICENSE file for copyright and license details. */
#include "common.h"


char *
libar2simplified_crypt(char *msg, const char *paramstr, char *rv)
{
	struct libar2_argon2_parameters *params = NULL;
	char *end, *ret = NULL, *hash = NULL;
	size_t size;

	params = libar2simplified_decode(paramstr, NULL, &end, NULL);
	if (!params)
		goto out;
	if (*end) {
		errno = EINVAL;
		goto out;
	}

	if (!rv) {
		size = libar2_hash_buf_size(params);
		if (!size || !(hash = malloc(size))) {
			errno = ENOMEM;
			goto out;
		}
	}
	if (libar2simplified_hash(rv ? rv : hash, msg, strlen(msg), params))
		goto out;

	ret = libar2simplified_encode(params, rv ? rv : hash);
	if (rv) {
		stpcpy(rv, ret);
		free(ret);
		ret = rv;
	}

out:
	if (params)
		libar2_erase(params->salt, params->saltlen);
	free(params);
	free(hash);
	return ret;
}
