/* See LICENSE file for copyright and license details. */
#include "common.h"


static size_t
encode_params(char *buf, size_t bufsize, const struct libar2_argon2_parameters *params)
{
	if (params->salt) {
		return libar2_encode_params(buf, params);
	}

	return 1 + (size_t)snprintf(buf, bufsize, "$%s$v=%i$m=%lu,t=%lu,p=%lu$*%zu$",
	                            libar2_type_to_string(params->type, LIBAR2_LOWER_CASE),
	                            (int)params->version,
	                            (unsigned long int)params->m_cost,
	                            (unsigned long int)params->t_cost,
	                            (unsigned long int)params->lanes,
	                            params->saltlen);
}


char *
libar2simplified_encode(const struct libar2_argon2_parameters *params_, void *hash)
{
	struct libar2_argon2_parameters params = *params_;
	size_t size, off;
	char *ret;

	if (libar2_validate_params(&params, NULL) != LIBAR2_OK) {
		errno = EINVAL;
		return NULL;
	}

	size = encode_params(NULL, 0, &params);
	if (hash)
		size += libar2_encode_base64(NULL, NULL, params.hashlen) - 1;
	else
		size += (size_t)snprintf(NULL, 0, "*%zu", params.hashlen);

	ret = malloc(size);
	if (!ret) {
		errno = ENOMEM;
		return NULL;
	}

	off = encode_params(ret, size, &params) - 1;
	if (off > size - 1)
		abort();

	if (hash)
		off += libar2_encode_base64(&ret[off], hash, params.hashlen) - 1;
	else
		off += (size_t)sprintf(&ret[off], "*%zu", params.hashlen);

	if (off > size - 1)
		abort();

	return ret;
}
