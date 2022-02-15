/* See LICENSE file for copyright and license details. */
#include "common.h"


int
libar2simplified_hash(void *hash, void *msg, size_t msglen, struct libar2_argon2_parameters *params)
{
	struct libar2_context ctx;
	int ret;

	libar2simplified_init_context(&ctx);
	ctx.autoerase_message = 1;

	ret = libar2_hash(hash, msg, msglen, params, &ctx);
	if (ret)
		libar2_erase(msg, msglen);
	return ret;
}
