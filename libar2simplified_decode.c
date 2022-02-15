/* See LICENSE file for copyright and license details. */
#include "common.h"


union function {
	int (*func)(char *out, size_t n);
};


static int
function_wrapper(char *out, size_t n, void *function)
{
	union function *func = function;
	return func->func(out, n);
}


struct libar2_argon2_parameters *
libar2simplified_decode(const char *str, char **tagp, char **endp, int (*random_byte_generator)(char *out, size_t n))
{
	union function func;
	if (random_byte_generator) {
		func.func = random_byte_generator;
		return libar2simplified_decode_r(str, tagp, endp, function_wrapper, &func);
	} else {
		return libar2simplified_decode_r(str, tagp, endp, NULL, NULL);
	}
}
