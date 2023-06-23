/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifdef __linux__
#include <sys/random.h>
#endif
#include <time.h>


static size_t
decode_u32(const char *s, uint_least32_t *outp)
{
	uint_least32_t digit;
	size_t i;

	if ((s[0] == '0' && s[1] == '0') || !isdigit(s[0])) {
		errno = EINVAL;
		return 0;
	}

	*outp = 0;
	for (i = 0; isdigit(s[i]); i++) {
		digit = (uint_least32_t)(s[i] & 15);
		if (*outp > ((uint_least32_t)0xFFFFffffUL - digit) / 10) {
			errno = ERANGE;
			return 0;
		}
		*outp = *outp * 10 + digit;
	}

	return i;
}


static int
random_salt(char *out, size_t n, int (*random_byte_generator)(char *out, size_t n, void *user_data), void *user_data)
{
#define ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	static int srand_called = 0;

	double x;
	size_t i;
	int xi;
#ifdef __linux__
	ssize_t r;
#endif

	if (random_byte_generator) {
		if (random_byte_generator(out, n, user_data))
			return -1;
	} else {
		i = 0;
#ifdef __linux__
		for (; i < n; i += (size_t)r) {
			r = getrandom(&out[i], n - i, GRND_NONBLOCK);
			if (r < 0)
				break;
		}
#endif
		if (i < n) {
			if (!srand_called) {
				srand((unsigned int)time(NULL) ^ (unsigned int)rand());
				srand_called = 1;
			}
			do {
				xi = rand();
				x = (double)xi;
				x /= (double)RAND_MAX;
				x *= 63;
				out[i] = (char)x;
			} while (++i < n);
		}
	}

	for (i = 0; i < n; i++)
		out[i] = ALPHABET[out[i] % 64];
	return 0;
}


static void *
allocate(size_t num, size_t size, size_t alignment, struct libar2_context *ctx)
{
	(void) ctx;
	(void) alignment;
	return malloc(num * size);
}


static void
deallocate(void *ptr, struct libar2_context *ctx)
{
	(void) ctx;
	free(ptr);
}


struct libar2_argon2_parameters *
libar2simplified_decode_r(const char *str, char **tagp, char **endp,
                          int (*random_byte_generator)(char *out, size_t n, void *user_data),
                          void *user_data)
{
	struct libar2_argon2_parameters params, *ret;
	const char *p = str;
	const char *end;
	char *str_free = NULL;
	char *buf = NULL;
	size_t n, saltsize, offset;
	uint_least32_t saltlen, hashlen;
	struct libar2_context ctx;

	if (*p != '$')
		goto einval;
	p = strchr(&p[1], '$');
	if (!p)
		goto einval;
	if (p[1] == 'v' && p[2] == '=') {
		p = strchr(&p[1], '$');
		if (!p)
			goto einval;
	}
	p = strchr(&p[1], '$');
	if (!p)
		goto einval;
	p++;
	end = strchr(p, '$');
	if (!end)
		goto einval;

	if (*p == '*') {
		n = decode_u32(&p[1], &saltlen);
		if (!n++)
			goto fail;
		if (&p[n] != end)
			goto einval;
		params.saltlen = (size_t)saltlen;
		saltsize = libar2_encode_base64(NULL, NULL, saltlen) - 1;
		offset = (size_t)(p - str);
		str_free = malloc(offset + saltsize + strlen(&p[n]) + 1);
		if (!str_free)
			goto enomem;
		memcpy(str_free, str, offset);
		if (random_salt(&str_free[offset], saltsize, random_byte_generator, user_data))
			goto fail;
		offset += saltsize;
		stpcpy(&str_free[offset], &p[n]);
		str = str_free;
	}
	end++;

	ctx.allocate = allocate;
	ctx.deallocate = deallocate;

	if (!libar2_decode_params(str, &params, &buf, &ctx))
		goto fail;

	if (*end == '*') {
		n = decode_u32(&end[1], &hashlen);
		if (!n++)
			goto fail;
		end = &end[n];
		params.hashlen = (size_t)hashlen;
		if (tagp)
			*tagp = NULL;
	} else {
		if (tagp)
			*tagp = *(void **)(void *)&end;
		end = &end[libar2_encode_base64(NULL, NULL, params.hashlen) - 1];
	}

	ret = malloc(sizeof(params) + params.saltlen);
	if (!ret)
		goto enomem;
	memcpy(ret, &params, sizeof(params));
	if (buf) {
		memcpy(&((char *)ret)[sizeof(params)], buf, params.saltlen);
		ret->salt = &((unsigned char *)ret)[sizeof(params)];
		deallocate(buf, &ctx);
	}

	if (endp)
		*endp = *(void **)(void *)&end;

	free(str_free);
	return ret;

einval:
	errno = EINVAL;
	return NULL;

fail:
	free(str_free);
	return NULL;

enomem:
	free(str_free);
	errno = ENOMEM;
	return NULL;
}
