/* See LICENSE file for copyright and license details. */
#include "common.h"
#ifdef __linux__
#include <sys/random.h>
#endif

#define SALT_ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


#define MEM(S) S, sizeof(S) - 1


#define assert(TRUTH) assert_(TRUTH, #TRUTH, __LINE__)
#define assert_streq(RESULT, EXPECT) assert_streq_(RESULT, EXPECT, #RESULT, __LINE__)
#define assert_zueq(RESULT, EXPECT) assert_zueq_(RESULT, EXPECT, #RESULT, __LINE__)

static int from_lineno = 0;


static int
nulstrcmp(const char *a, const char *b)
{
	return !a ? -!!b : !b ? +1 : strcmp(a, b);
}


static void
assert_(int truth, const char *truthstr, int lineno)
{
	if (!truth) {
		if (from_lineno)
			fprintf(stderr, "Assertion at line %i, from line %i failed: %s\n", lineno, from_lineno, truthstr);
		else
			fprintf(stderr, "Assertion at line %i failed: %s\n", lineno, truthstr);
		fprintf(stderr, "\terrno: %i (%s)\n", errno, strerror(errno));
		exit(1);
	}
}


static void
assert_streq_(const char *result, const char *expect, const char *code, int lineno)
{
	if (nulstrcmp(result, expect)) {
		if (from_lineno)
			fprintf(stderr, "Assertion at line %i, from line %i failed:\n", lineno, from_lineno);
		else
			fprintf(stderr, "Assertion at line %i failed:\n", lineno);
		fprintf(stderr, "\tcode:     %s\n", code);
		fprintf(stderr, "\tresult:   %s\n", result);
		fprintf(stderr, "\texpected: %s\n", expect);
		fprintf(stderr, "\terrno:    %i (%s)\n", errno, strerror(errno));
		exit(1);
	}
}


static void
assert_zueq_(size_t result, size_t expect, const char *code, int lineno)
{
	if (result != expect) {
		if (from_lineno)
			fprintf(stderr, "Assertion at line %i, from line %i failed:\n", lineno, from_lineno);
		else
			fprintf(stderr, "Assertion at line %i failed:\n", lineno);
		fprintf(stderr, "\tcode:     %s\n", code);
		fprintf(stderr, "\tresult:   %zu\n", result);
		fprintf(stderr, "\texpected: %zu\n", expect);
		fprintf(stderr, "\terrno:    %i (%s)\n", errno, strerror(errno));
		exit(1);
	}
}


static void
check_hash(const char *pwd, size_t pwdlen, const char *input, const char *output,
	   int (*saltgenerator)(char *out, size_t n), int lineno)
{
	struct libar2_argon2_parameters *params;
	char tag_buf[512], pwd_buf[512], *input_tag, *tag_got, *paramstr, *output_got;
	size_t taglen;

	from_lineno = lineno;
	errno = 0;

	assert(!!(params = libar2simplified_decode(input, &input_tag, NULL, saltgenerator)));
	if (input_tag) {
		assert_zueq(libar2_decode_base64(input_tag, tag_buf, &taglen), strlen(input_tag));
		assert_zueq(taglen, params->hashlen);
		assert(!!(paramstr = libar2simplified_encode(params, tag_buf)));
		assert_streq(paramstr, output);
		free(paramstr);
	}

	strcpy(pwd_buf, pwd);
	assert(!libar2simplified_hash(tag_buf, pwd_buf, pwdlen, params));
	tag_got = libar2simplified_encode_hash(params, tag_buf);
	assert_streq(tag_got, &strrchr(output, '$')[1]);
	free(tag_got);
	output_got = libar2simplified_encode(params, tag_buf);
	assert_streq(output_got, output);
	free(output_got);
	free(params);

	if (strlen(pwd) == pwdlen && !saltgenerator) {
		strcpy(pwd_buf, pwd);
		output_got = libar2simplified_crypt(pwd_buf, input, NULL);
		assert_streq(output_got, output);
		free(output_got);
	}

	from_lineno = 0;
}


#ifdef __linux__
static ssize_t getrandom_return;
static char getrandom_random0;
#endif

ssize_t
getrandom(void *buf, size_t buflen, unsigned int flags)
{
	size_t i;
	assert(flags == GRND_NONBLOCK);
	if (getrandom_return < 0)
		return getrandom_return;
	for (i = 0; i < buflen && i < (size_t)getrandom_return; i++)
		((char *)buf)[i] = (char)((size_t)getrandom_random0 + i);
	return (ssize_t)i;
}

static void
check_random_salt_generate(void)
{
	struct libar2_argon2_parameters *params[8];
	size_t i, num_equal_first;

#ifdef __linux__
	char expected_salt[8];
	const char *expected_salts[] = {
		"AAAAAAAAAAA",
		"BCBCBCBCBCB",
		"CDECDECDECD",
		"DEFGDEFGDEF",
		"EFGHIEFGHIE",
		"FGHIJKFGHIJ",
		"GHIJKLMGHIJ",
		"HIJKLMNOHIJ"
	};

	for (i = 0; i < sizeof(params) / sizeof(*params); i++) {
		getrandom_return = (ssize_t)(i + 1);
		getrandom_random0 = (char)i;
		assert(!!(params[i] = libar2simplified_decode("$argon2d$v=16$m=8,t=1,p=1$*8$*8", NULL, NULL, NULL)));
		assert_zueq(params[i]->saltlen, sizeof(expected_salt));
		libar2_decode_base64(expected_salts[i], expected_salt, &(size_t){0});
		assert(!memcmp(params[i]->salt, expected_salt, sizeof(expected_salt)));
		free(params[i]);
	}

	getrandom_return = -1;
	getrandom_random0 = 0;
#endif

	num_equal_first = 0;
	for (i = 0; i < sizeof(params) / sizeof(*params); i++) {
		assert(!!(params[i] = libar2simplified_decode("$argon2d$v=16$m=8,t=1,p=1$*8$*8", NULL, NULL, NULL)));
	}
	for (i = 1; i < sizeof(params) / sizeof(*params); i++) {
		assert_zueq(params[i]->saltlen, params[0]->saltlen);
		num_equal_first += !memcmp(params[i]->salt, params[0]->salt, params[0]->saltlen);
		free(params[i]);
	}
	free(params[0]);
	assert(num_equal_first <= (sizeof(params) / sizeof(*params) - 1) / 4);
}


static int
gensalt_ICAgICAgICA(char *out, size_t n)
{
	const char *salt = "ICAgICAgICA";
	size_t i;
	assert_zueq(n, strlen(salt));
	for (i = 0; i < n; i++)
		out[i] = (char)(strchr(SALT_ALPHABET, salt[i]) - SALT_ALPHABET);
	return 0;
}


int
main(void)
{
#define CHECK(PWD, HASH)\
	check_hash(MEM(PWD), HASH, HASH, NULL, __LINE__)

	CHECK("\x00", "$argon2d$v=16$m=8,t=1,p=1$ICAgICAgICA$Eyx1BxGazSuPQoy7osaQuo20Dw9VI97dYUOgcC3cMgw");
	CHECK("test", "$argon2i$v=19$m=4096,t=3,p=1$fn5/f35+f38$9tqKA4WMEsSAOEUwatjxvJLSqL1j0GQkgbsfnpresDw");
	CHECK("\x00", "$argon2id$v=16$m=8,t=1,p=1$ICAgICAgICA$fXq1aUbp9yhbn+EQc4AzUUE6AKnHAkvzIXsN6J4ukvE");
	CHECK("", "$argon2d$v=16$m=8,t=1,p=1$ICAgICAgICA$X54KZYxUSfMUihzebb70sKbheabHilo8gsUldrVU4IU");
	CHECK("", "$argon2d$v=16$m=8,t=1,p=1$ICAgICAgICA$NjODMrWrS7zeivNNpHsuxD9c6uDmUQ6YqPRhb8H5DSNw9n683FUCJZ3tyxgfJpYYANI+01WT/S5zp1UVs+qNRwnkdEyLKZMg+DIOXVc9z1po9ZlZG8+Gp4g5brqfza3lvkR9vw");
	CHECK("", "$argon2ds$v=16$m=8,t=1,p=1$ICAgICAgICA$zgdykk9ZjN5VyrW0LxGw8LmrJ1Z6fqSC+3jPQtn4n0s");

	CHECK("password", "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ");
	CHECK("password", "$argon2i$m=256,t=2,p=1$c29tZXNhbHQ$/U3YPXYsSb3q9XxHvc0MLxur+GP960kN9j7emXX8zwY");
	CHECK("password", "$argon2i$m=65536,t=1,p=1$c29tZXNhbHQ$gWMFUrjzsfSM2xmSxMZ4ZD1JCytetP9sSzQ4tWIXJLI");
	CHECK("password", "$argon2i$m=65536,t=4,p=1$c29tZXNhbHQ$8hLwFhXm6110c03D70Ct4tUdBSRo2MaUQKOh8sHChHs");
	CHECK("differentpassword", "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$6ckCB0tnVFMaOgvlGeW69ASzDOabPwGsO/ISKZYBCaM");
	CHECK("password", "$argon2i$m=65536,t=2,p=1$ZGlmZnNhbHQ$eaEDuQ/orvhXDLMfyLIiWXeJFvgza3vaw4kladTxxJc");

	CHECK("password", "$argon2i$v=16$m=256,t=2,p=1$c29tZXNhbHQ$/U3YPXYsSb3q9XxHvc0MLxur+GP960kN9j7emXX8zwY");

	CHECK("password", "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8");
	CHECK("password", "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$0WgHXE2YXhPr6uVgz4uUw7XYoWxRkWtvSsLaOsEbvs8");
	CHECK("differentpassword", "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$FK6NoBr+qHAMI1jc73xTWNkCEoK9iGY6RWL1n7dNIu4");

	CHECK("password", "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4");
	CHECK("password", "$argon2id$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$9qWtwbpyPd3vm1rB1GThgPzZ3/ydHL92zKL+15XZypg");
	CHECK("password", "$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$kCXUjmjvc5XMqQedpMTsOv+zyJEf5PhtGiUghW9jFyw");
	CHECK("differentpassword", "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$C4TWUs9rDEvq7w3+J4umqA32aWKB1+DSiRuBfYxFj94");

	CHECK("password", "$argon2i$m=256,t=2,p=2$c29tZXNhbHQ$tsEVYKap1h6scGt5ovl9aLRGOqOth+AMB+KwHpDFZPs");
	CHECK("password", "$argon2i$v=16$m=256,t=2,p=2$c29tZXNhbHQ$tsEVYKap1h6scGt5ovl9aLRGOqOth+AMB+KwHpDFZPs");
	CHECK("password", "$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E");
	CHECK("password", "$argon2id$v=19$m=256,t=2,p=2$c29tZXNhbHQ$bQk8UB/VmZZF4Oo79iDXuL5/0ttZwg2f/5U52iv1cDc");

	/* This hash is not well-known. It is used to test thread-support and was calculated with multi-threading disabled */
	CHECK("password", "$argon2id$v=19$m=2048,t=16,p=16$c29tZXNhbHQ$FRWpYzcrsos+DHNInvfsl0g8mZBdPqUdarIYh/Pnc1g");

#undef CHECK
#define CHECK(PWD, INPUT, SALTGEN, OUTPUT)\
	check_hash(MEM(PWD), INPUT, OUTPUT, SALTGEN, __LINE__)

	CHECK("", "$argon2d$v=16$m=8,t=1,p=1$*8$*32", gensalt_ICAgICAgICA,
	      "$argon2d$v=16$m=8,t=1,p=1$ICAgICAgICA$X54KZYxUSfMUihzebb70sKbheabHilo8gsUldrVU4IU");
	CHECK("", "$argon2d$v=16$m=8,t=1,p=1$ICAgICAgICA$*32", NULL,
	      "$argon2d$v=16$m=8,t=1,p=1$ICAgICAgICA$X54KZYxUSfMUihzebb70sKbheabHilo8gsUldrVU4IU");
	CHECK("", "$argon2d$v=16$m=8,t=1,p=1$*8$X54KZYxUSfMUihzebb70sKbheabHilo8gsUldrVU4IU", gensalt_ICAgICAgICA,
	      "$argon2d$v=16$m=8,t=1,p=1$ICAgICAgICA$X54KZYxUSfMUihzebb70sKbheabHilo8gsUldrVU4IU");
	CHECK("", "$argon2d$v=16$m=8,t=1,p=1$*8$*100", gensalt_ICAgICAgICA,
	      "$argon2d$v=16$m=8,t=1,p=1$ICAgICAgICA$"
	      "NjODMrWrS7zeivNNpHsuxD9c6uDmUQ6YqPRhb8H5DSNw9n683FUCJZ3tyxgfJpYYANI"
	      "+01WT/S5zp1UVs+qNRwnkdEyLKZMg+DIOXVc9z1po9ZlZG8+Gp4g5brqfza3lvkR9vw");

	check_random_salt_generate();

	return 0;
}
