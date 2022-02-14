/* See LICENSE file for copyright and license details. */
#include "common.h"


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
check_hash(const char *pwd_, size_t pwdlen, const char *hash, int lineno)
{
	struct libar2_argon2_parameters *params;
	char *output[512], pwd[512], *tag_expect, *tag_got, *paramstr, *hash_got;
	size_t taglen;

	from_lineno = lineno;
	errno = 0;

	assert(!!(params = libar2simplified_decode(hash, &tag_expect, NULL, NULL)));
	assert_zueq(libar2_decode_base64(tag_expect, output, &taglen), strlen(tag_expect));
	assert_zueq(taglen, params->hashlen);
	assert(!!(paramstr = libar2simplified_encode(params, output)));
	assert_streq(paramstr, hash);
	free(paramstr);

	strcpy(pwd, pwd_);
	assert(!libar2simplified_hash(output, pwd, pwdlen, params));
	tag_got = libar2simplified_encode_hash(params, output);
	free(params);
	assert_streq(tag_got, tag_expect);
	free(tag_got);

	if (strlen(pwd_) == pwdlen) { /* libar2simplified_crypt does not support NUL bytes in the password */
		strcpy(pwd, pwd_);
		hash_got = libar2simplified_crypt(pwd, hash, NULL);
		assert_streq(hash_got, hash);
		free(hash_got);
	}

	from_lineno = 0;
}


int
main(void)
{
#define CHECK(PWD, HASH)\
	check_hash(MEM(PWD), HASH, __LINE__)

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

	CHECK("password", "$argon2id$v=19$m=2048,t=16,p=16$c29tZXNhbHQ$FRWpYzcrsos+DHNInvfsl0g8mZBdPqUdarIYh/Pnc1g");

	return 0;
}
