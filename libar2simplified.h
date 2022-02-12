/* See LICENSE file for copyright and license details. */
#ifndef LIBAR2SIMPLIFIED_H
#define LIBAR2SIMPLIFIED_H

#include <libar2.h>

LIBAR2_PUBLIC__ LIBAR2_NONNULL__(1)
char *libar2simplified_encode(const struct libar2_argon2_parameters *params, void *hash);

LIBAR2_PUBLIC__ LIBAR2_NONNULL__(1, 2)
char *libar2simplified_encode_hash(const struct libar2_argon2_parameters *params, void *hash);

LIBAR2_PUBLIC__ LIBAR2_NONNULL__(1)
struct libar2_argon2_parameters *
libar2simplified_decode(const char *str, char **tagp, char **endp, int (*random_byte_generator)(char *out, size_t n));

LIBAR2_PUBLIC__ LIBAR2_NONNULL__(1, 4)
int libar2simplified_hash(void *hash, void *msg, size_t msglen, struct libar2_argon2_parameters *params);

#endif
