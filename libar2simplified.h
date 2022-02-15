/* See LICENSE file for copyright and license details. */
#ifndef LIBAR2SIMPLIFIED_H
#define LIBAR2SIMPLIFIED_H

#include <libar2.h>

/* These are useful when the database stores parameters and
 * hash separately, when the application uses a pepper, or
 * when composing multiple hash functions: */

/**
 * Encode hashing parameters, with or without hashing result
 * 
 * This function extends the standard format for Argon2 by
 * letting the exact salt or tag (hash) be unspecified, but
 * the length specified using an asterisk-prefixed, decimal
 * integer
 * 
 * `params->key` and `params->ad` will not be included in
 * the returned string
 * 
 * @param   params  The hashing parameters, if `params->salt`
 *                  is `NULL` the salt's length is encoded
 *                  instead of an actual salt
 * @param   hash    The tag, or `NULL` the tag's length is
 *                  encoded instead of an actual tag
 * @return          The hashing parameter string,
 *                  or `NULL` on failure; shall be dellocated
 *                  using free(3) when no longer needed
 */
LIBAR2_PUBLIC__ LIBAR2_NONNULL__(1)
char *libar2simplified_encode(const struct libar2_argon2_parameters *params, void *hash);

/**
 * Encode tag (hashing result) without parameters
 * 
 * @param   params  The hashing parameters (used to get the tag length)
 * @param   hash    The binary tag (hashing result)
 * @return          `hash` encoded with base64, or `NULL`
 *                  on failure; shall be dellocated using
 *                  free(3) when no longer needed
 */
LIBAR2_PUBLIC__ LIBAR2_NONNULL__(1, 2)
char *libar2simplified_encode_hash(const struct libar2_argon2_parameters *params, void *hash);

/**
 * Decode hashing parameters
 * 
 * If the salt's lengths is encoded, but not an
 * actual salt, a random salt will be created
 * 
 * The hashing string does not encode information
 * about `params->key` or `params->ad`, therefore
 * `params->key` and `params->ad` will be set to
 * `NULL` and `params->keylen` and `params->adlen`
 * will be set to 0
 * 
 * @param   str                    The hashing parameter string to decode
 * @param   tagp                   Output parameter for the tag (hash result), or `NULL`.
 *                                 Unless `NULL`, `NULL` will be stored in `*tagp` if `str`
 *                                 includes a tag length instead of an actual tag, otherwise
 *                                 unless `NULL`, the beginning of the tag, in `str`, will
 *                                 be stored in `*tagp`. `*endp` will (unless `endp` or
 *                                 `*tagp` is `NULL`) mark the end of the tag.
 * @param   endp                   Output parameter for the end of the hashing parameter
 *                                 string, or `NULL`. Unless `NULL`, one position beyond the
 *                                 last byte in `str` determined to be part of the hashing
 *                                 parameter string will be stored in `*endp`. The application
 *                                 shall make sure that `**endp` is a valid termination of
 *                                 the hashing parameter string; typically this would be a ':'
 *                                 or a NUL byte.
 * @param   random_byte_generator  Random number generator function, used to generate salt if
 *                                 `str` does not contain one. The function shall output `n`
 *                                 random bytes (only the lower 6 bits in each byte need to
 *                                 be random) to `out` and return 0. On failure, the function
 *                                 shall return -1. If `NULL`, the function will use a random
 *                                 number generator provided by the C standard library or the
 *                                 operating system.
 * @return                         Decoded hashing parameters. Shall be deallocated using
 *                                 free(3) when no longer needed. Be aware than the allocation
 *                                 size of the returned object will exceed the size of the
 *                                 return type.
 */
LIBAR2_PUBLIC__ LIBAR2_NONNULL__(1)
struct libar2_argon2_parameters *
libar2simplified_decode(const char *str, char **tagp, char **endp, int (*random_byte_generator)(char *out, size_t n));

/**
 * Calculate a password hash
 * 
 * @param   hash    Output parameter for the tag (hash result).
 *                  This must be a buffer than is at least
 *                  `libar2_hash_buf_size(params)` bytes large.
 * @param   msg     The message (password) to hash. Will be
 *                  erased (not deallocated) some time before
 *                  the function returns.
 * @param   msglen  The number of bytes in `msg`
 * @param   params  Hashing parameters
 * @return          0 on success, -1 on failure
 */
LIBAR2_PUBLIC__ LIBAR2_NONNULL__(1, 4)
int libar2simplified_hash(void *hash, void *msg, size_t msglen, struct libar2_argon2_parameters *params);

/* This one is useful you just want to do it crypt(3)-style: */

/**
 * Calculate a password hash
 * 
 * This function works like crypt(3), except that it only supports
 * Argon2, it will erase the input password, the return buffer is
 * provided in the third parameter or (if `NULL`) is dynamically
 * allocated, and it will generate a salt if one is not provided
 * 
 * Assumming `params` contains a salt and a tag (hash), `msg`
 * is (in all likelyhood) the password it was created with if
 * the returned string is identical to `params`. It is
 * recommended, to hinder timing attack, that this check is done
 * by comparing all characters in the strings, even if a mismatch
 * is found early.
 * 
 * This function is generally not recommend. It should only be
 * used for /etc/shadow and similar files. Other applications should
 * use `libar2simplified_hash` and provide an application-specific,
 * random, pepper. Applications are also recommended to use
 * `libar2simplified_hash` so that they can compose password hashing
 * functions and automatically harden passwords, without knowing
 * their plain-text, when the hashing configuration is determined
 * to be too weak.
 * 
 * @param   msg     The password to hash. NB! Will be erased (not
 *                  deallocated) some time before the function returns.
 * @param   params  Hashing parameter string
 * @param   rv      Output parameter for the hasing, or `NULL`.
 *                  Unless `NULL`, this must be a buffer than is at least
 *                  `libar2_hash_buf_size(libar2simplified_decode(params,
 *                  NULL, NULL, NULL))` bytes large.
 * @return          The hashing result, including hashing parameters.
 *                  `NULL` on failure. On success, `rv` is returned
 *                  unless `rv` is `NULL`. If `rv` is `NULL`, the
 *                  returned shall be deallocated using free(3) when
 *                  it is no longer needed
 */
LIBAR2_PUBLIC__ LIBAR2_NONNULL__(1, 2)
char *libar2simplified_crypt(char *msg, const char *params, char *rv);

#endif
