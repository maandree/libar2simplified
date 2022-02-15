/* See LICENSE file for copyright and license details. */
#include "libar2simplified.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libar2.h>


#ifndef ALIGNOF
# ifdef __STDC_VERSION__
#  if __STDC_VERSION__ >= 201112L
#   define ALIGNOF(X) _Alignof(X)
#  endif
# endif
#endif
#ifndef ALIGNOF
# ifdef __GNUC__
#   define ALIGNOF(X) __alignof__(X)
# else
#   define ALIGNOF(X) sizeof(X)
# endif
#endif


#ifndef FALLBACK_NPROC
# define FALLBACK_NPROC 4
#endif


#ifndef RECOMMENDATION_SIDE_CHANNEL_ENVIRONMENT
# define RECOMMENDATION_SIDE_CHANNEL_ENVIRONMENT "$argon2id$v=19$m=3072,t=32,p=4$*16$*48"
#endif
#ifndef RECOMMENDATION_SIDE_CHANNEL_FREE_ENVIRONMENT
# define RECOMMENDATION_SIDE_CHANNEL_FREE_ENVIRONMENT "$argon2d$v=19$m=3072,t=32,p=4$*16$*48"
#endif
