/* See LICENSE file for copyright and license details. */
#include "common.h"


const char *
libar2simplified_recommendation(int side_channel_free)
{
	return side_channel_free ? RECOMMENDATION_SIDE_CHANNEL_FREE_ENVIRONMENT : RECOMMENDATION_SIDE_CHANNEL_ENVIRONMENT;
}
