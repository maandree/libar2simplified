/* See LICENSE file for copyright and license details. */
#include "common.h"
#include <pthread.h>
#include <semaphore.h>


struct user_data;

struct thread_data {
	size_t index;
	struct user_data *master;
	pthread_t thread;
	sem_t semaphore;
	int error;
	void (*function)(void *data);
	void *function_input;
};

struct user_data {
	struct thread_data *threads;
	size_t nthreads;
	pthread_mutex_t mutex;
	sem_t semaphore;
	uint_least64_t *joined;
	uint_least64_t resting[];
};


static void *
alignedalloc(size_t num, size_t size, size_t extra, size_t alignment)
{
	void *ptr;
	int err;
	if (num > (SIZE_MAX - extra) / size) {
		errno = ENOMEM;
		return NULL;
	}
	if (alignment < sizeof(void *))
		alignment = sizeof(void *);
	err = posix_memalign(&ptr, alignment, num * size + extra);
	if (err) {
		errno = err;
		return NULL;
	} else {
		return ptr;
	}
}


static void *
allocate(size_t num, size_t size, size_t alignment, struct libar2_context *ctx)
{
	size_t pad = (alignment - ((2 * sizeof(size_t)) & (alignment - 1))) & (alignment - 1);
	char *ptr = alignedalloc(num, size, pad + 2 * sizeof(size_t), alignment);
	if (ptr) {
		ptr = &ptr[pad];
		*(size_t *)ptr = pad;
		ptr = &ptr[sizeof(size_t)];
		*(size_t *)ptr = num * size;
		ptr = &ptr[sizeof(size_t)];
	}
	(void) ctx;
	return ptr;
}


static void
deallocate(void *ptr, struct libar2_context *ctx)
{
	char *p = ptr;
	p -= sizeof(size_t);
	libar2_erase(ptr, *(size_t *)p);
	p -= sizeof(size_t);
	p -= *(size_t *)p;
	free(p);
	(void) ctx;
}


static void *
thread_loop(void *data_)
{
	struct thread_data *data = data_;
	int err;

	for (;;) {
		if (sem_wait(&data->semaphore)) {
			data->error = errno;
			return NULL;
		}

		if (!data->function) {
			data->error = ENOTRECOVERABLE;
			return NULL;
		}
		data->function(data->function_input);

		err = pthread_mutex_lock(&data->master->mutex);
		if (err) {
			data->error = err;
			return NULL;
		}
		data->master->resting[data->index / 64] |= (uint_least64_t)1 << (data->index % 64);
		pthread_mutex_unlock(&data->master->mutex);
		if (sem_post(&data->master->semaphore)) {
			data->error = errno;
			return NULL;
		}
	}
}


static int
run_thread(size_t index, void (*function)(void *arg), void *arg, struct libar2_context *ctx)
{
	struct user_data *data = ctx->user_data;
	int err;

	err = pthread_mutex_lock(&data->mutex);
	if (err) {
		errno = err;
		return -1;
	}
	data->resting[index / 64] ^= (uint_least64_t)1 << (index % 64);
	pthread_mutex_unlock(&data->mutex);

	if (data->threads[index].error) {
		errno = data->threads[index].error;
		return -1;
	}

	data->threads[index].function = function;
	data->threads[index].function_input = arg;
	if (sem_post(&data->threads[index].semaphore))
		return -1;

	return 0;
}


static int
destroy_thread_pool(struct libar2_context *ctx)
{
	struct user_data *data = ctx->user_data;
	size_t i;
	int ret = 0;
	for (i = data->nthreads; i--;)
		if (run_thread(i, pthread_exit, NULL, ctx))
			return -1;
	for (i = data->nthreads; i--;) {
		pthread_join(data->threads[i].thread, NULL);
		sem_destroy(&data->threads[i].semaphore);
		if (data->threads[i].error)
			ret = data->threads[i].error;
	}
	free(data->threads);
	sem_destroy(&data->semaphore);
	pthread_mutex_destroy(&data->mutex);
	free(data);
	return ret;
}


static int
init_thread_pool(size_t desired, size_t *createdp, struct libar2_context *ctx)
{
	struct user_data *data;
	int err;
	size_t i, size;
	long int nproc, nproc_limit;
#ifdef __linux__
	char path[sizeof("/sys/devices/system/cpu/cpu") + 3 * sizeof(nproc)];
#endif
#ifdef _SC_SEM_VALUE_MAX
	long int semlimit;
#endif

	if (desired < 2) {
		*createdp = 0;
		return 0;
	}

	nproc = sysconf(_SC_NPROCESSORS_ONLN);
#ifdef __linux__
	if (nproc < 1) {
		nproc_limit = desired > LONG_MAX ? LONG_MAX : (long int)desired;
		for (nproc = 0; nproc < nproc_limit; nproc++) {
			sprintf(path, "%s%li", "/sys/devices/system/cpu/cpu", nproc);
			if (access(path, F_OK))
				break;
		}
	}
#endif
	if (nproc < 1)
		nproc = FALLBACK_NPROC;

#ifdef _SC_SEM_VALUE_MAX
	semlimit = sysconf(_SC_SEM_VALUE_MAX);
	if (semlimit >= 1 && semlimit < nproc)
		nproc = semlimit;
#endif

	if (nproc == 1) {
		*createdp = 0;
		return 0;
	}

	desired = (size_t)nproc < desired ? (size_t)nproc : desired;

	if (desired > SIZE_MAX - 63 || (desired + 63) / 64 > SIZE_MAX / sizeof(uint_least64_t) / 2) {
		errno = ENOMEM;
		return -1;
	}
	size = (desired + 63) / 64;
	size *= sizeof(uint_least64_t) * 2;
	data = alignedalloc(1, offsetof(struct user_data, resting), size, ALIGNOF(struct user_data));
	memset(data, 0, offsetof(struct user_data, resting) + size);
	data->joined = &data->resting[(desired + 63) / 64];
	ctx->user_data = data;

	*createdp = data->nthreads = desired;

	data->threads = alignedalloc(data->nthreads, sizeof(*data->threads), 0, ALIGNOF(struct thread_data));
	if (!data->threads)
		return -1;

	err = pthread_mutex_init(&data->mutex, NULL);
	if (err) {
		free(data->threads);
		return -1;
	}
	err = sem_init(&data->semaphore, 0, 0);
	if (err) {
		pthread_mutex_destroy(&data->mutex);
		free(data->threads);
		return -1;
	}

	for (i = 0; i < data->nthreads; i++) {
		memset(&data->threads[i], 0, sizeof(data->threads[i]));
		data->threads[i].master = data;
		data->threads[i].index = i;
		data->resting[i / 64] |= (uint_least64_t)1 << (i % 64);
		if (sem_init(&data->threads[i].semaphore, 0, 0)) {
			err = errno;
			goto fail_post_sem;
		}
		err = pthread_create(&data->threads[i].thread, NULL, thread_loop, &data->threads[i]);
		if (err) {
			sem_destroy(&data->threads[i].semaphore);
		fail_post_sem:
			data->nthreads = i;
			destroy_thread_pool(ctx);
			errno = err;
			return -1;
		}
	}

	return 0;
}


#if defined(__GNUC__)
__attribute__((__const__))
#endif
static size_t
lb(uint_least64_t x)
{
	size_t r = 0;
	while (x > 1) {
		x >>= 1;
		r += 1;
	}
	return r;
}

static size_t
await_threads(size_t *indices, size_t n, size_t require, struct libar2_context *ctx)
{
	struct user_data *data = ctx->user_data;
	size_t ret = 0, i;
	uint_least64_t one;
	int err;

	memset(data->joined, 0, (data->nthreads + 63) / 64 * sizeof(*data->joined));

	for (i = 0; i < data->nthreads; i += 64) {
		for (;;) {
			one = data->resting[i / 64];
			one ^= data->joined[i / 64];
			if (!one)
				break;
			one &= ~(one - 1);
			data->joined[i / 64] |= one;
			if (ret++ < n)
				indices[ret - 1] = i + lb(one);
		}
	}

	for (;;) {
		if (ret < require) {
			if (sem_wait(&data->semaphore))
				return 0;
		} else if (sem_trywait(&data->semaphore)) {
			if (errno == EAGAIN)
				break;
			else
				return 0;
		}

		err = pthread_mutex_lock(&data->mutex);
		if (err) {
			errno = err;
			return 0;
		}
		for (i = 0; i < data->nthreads; i += 64) {
			one = data->resting[i / 64];
			one ^= data->joined[i / 64];
			if (!one)
				continue;
			one &= ~(one - 1);
			data->joined[i / 64] |= one;
			if (ret++ < n)
				indices[ret - 1] = i + lb(one);
			break;
		}
		pthread_mutex_unlock(&data->mutex);
	}

	return ret;
}


static size_t
get_ready_threads(size_t *indices, size_t n, struct libar2_context *ctx)
{
	return await_threads(indices, n, 1, ctx);
}


static int
join_thread_pool(struct libar2_context *ctx)
{
	struct user_data *data = ctx->user_data;
	if (await_threads(NULL, 0, data->nthreads, ctx))
		return 0;
	destroy_thread_pool(ctx);
	return -1;
}


int
libar2simplified_hash(void *hash, void *msg, size_t msglen, struct libar2_argon2_parameters *params)
{
	struct libar2_context ctx;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.autoerase_message = 1;
	ctx.allocate = allocate;
	ctx.deallocate = deallocate;
	ctx.init_thread_pool = init_thread_pool;
	ctx.get_ready_threads = get_ready_threads;
	ctx.run_thread = run_thread;
	ctx.join_thread_pool = join_thread_pool;
	ctx.destroy_thread_pool = destroy_thread_pool;

	ret = libar2_hash(hash, msg, msglen, params, &ctx);
	if (ret)
		libar2_erase(msg, msglen);
	return ret;
}
