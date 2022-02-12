/* See LICENSE file for copyright and license details. */
#include "common.h"
#include <pthread.h>
#include <semaphore.h>


struct thread_data {
	pthread_t thread;
	pthread_mutex_t mutex;
	sem_t semaphore;
	pthread_mutex_t *master_mutex;
	sem_t *master_semaphore;
	int *master_needs_a_thread;
	int error;
	void (*function)(void *data);
	void *function_input;
};

struct user_data {
	struct thread_data *threads;
	size_t nthreads;
	int need_a_thread;
	pthread_mutex_t master_mutex;
	sem_t master_semaphore;
};


static void *
alignedalloc(size_t num, size_t size, size_t alignment, size_t extra)
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
	char *ptr = alignedalloc(num, size, alignment, pad + 2 * sizeof(size_t));
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
	void (*function)(void *data);
	void *function_input;

	for (;;) {
		if (sem_wait(&data->semaphore)) {
			data->error = errno;
			return NULL;
		}

		err = pthread_mutex_lock(&data->mutex);
		if (err) {
			data->error = err;
			return NULL;
		}
		function_input = data->function_input;
		function = data->function;
		pthread_mutex_unlock(&data->mutex);

		if (function) {
			function(function_input);

			err = pthread_mutex_lock(data->master_mutex);
			if (err) {
				data->error = err;
				return NULL;
			}

			err = pthread_mutex_lock(&data->mutex);
			if (err) {
				pthread_mutex_unlock(data->master_mutex);
				data->error = err;
				return NULL;
			}
			data->function = NULL;
			data->function_input = NULL;
			pthread_mutex_unlock(&data->mutex);
			if (*data->master_needs_a_thread) {
				*data->master_needs_a_thread = 0;
				if (sem_post(data->master_semaphore)) {
					err = errno;
					pthread_mutex_unlock(data->master_mutex);
					data->error = err;
					return NULL;
				}
			}
			pthread_mutex_unlock(data->master_mutex);
		}
	}
}


static int
run_thread(size_t index, void (*function)(void *arg), void *arg, struct libar2_context *ctx)
{
	struct user_data *data = ctx->user_data;
	int err;
	err = pthread_mutex_lock(&data->threads[index].mutex);
	if (err) {
		errno = err;
		return -1;
	}
	if (data->threads[index].error) {
		err = data->threads[index].error;
		pthread_mutex_unlock(&data->threads[index].mutex);
		errno = err;
		return -1;
	}
	data->threads[index].function_input = arg;
	data->threads[index].function = function;
	if (sem_post(&data->threads[index].semaphore)) {
		return -1;
	}
	pthread_mutex_unlock(&data->threads[index].mutex);
	return 0;
}


static int
destroy_thread_pool(struct libar2_context *ctx)
{
	struct user_data *data = ctx->user_data;
	size_t i;
	int ret = 0, err;
	for (i = data->nthreads; i--;)
		if (run_thread(i, pthread_exit, NULL, ctx))
			return -1;
	for (i = data->nthreads; i--;) {
		pthread_join(data->threads[i].thread, NULL);
		err = pthread_mutex_lock(&data->threads[i].mutex);
		if (err)
			ret = err;
		sem_destroy(&data->threads[i].semaphore);
		if (data->threads[i].error)
			ret = data->threads[i].error;
		pthread_mutex_unlock(&data->threads[i].mutex);
		pthread_mutex_destroy(&data->threads[i].mutex);
	}
	free(data->threads);
	sem_destroy(&data->master_semaphore);
	pthread_mutex_destroy(&data->master_mutex);
	return ret;
}


static int
init_thread_pool(size_t desired, size_t *createdp, struct libar2_context *ctx)
{
	struct user_data *data = ctx->user_data;
	int err;
	size_t i;
	long int nproc, nproc_limit;
#ifdef __linux__
	char path[sizeof("/sys/devices/system/cpu/cpu") + 3 * sizeof(nproc)];
#endif

#ifdef TODO
	if (desired < 2) {
		*createdp = 0;
		return 0;
	}
#endif

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

	if (nproc == 1) {
		*createdp = 0;
		return 0;
	}

	data->nthreads = (size_t)nproc < desired ? (size_t)nproc : desired;
	*createdp = data->nthreads;

	data->threads = alignedalloc(data->nthreads, sizeof(*data->threads), ALIGNOF(struct thread_data), 0);
	if (!data->threads)
		return -1;

	err = pthread_mutex_init(&data->master_mutex, NULL);
	if (err) {
		free(data->threads);
		return -1;
	}
	err = sem_init(&data->master_semaphore, 0, 0);
	if (err) {
		pthread_mutex_destroy(&data->master_mutex);
		free(data->threads);
		return -1;
	}
	data->need_a_thread = 0;

	for (i = 0; i < data->nthreads; i++) {
		memset(&data->threads[i], 0, sizeof(data->threads[i]));
		data->threads[i].master_mutex = &data->master_mutex;
		data->threads[i].master_semaphore = &data->master_semaphore;
		data->threads[i].master_needs_a_thread = &data->need_a_thread;
		err = pthread_mutex_init(&data->threads[i].mutex, NULL);
		if (err)
			goto fail_post_mutex;
		if (sem_init(&data->threads[i].semaphore, 0, 0)) {
			err = errno;
			goto fail_post_cond;
		}
		err = pthread_create(&data->threads[i].thread, NULL, thread_loop, &data->threads[i]);
		if (err) {
			sem_destroy(&data->threads[i].semaphore);
		fail_post_cond:
			pthread_mutex_destroy(&data->threads[i].mutex);
		fail_post_mutex:
			data->nthreads = i;
			destroy_thread_pool(ctx);
			errno = err;
			return -1;
		}
	}

	return 0;
}


static int
set_need_a_thread(struct user_data *data, int need)
{
	int err;
	err = pthread_mutex_lock(&data->master_mutex);
	if (err) {
		errno = err;
		return -1;
	}
	data->need_a_thread = need;
	pthread_mutex_unlock(&data->master_mutex);
	return 0;
}


static int
await_some_thread(struct user_data *data)
{
	int err, need_a_thread;
	err = pthread_mutex_lock(&data->master_mutex);
	if (err) {
		errno = err;
		return -1;
	}
	need_a_thread = data->need_a_thread;
	pthread_mutex_unlock(&data->master_mutex);
	if (need_a_thread) {
		if (sem_wait(&data->master_semaphore)) {
			err = errno;
			pthread_mutex_unlock(&data->master_mutex);
			errno = err;
			return -1;
		}
	}
	return 0;
}


static size_t
await_threads(size_t *indices, size_t n, size_t require, struct libar2_context *ctx)
{
	struct user_data *data = ctx->user_data;
	size_t i, ret = 0, first = 0;
	int err;
	for (;;) {
		if (set_need_a_thread(data, 1))
			return 0;
		for (i = first; i < data->nthreads; i++) {
			err = pthread_mutex_lock(&data->threads[i].mutex);
			if (err) {
				errno = err;
				return 0;
			}
			if (!data->threads[i].function) {
				if (ret++ < n)
					indices[ret - 1] = i;
				first += (i == first);
			}
			if (data->threads[i].error) {
				errno = data->threads[i].error;
				return 0;
			}
			pthread_mutex_unlock(&data->threads[i].mutex);
		}
		if (ret >= require) {
			if (set_need_a_thread(data, 0))
				return 0;
			return ret;
		}
		if (await_some_thread(data))
			return 0;
	}
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
	return await_threads(NULL, 0, data->nthreads, ctx) ? 0 : -1;
}


int
libar2simplified_hash(void *hash, void *msg, size_t msglen, struct libar2_argon2_parameters *params)
{
	struct user_data ctx_data;
	struct libar2_context ctx;

	memset(&ctx, 0, sizeof(ctx));
	ctx.user_data = &ctx_data;
	ctx.autoerase_message = 1;
	ctx.autoerase_salt = 1;
	ctx.allocate = allocate;
	ctx.deallocate = deallocate;
	ctx.init_thread_pool = init_thread_pool;
	ctx.get_ready_threads = get_ready_threads;
	ctx.run_thread = run_thread;
	ctx.join_thread_pool = join_thread_pool;
	ctx.destroy_thread_pool = destroy_thread_pool;

	return libar2_hash(hash, msg, msglen, params, &ctx);
}
