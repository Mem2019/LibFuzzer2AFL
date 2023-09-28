#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <memory.h>
#include <assert.h>

static uint8_t* mutated_out = NULL;
static double cross_over_ratio = 0.5;

__attribute__((weak)) extern size_t LLVMFuzzerCustomMutator(
	uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed);

__attribute__((weak)) extern size_t LLVMFuzzerCustomCrossOver(
	const uint8_t *Data1, size_t Size1, const uint8_t *Data2, size_t Size2,
	uint8_t *Out, size_t MaxOutSize, unsigned int Seed);

__attribute__((weak)) extern void LLVMFuzzerMyInit(
	int (*UserCb)(const uint8_t*, size_t), unsigned int Seed);

static int dummy(const uint8_t *, size_t) { return 0; }

void* afl_custom_init(void *afl, unsigned int seed)
{
	if (LLVMFuzzerCustomMutator == NULL && LLVMFuzzerCustomCrossOver == NULL)
	{
		fprintf(stderr,
			"Both `LLVMFuzzerCustomMutator` and `LLVMFuzzerCustomCrossOver` "
			"are undefined. Please define at least one of them.\n");
		abort();
	}
	else if (LLVMFuzzerCustomMutator == NULL)
	{
		puts("`LLVMFuzzerCustomMutator` is undefined, "
			"using `LLVMFuzzerCustomCrossOver` only.");
	}
	else if (LLVMFuzzerCustomCrossOver == NULL)
	{
		puts("`LLVMFuzzerCustomCrossOver` is undefined, "
			"using `LLVMFuzzerCustomMutator` only.");
	}
	const char* s_cross_over_ratio = getenv("CROSS_OVER_RATIO");
	if (s_cross_over_ratio)
	{
		cross_over_ratio = strtod(s_cross_over_ratio, NULL);
		if (!(0 <= cross_over_ratio && cross_over_ratio <= 1))
		{
			fprintf(stderr, "Wrong CROSS_OVER_RATIO: %lf\n", cross_over_ratio);
			abort();
		}
	}
	srand(seed);
	if (LLVMFuzzerMyInit) LLVMFuzzerMyInit(dummy, seed);
	return (void*)1;
}

size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size, uint8_t **out_buf,
	uint8_t *add_buf, size_t add_buf_size, size_t max_size)
{
	mutated_out = (uint8_t*)realloc(mutated_out, max_size);
	*out_buf = mutated_out;
	assert(buf_size <= max_size && add_buf_size <= max_size);

	const bool use_cross_over = rand() < (RAND_MAX + 1.0) * cross_over_ratio;

	if (LLVMFuzzerCustomMutator == NULL ||
		// If we only have `LLVMFuzzerCustomCrossOver`, we have to use it.
		(LLVMFuzzerCustomCrossOver != NULL && use_cross_over &&
		// If we only have `LLVMFuzzerCustomMutator`, we have to use it;
		// If we have both, we use the probability to decide which to use.
			add_buf_size > 0))
			// Finally, we also must ensure the second buf exists
	{
		if (add_buf_size == 0)
		{
			// If we don't have the second buffer,
			// and we also have no LLVMFuzzerCustomMutator,
			// we clone the first buffer as the second buffer,
			// and use LLVMFuzzerCustomCrossOver.
			add_buf = (uint8_t*)malloc(buf_size);
			memcpy(add_buf, buf, buf_size);
			size_t ret = LLVMFuzzerCustomCrossOver(
				buf, buf_size, add_buf, buf_size, mutated_out, max_size, rand());
			free(add_buf);
			return ret;
		}
		return LLVMFuzzerCustomCrossOver(
			buf, buf_size, add_buf, add_buf_size, mutated_out, max_size, rand());
	}
	else
	{
		memcpy(mutated_out, buf, buf_size);
		return LLVMFuzzerCustomMutator(mutated_out, buf_size, max_size, rand());
	}
}

void afl_custom_deinit(void *data) {}