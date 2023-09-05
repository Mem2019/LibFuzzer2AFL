#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <assert.h>

static size_t CustomMutator(uint8_t *data, size_t size, size_t max_size)
{
	if (rand() % 2 == 0 && size < max_size)
	{
		data[size] = (rand() % 26) + 'A';
		return size + 1;
	}
	else
	{
		data[rand() % size] = (rand() % 26) + 'A';
		return size;
	}
}

#ifndef NO_CUSTOM_MUTATOR
size_t LLVMFuzzerCustomMutator(
	uint8_t *data, size_t size, size_t max_size, unsigned int seed)
{
	puts("LLVMFuzzerCustomMutator");
	srand(seed);
	return CustomMutator(data, size, max_size);
}
#endif // NO_CUSTOM_MUTATOR

#ifndef NO_CUSTOM_CROSS_OVER
size_t LLVMFuzzerCustomCrossOver(
	const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2,
	uint8_t *out, size_t max_out_size, unsigned int seed)
{
	puts("LLVMFuzzerCustomCrossOver");
	assert(size1 <= max_out_size && size2 <= max_out_size);
	size_t min_size = size1 < size2 ? size1 : size2;
	srand(seed);
	size_t split_idx = rand() % min_size;
	memcpy(out, data1, split_idx);
	memcpy(out + split_idx, data2 + split_idx, size2 - split_idx);
	return CustomMutator(out, size2, max_out_size);
}
#endif // NO_CUSTOM_CROSS_OVER

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size != 5)
		return 0;
	if (data[0] == 'C' && data[1] == 'R' && data[2] == 'A' &&
		data[3] == 'S' && data[4] == 'H')
		abort();
	return 0;
}
