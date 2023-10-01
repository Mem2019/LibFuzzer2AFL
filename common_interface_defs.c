/* The file is a dummy implementation for functions in common_interface_defs.h
	to prevent link error. llvmorg-17.0.1 is used as the reference. */

#include <stddef.h>
#include <stdint.h>

#define ATTR_WEAK __attribute__((weak))

ATTR_WEAK void __sanitizer_set_report_path(const char *path) {}
ATTR_WEAK void __sanitizer_set_report_fd(void *fd) {}
ATTR_WEAK const char *__sanitizer_get_report_path() { return NULL; }
ATTR_WEAK void __sanitizer_sandbox_on_notify(void *args) {}
ATTR_WEAK void __sanitizer_report_error_summary(const char *error_summary) {}
ATTR_WEAK int __sanitizer_acquire_crash_state()
{
	static int next = 1;
	const int ret = next;
	next = 0;
	return ret;
}
ATTR_WEAK void __sanitizer_annotate_contiguous_container(
	const void *beg, const void *end, const void *old_mid, const void *new_mid) {}
ATTR_WEAK void __sanitizer_annotate_double_ended_contiguous_container(
	const void *storage_beg, const void *storage_end,
	const void *old_container_beg, const void *old_container_end,
	const void *new_container_beg, const void *new_container_end) {}
ATTR_WEAK int __sanitizer_verify_contiguous_container(
	const void *beg, const void *mid, const void *end) { return 1; }
ATTR_WEAK int __sanitizer_verify_double_ended_contiguous_container(
	const void *storage_beg, const void *container_beg,
	const void *container_end, const void *storage_end) { return 1; }
ATTR_WEAK const void *__sanitizer_contiguous_container_find_bad_address(
	const void *beg, const void *mid, const void *end) { return NULL; }
ATTR_WEAK const void *__sanitizer_double_ended_contiguous_container_find_bad_address(
	const void *storage_beg, const void *container_beg,
	const void *container_end, const void *storage_end) { return NULL; }
ATTR_WEAK void __sanitizer_print_stack_trace(void) {}
ATTR_WEAK void __sanitizer_symbolize_pc(
	void *pc, const char *fmt, char *out_buf, size_t out_buf_size) {}
ATTR_WEAK void __sanitizer_symbolize_global(
	void *data_ptr, const char *fmt, char *out_buf, size_t out_buf_size) {}
ATTR_WEAK void __sanitizer_set_death_callback(void (*callback)(void)) {}
ATTR_WEAK void __sanitizer_print_memory_profile(
	size_t top_percent, size_t max_number_of_contexts) {}
ATTR_WEAK void __sanitizer_start_switch_fiber(
	void **fake_stack_save, const void *bottom, size_t size) {}
ATTR_WEAK void __sanitizer_finish_switch_fiber(
	void *fake_stack_save, const void **bottom_old, size_t *size_old) {}
ATTR_WEAK int __sanitizer_get_module_and_offset_for_pc(
	void *pc, char *module_path, size_t module_path_len, void **pc_offset)
{
	return 0;
}