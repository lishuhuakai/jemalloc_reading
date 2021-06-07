#define JEMALLOC_EXTENT_MMAP_C_
#include "jemalloc/internal/jemalloc_preamble.h"
#include "jemalloc/internal/jemalloc_internal_includes.h"

#include "jemalloc/internal/assert.h"
#include "jemalloc/internal/extent_mmap.h"

/* 通过mmap来向操作系统请求内存 */
/******************************************************************************/
/* Data. */

/* opt_retain表示是否回收未使用的虚拟内存,一般设置为false */
bool	opt_retain =
#ifdef JEMALLOC_RETAIN
    true
#else
    false
#endif
    ;

/******************************************************************************/
/* 当内存不够用的时候,jemalloc尝试分配内存,这里通过mmap来进行分配
 * @param new_addr 虚拟地址
 * @param size 内存块大小
 * @param alignment 对齐大小
 */
void *
extent_alloc_mmap(void *new_addr, size_t size, size_t alignment, bool *zero,
    bool *commit) {
	assert(alignment == ALIGNMENT_CEILING(alignment, PAGE));
	void *ret = pages_map(new_addr, size, alignment, commit);
	if (ret == NULL) {
		return NULL;
	}
	assert(ret != NULL);
	if (*commit) {
		*zero = true;
	}
	return ret;
}

bool
extent_dalloc_mmap(void *addr, size_t size) {
	if (!opt_retain) {
		pages_unmap(addr, size);
	}
	return opt_retain;
}
