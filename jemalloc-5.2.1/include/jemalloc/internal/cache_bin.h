#ifndef JEMALLOC_INTERNAL_CACHE_BIN_H
#define JEMALLOC_INTERNAL_CACHE_BIN_H

#include "jemalloc/internal/ql.h"

/*
 * The cache_bins are the mechanism that the tcache and the arena use to
 * communicate.  The tcache fills from and flushes to the arena by passing a
 * cache_bin_t to fill/flush.  When the arena needs to pull stats from the
 * tcaches associated with it, it does so by iterating over its
 * cache_bin_array_descriptor_t objects and reading out per-bin stats it
 * contains.  This makes it so that the arena need not know about the existence
 * of the tcache at all.
 */


/*
 * The count of the number of cached allocations in a bin.  We make this signed
 * so that negative numbers can encode "invalid" states (e.g. a low water mark
 * of -1 for a cache that has been depleted).
 */
typedef int32_t cache_bin_sz_t; /* bin的大小 */

typedef struct cache_bin_stats_s cache_bin_stats_t;
struct cache_bin_stats_s {
	/*
	 * Number of allocation requests that corresponded to the size of this
	 * bin.
	 */
	uint64_t nrequests; /* 分配请求的个数 */
};

/*
 * Read-only information associated with each element of tcache_t's tbins array
 * is stored separately, mainly to reduce memory usage.
 */
typedef struct cache_bin_info_s cache_bin_info_t;
struct cache_bin_info_s {
	/* Upper limit on ncached. */
	cache_bin_sz_t ncached_max; /* 上限 */
};

typedef struct cache_bin_s cache_bin_t;
struct cache_bin_s {
	/* Min # cached since last GC. */
	cache_bin_sz_t low_water; /* 低水位 */
	/* # of cached objects. */
	cache_bin_sz_t ncached; /* 已经缓存的object的数目 */
	/*
	 * ncached and stats are both modified frequently.  Let's keep them
	 * close so that they have a higher chance of being on the same
	 * cacheline, thus less write-backs.
	 */
	cache_bin_stats_t tstats;
	/*
	 * Stack of available objects.
	 *
	 * To make use of adjacent cacheline prefetch, the items in the avail
	 * stack goes to higher address for newer allocations.  avail points
	 * just above the available space, which means that
	 * avail[-ncached, ... -1] are available items and the lowest item will
	 * be allocated first.
	 */
	void **avail;
};

typedef struct cache_bin_array_descriptor_s cache_bin_array_descriptor_t;
struct cache_bin_array_descriptor_s {
	/*
	 * The arena keeps a list of the cache bins associated with it, for
	 * stats collection.
	 */
	ql_elm(cache_bin_array_descriptor_t) link; /* 链表  */
	/* Pointers to the tcache bins. */
	cache_bin_t *bins_small;
	cache_bin_t *bins_large;
};

/* cache_bin_array_descriptor的初始化 */
static inline void
cache_bin_array_descriptor_init(cache_bin_array_descriptor_t *descriptor,
    cache_bin_t *bins_small, cache_bin_t *bins_large) {
	ql_elm_new(descriptor, link);
	descriptor->bins_small = bins_small;
	descriptor->bins_large = bins_large;
}

/* 从bin中获取一个内存块
 * @param success 是否获取成功
 * @param bin
 * @return 返回指针
 */
JEMALLOC_ALWAYS_INLINE void *
cache_bin_alloc_easy(cache_bin_t *bin, bool *success) {
	void *ret;

	bin->ncached--;

	/*
	 * Check for both bin->ncached == 0 and ncached < low_water
	 * in a single branch.
	 */
	if (unlikely(bin->ncached <= bin->low_water)) {
		bin->low_water = bin->ncached;
		if (bin->ncached == -1) {
			bin->ncached = 0;
			*success = false;
			return NULL;
		}
	}

	/*
	 * success (instead of ret) should be checked upon the return of this
	 * function.  We avoid checking (ret == NULL) because there is never a
	 * null stored on the avail stack (which is unknown to the compiler),
	 * and eagerly checking ret would cause pipeline stall (waiting for the
	 * cacheline).
	 */
	*success = true;
	ret = *(bin->avail - (bin->ncached + 1));

	return ret;
}

/* 将ptr缓存到bin中
 * @param bin_info 配置信息
 */
JEMALLOC_ALWAYS_INLINE bool
cache_bin_dalloc_easy(cache_bin_t *bin, cache_bin_info_t *bin_info, void *ptr) {
	if (unlikely(bin->ncached == bin_info->ncached_max)) {
		return false;
	}
	assert(bin->ncached < bin_info->ncached_max);
	bin->ncached++;
	*(bin->avail - bin->ncached) = ptr;

	return true;
}

#endif /* JEMALLOC_INTERNAL_CACHE_BIN_H */
