## tsd

```c
typedef struct tsd_s tsd_t;
typedef struct tsdn_s tsdn_t;
struct tsdn_s {
	tsd_t tsd;
};

/*  O(name,			type,			nullable type */
#define MALLOC_TSD											\
    O(tcache_enabled,		bool,			bool)			\
    O(arenas_tdata_bypass,	bool,			bool)			\
    O(reentrancy_level,		int8_t,			int8_t)			\
    O(narenas_tdata,		uint32_t,		uint32_t)		\
    O(offset_state,		uint64_t,		uint64_t)			\
    O(thread_allocated,		uint64_t,		uint64_t)		\
    O(thread_deallocated,	uint64_t,		uint64_t)		\
    O(bytes_until_sample,	int64_t,		int64_t)		\
    O(prof_tdata,		prof_tdata_t *,		prof_tdata_t *)	\
    O(rtree_ctx,		rtree_ctx_t,		rtree_ctx_t)	\
    O(iarena,			arena_t *,		arena_t *)			\
    O(arena,			arena_t *,		arena_t *)			\
    O(arenas_tdata,		arena_tdata_t *,	arena_tdata_t *)\
    O(binshards,		tsd_binshards_t,	tsd_binshards_t)\
    O(tcache,			tcache_t,		tcache_t)			\
    O(witness_tsd,      witness_tsd_t,	witness_tsdn_t)		\
    MALLOC_TEST_TSD

#define TSD_MANGLE(n) cant_access_tsd_items_directly_use_a_getter_or_setter_##n

struct tsd_s {
	/*
	 * The contents should be treated as totally opaque outside the tsd
	 * module.  Access any thread-local state through the getters and
	 * setters below.
	 */

	/*
	 * We manually limit the state to just a single byte.  Unless the 8-bit
	 * atomics are unavailable (which is rare).
	 */
	tsd_state_t state;
#define O(n, t, nt)	 \
	t TSD_MANGLE(n);
MALLOC_TSD
#undef O
};
```

关于它的成员变量,我拿其中一个`tcache_enabled`举例,宏展开之后结果如下:

```c
bool cant_access_tsd_items_directly_use_a_getter_or_setter_tcache_enabled;
```

之所以弄得这么复杂,是因为jemalloc并不希望我们直接访问tsd的成员,而是要通过下面的`get`接口.

```c
#define O(n, t, nt)									\
JEMALLOC_ALWAYS_INLINE t *							\
tsd_##n##p_get_unsafe(tsd_t *tsd) {					\
	return &tsd->TSD_MANGLE(n);						\
}
MALLOC_TSD
#undef O

/* tsd_foop_get(tsd) returns a pointer to the thread-local instance of foo. */
#define O(n, t, nt)							\
JEMALLOC_ALWAYS_INLINE t *						\
tsd_##n##p_get(tsd_t *tsd) {						\
	/*								\
	 * Because the state might change asynchronously if it's	\
	 * nominal, we need to make sure that we only read it once.	\
	 */								\
	uint8_t state = tsd_state_get(tsd);				\
	assert(state == tsd_state_nominal ||				\
	    state == tsd_state_nominal_slow ||				\
	    state == tsd_state_nominal_recompute ||			\
	    state == tsd_state_reincarnated ||				\
	    state == tsd_state_minimal_initialized);			\
	return tsd_##n##p_get_unsafe(tsd);				\
}
MALLOC_TSD
#undef O
```

我们举一个例子,依然拿`tcache_nabled`举例:

```c
JEMALLOC_ALWAYS_INLINE t *					
tsd_tcache_enabledp_get_unsafe(tsd_t *tsd) {
	return &tsd->cant_access_tsd_items_directly_use_a_getter_or_setter_tcache_anebled;
}

JEMALLOC_ALWAYS_INLINE t *
tsd_tcache_enabledp_get(tsd_t *tsd) {
	uint8_t state = tsd_state_get(tsd);
	assert(state == tsd_state_nominal ||
	    state == tsd_state_nominal_slow ||
	    state == tsd_state_nominal_recompute ||
	    state == tsd_state_reincarnated ||
	    state == tsd_state_minimal_initialized);
	return tsd_tcache_enabledp_get_unsafe(tsd);
}
```

tsd中比较重要的成员:

**tsd.tcache** 当前线程的tcache

**tsd.arena** 当前线程绑定的arena

**tsd.rtree_ctx** 当前线程的rtree context,用于快速访问extent的相关信息.

## arena

```c
typedef struct arena_s arena_t;

/* 用于分配和回收extent的结构,每个用户线程会被绑定到一个arena上 */
struct arena_s {
	/*
	 * Number of threads currently assigned to this arena.  Each thread has
	 * two distinct assignments, one for application-serving allocation, and
	 * the other for internal metadata allocation.  Internal metadata must
	 * not be allocated from arenas explicitly created via the arenas.create
	 * mallctl, because the arena.<i>.reset mallctl indiscriminately
	 * discards all allocations for the affected arena.
	 *
	 *   0: Application allocation.
	 *   1: Internal metadata allocation.
	 *
	 * Synchronization: atomic.
	 */
	atomic_u_t		nthreads[2];

	/* Next bin shard for binding new threads. Synchronization: atomic. */
	atomic_u_t		binshard_next;

	/*
	 * When percpu_arena is enabled, to amortize the cost of reading /
	 * updating the current CPU id, track the most recent thread accessing
	 * this arena, and only read CPU if there is a mismatch.
	 */
	tsdn_t		*last_thd;

	/* Synchronization: internal. */
	arena_stats_t		stats; /* 统计信息 */

	/*
	 * Lists of tcaches and cache_bin_array_descriptors for extant threads
	 * associated with this arena.  Stats from these are merged
	 * incrementally, and at exit if opt_stats_print is enabled.
	 *
	 * Synchronization: tcache_ql_mtx.
	 */
	ql_head(tcache_t)			tcache_ql; /* tcache构成的链表 */
	ql_head(cache_bin_array_descriptor_t)	cache_bin_array_descriptor_ql;
	malloc_mutex_t				tcache_ql_mtx;  /* 互斥锁 */

	/* Synchronization: internal. */
	prof_accum_t		prof_accum;

	/*
	 * PRNG state for cache index randomization of large allocation base
	 * pointers.
	 *
	 * Synchronization: atomic.
	 */
	atomic_zu_t		offset_state;

	/*
	 * Extent serial number generator state.
	 *
	 * Synchronization: atomic.
	 */
	atomic_zu_t		extent_sn_next;

	/*
	 * Represents a dss_prec_t, but atomically.
	 *
	 * Synchronization: atomic.
	 */
	atomic_u_t		dss_prec;

	/*
	 * Number of pages in active extents.
	 *
	 * Synchronization: atomic.
	 */
	atomic_zu_t		nactive; /* active extents中页的个数 */

	/*
	 * Extant large allocations.
	 *
	 * Synchronization: large_mtx.
	 */
	extent_list_t		large; /* 大内存块组成的list */
	/* Synchronizes all large allocation/update/deallocation. */
	malloc_mutex_t		large_mtx;

	/*
	 * Collections of extents that were previously allocated.  These are
	 * used when allocating extents, in an attempt to re-use address space.
	 *
	 * Synchronization: internal.
	 */
	extents_t		extents_dirty; /* 刚被释放后空闲extent位于的地方 */
	extents_t		extents_muzzy; /* extents_dirty进行lazy purge后位于的地方 */
	extents_t		extents_retained;

	/*
	 * Decay-based purging state, responsible for scheduling extent state
	 * transitions.
	 *
	 * Synchronization: internal.
	 */
	arena_decay_t		decay_dirty; /* dirty --> muzzy */
	arena_decay_t		decay_muzzy; /* muzzy --> retained */

	/*
	 * Next extent size class in a growing series to use when satisfying a
	 * request via the extent hooks (only if opt_retain).  This limits the
	 * number of disjoint virtual memory ranges so that extent merging can
	 * be effective even if multiple arenas' extent allocation requests are
	 * highly interleaved.
	 *
	 * retain_grow_limit is the max allowed size ind to expand (unless the
	 * required size is greater).  Default is no limit, and controlled
	 * through mallctl only.
	 *
	 * Synchronization: extent_grow_mtx
	 */
	pszind_t		extent_grow_next;
	pszind_t		retain_grow_limit;
	malloc_mutex_t		extent_grow_mtx;

	/*
	 * Available extent structures that were allocated via
	 * base_alloc_extent().
	 *
	 * Synchronization: extent_avail_mtx.
	 */
	extent_tree_t		extent_avail;
	atomic_zu_t		extent_avail_cnt;
	malloc_mutex_t		extent_avail_mtx;

	/*
	 * bins is used to store heaps of free regions.
	 *
	 * Synchronization: internal.
	 */
	bins_t			bins[SC_NBINS];

	/*
	 * Base allocator, from which arena metadata are allocated.
	 *
	 * Synchronization: internal.
	 */
	base_t			*base; /* 用于分配元数据的base */
	/* Used to determine uptime.  Read-only after initialization. */
	nstime_t		create_time;
};
```


