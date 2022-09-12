# 1. 结构体的定义



```c
/* Embedded at the beginning of every block of base-managed virtual memory. */
struct base_block_s {
	/* Total size of block's virtual memory mapping. */
	size_t		size; /* 虚拟内存映射块的大小 */

	/* Next block in list of base's blocks. */
	base_block_t	*next;  /* 下一个block */

	/* Tracks unused trailing space. */
	extent_t	extent;
};

struct base_s {
	/* Associated arena's index within the arenas array. */
	unsigned	ind;  /* 此结构关联的arena在arenas数组中的下标 */
	/*
	 * User-configurable extent hook functions.  Points to an
	 * extent_hooks_t.
	 */
	atomic_p_t	extent_hooks; /* 一般为&extent_hooks_default */

	/* Protects base_alloc() and base_stats_get() operations. */
	malloc_mutex_t	mtx;

	/* Using THP when true (metadata_thp auto mode). */
	bool		auto_thp_switched;
	/*
	 * Most recent size class in the series of increasingly large base
	 * extents.  Logarithmic spacing between subsequent allocations ensures
	 * that the total number of distinct mappings remains small.
	 */
	pszind_t	pind_last;

	/* Serial number generation state. */
	size_t		extent_sn_next;

	/* Chain of all blocks associated with base. */
	base_block_t	*blocks; /* block链表 */

	/* Heap of extents that track unused trailing space within blocks. */
	extent_heap_t	avail[SC_NSIZES];
	// ...
};

typedef struct base_block_s base_block_t;
typedef struct base_s base_t;
```





# 2. 相关函数

## 2.1 base创建

`jemalloc`在初始化的时候,会创建一个`b0`的`base`分配器.

```c
static base_t *b0; /* 实际上,每一个arena都对应一个base实例,b0是arena0的base */
bool
base_boot(tsdn_t *tsdn) {
	b0 = base_new(tsdn, 0, (extent_hooks_t *)&extent_hooks_default);
	return (b0 == NULL);
}
```

除此之外,每一个`arena`都会创建一个`base`分配器,可以调用接口`base_new`来创建:

```c
/* 创建一个新的base结构 */
base_t *
base_new(tsdn_t *tsdn, unsigned ind, extent_hooks_t *extent_hooks) {
	pszind_t pind_last = 0;
	size_t extent_sn_next = 0;
    /* 首先创建一个base_block结构 */
	base_block_t *block = base_block_alloc(tsdn, NULL, extent_hooks, ind,
	    &pind_last, &extent_sn_next, sizeof(base_t), QUANTUM);
	if (block == NULL) {
		return NULL;
	}

	size_t gap_size;
	size_t base_alignment = CACHELINE;
	size_t base_size = ALIGNMENT_CEILING(sizeof(base_t), base_alignment);
    /* 从base_block结构中分配一个base */
	base_t *base = (base_t *)base_extent_bump_alloc_helper(&block->extent,
	    &gap_size, base_size, base_alignment);
	base->ind = ind;
	atomic_store_p(&base->extent_hooks, extent_hooks, ATOMIC_RELAXED);
	if (malloc_mutex_init(&base->mtx, "base", WITNESS_RANK_BASE,
	    malloc_mutex_rank_exclusive)) {
		base_unmap(tsdn, extent_hooks, ind, block, block->size);
		return NULL;
	}
	base->pind_last = pind_last;
	base->extent_sn_next = extent_sn_next;
	base->blocks = block;
	base->auto_thp_switched = false;
	for (szind_t i = 0; i < SC_NSIZES; i++) {
		extent_heap_new(&base->avail[i]);
	}
    /* 将base_block->extent和base联系起来 */
	base_extent_bump_alloc_post(base, &block->extent, gap_size, base, base_size);
	return base;
}
```



```c
/*
 * Allocate a block of virtual memory that is large enough to start with a
 * base_block_t header, followed by an object of specified size and alignment.
 * On success a pointer to the initialized base_block_t header is returned.
 */
/* 分配base_block
 * @param size 内存块大小
 * @param alignment 对齐
 */
static base_block_t *
base_block_alloc(tsdn_t *tsdn, base_t *base, extent_hooks_t *extent_hooks,
    unsigned ind, pszind_t *pind_last, size_t *extent_sn_next, size_t size,
    size_t alignment) {
	alignment = ALIGNMENT_CEILING(alignment, QUANTUM);
	size_t usize = ALIGNMENT_CEILING(size, alignment); /* 对齐后的大小 */
	size_t header_size = sizeof(base_block_t); /* 元数据,头部大小 */
	size_t gap_size = ALIGNMENT_CEILING(header_size, alignment) - header_size;
	/*
	 * Create increasingly larger blocks in order to limit the total number
	 * of disjoint virtual memory ranges.  Choose the next size in the page
	 * size class series (skipping size classes that are not a multiple of
	 * HUGEPAGE), or a size large enough to satisfy the requested size and
	 * alignment, whichever is larger.
	 */
	size_t min_block_size = HUGEPAGE_CEILING(sz_psz2u(header_size + gap_size
	    + usize)); /* 至少要分配这么多字节 */
	pszind_t pind_next = (*pind_last + 1 < sz_psz2ind(SC_LARGE_MAXCLASS)) ?
	    *pind_last + 1 : *pind_last;
	size_t next_block_size = HUGEPAGE_CEILING(sz_pind2sz(pind_next));
    /* 计算实际要分配的内存块的大小 */
	size_t block_size = (min_block_size > next_block_size) ? min_block_size : next_block_size;
    /* 内存分配,注意这里的内存分配,头部已经计算在block_size中了 */
	base_block_t *block = (base_block_t *)base_map(tsdn, extent_hooks, ind, block_size);
	if (block == NULL) {
		return NULL;
	}

	if (metadata_thp_madvise()) {
		void *addr = (void *)block;
		assert(((uintptr_t)addr & HUGEPAGE_MASK) == 0 &&
		    (block_size & HUGEPAGE_MASK) == 0);
		if (opt_metadata_thp == metadata_thp_always) {
			pages_huge(addr, block_size);
		} else if (opt_metadata_thp == metadata_thp_auto &&
		    base != NULL) {
			/* base != NULL indicates this is not a new base. */
			malloc_mutex_lock(tsdn, &base->mtx);
			base_auto_thp_switch(tsdn, base);
			if (base->auto_thp_switched) {
				pages_huge(addr, block_size);
			}
			malloc_mutex_unlock(tsdn, &base->mtx);
		}
	}

	*pind_last = sz_psz2ind(block_size);
	block->size = block_size; /* 记录下大小 */
	block->next = NULL;
	assert(block_size >= header_size);
    /* 初始化block->extent */
	base_extent_init(extent_sn_next, &block->extent,
	    (void *)((uintptr_t)block + header_size), block_size - header_size);
	return block;
}
```



```c
/* 内存分配 */
static void *
base_map(tsdn_t *tsdn, extent_hooks_t *extent_hooks, unsigned ind, size_t size) {
	void *addr;
	bool zero = true;
	bool commit = true;

	/* Use huge page sizes and alignment regardless of opt_metadata_thp. */
	assert(size == HUGEPAGE_CEILING(size));
	size_t alignment = HUGEPAGE;
	if (extent_hooks == &extent_hooks_default) {
		addr = extent_alloc_mmap(NULL, size, alignment, &zero, &commit);
	} else {
		/* No arena context as we are creating new arenas. */
		tsd_t *tsd = tsdn_null(tsdn) ? tsd_fetch() : tsdn_tsd(tsdn);
		pre_reentrancy(tsd, NULL);
		addr = extent_hooks->alloc(extent_hooks, NULL, size, alignment, &zero, &commit, ind);
		post_reentrancy(tsd);
	}

	return addr;
}
```



```c
static bool
pages_huge_impl(void *addr, size_t size, bool aligned) {
	if (aligned) {
		assert(HUGEPAGE_ADDR2BASE(addr) == addr);
		assert(HUGEPAGE_CEILING(size) == size);
	}
#ifdef JEMALLOC_HAVE_MADVISE_HUGE
	return (madvise(addr, size, MADV_HUGEPAGE) != 0);
#else
	return true;
#endif
}

bool
pages_huge(void *addr, size_t size) {
	return pages_huge_impl(addr, size, true);
}
```

## 2.2 base销毁

```c
/* 移除base
 *
 */
void
base_delete(tsdn_t *tsdn, base_t *base) {
	extent_hooks_t *extent_hooks = base_extent_hooks_get(base);
	base_block_t *next = base->blocks;
	do {
		base_block_t *block = next;
		next = block->next;
        /* 不停销毁掉base所管理的base_block */
		base_unmap(tsdn, extent_hooks, base_ind_get(base), block, block->size);
	} while (next != NULL);
}
```



```c
static void
base_unmap(tsdn_t *tsdn, extent_hooks_t *extent_hooks, unsigned ind, void *addr, size_t size) {
	/*
	 * Cascade through dalloc, decommit, purge_forced, and purge_lazy,
	 * stopping at first success.  This cascade is performed for consistency
	 * with the cascade in extent_dalloc_wrapper() because an application's
	 * custom hooks may not support e.g. dalloc.  This function is only ever
	 * called as a side effect of arena destruction, so although it might
	 * seem pointless to do anything besides dalloc here, the application
	 * may in fact want the end state of all associated virtual memory to be
	 * in some consistent-but-allocated state.
	 */
	if (extent_hooks == &extent_hooks_default) {
		if (!extent_dalloc_mmap(addr, size)) {
			goto label_done;
		}
		if (!pages_decommit(addr, size)) {
			goto label_done;
		}
		if (!pages_purge_forced(addr, size)) {
			goto label_done;
		}
		if (!pages_purge_lazy(addr, size)) {
			goto label_done;
		}
		/* Nothing worked.  This should never happen. */
		not_reached();
	} else {
		tsd_t *tsd = tsdn_null(tsdn) ? tsd_fetch() : tsdn_tsd(tsdn);
		pre_reentrancy(tsd, NULL);
		if (extent_hooks->dalloc != NULL &&
		    !extent_hooks->dalloc(extent_hooks, addr, size, true,
		    ind)) {
			goto label_post_reentrancy;
		}
		if (extent_hooks->decommit != NULL &&
		    !extent_hooks->decommit(extent_hooks, addr, size, 0, size, ind)) {
			goto label_post_reentrancy;
		}
		if (extent_hooks->purge_forced != NULL &&
		    !extent_hooks->purge_forced(extent_hooks, addr, size, 0, size, ind)) {
			goto label_post_reentrancy;
		}
		if (extent_hooks->purge_lazy != NULL &&
		    !extent_hooks->purge_lazy(extent_hooks, addr, size, 0, size, ind)) {
			goto label_post_reentrancy;
		}
		/* Nothing worked.  That's the application's problem. */
	label_post_reentrancy:
		post_reentrancy(tsd);
	}
label_done:
	if (metadata_thp_madvise()) {
		/* Set NOHUGEPAGE after unmap to avoid kernel defrag. */
		assert(((uintptr_t)addr & HUGEPAGE_MASK) == 0 &&
		    (size & HUGEPAGE_MASK) == 0);
		pages_nohuge(addr, size);
	}
}
```



## 2.3 base内存分配

`jemalloc`的元数据都通过`base`分配器来进行分配,`jemalloc`提供了`base_alloc`来分配内存,这里需要说的是,目前为止,每一个`arena`都有一个对应的`base`结构体.

```c
/*
 * base_alloc() returns zeroed memory, which is always demand-zeroed for the
 * auto arenas, in order to make multi-page sparse data structures such as radix
 * tree nodes efficient with respect to physical memory usage.  Upon success a
 * pointer to at least size bytes with specified alignment is returned.  Note
 * that size is rounded up to the nearest multiple of alignment to avoid false
 * sharing.
 */
void *
base_alloc(tsdn_t *tsdn, base_t *base, size_t size, size_t alignment) {
	return base_alloc_impl(tsdn, base, size, alignment, NULL);
}
```



```c
/* 通过base来分配内存
 * @param size 内存块大小
 */
static void *
base_alloc_impl(tsdn_t *tsdn, base_t *base, size_t size, size_t alignment, size_t *esn) {
	alignment = QUANTUM_CEILING(alignment);
	size_t usize = ALIGNMENT_CEILING(size, alignment);
	size_t asize = usize + alignment - QUANTUM; /* 实际大小 */

	extent_t *extent = NULL;
	malloc_mutex_lock(tsdn, &base->mtx);
    /* best-fit */
	for (szind_t i = sz_size2index(asize); i < SC_NSIZES; i++) {
		extent = extent_heap_remove_first(&base->avail[i]);
		if (extent != NULL) {
			/* Use existing space. */
			break;
		}
	}
	if (extent == NULL) { /* 如果没有找到可用的extent,就需要重新分配 */
		/* Try to allocate more space. */
		extent = base_extent_alloc(tsdn, base, usize, alignment);
	}
	void *ret;
	if (extent == NULL) {
		ret = NULL;
		goto label_return;
	}

	ret = base_extent_bump_alloc(base, extent, usize, alignment);
	if (esn != NULL) {
		*esn = extent_sn_get(extent);
	}
label_return:
	malloc_mutex_unlock(tsdn, &base->mtx);
	return ret;
}
```

如果没有找到可用的`extent`,需要重新分配`extent`:

```c
/*
 * Allocate an extent that is at least as large as specified size, with
 * specified alignment.
 */
/* 分配一个extent,它至少有size大小,以及指定的对齐方式
 *
 */
static extent_t *
base_extent_alloc(tsdn_t *tsdn, base_t *base, size_t size, size_t alignment) {
	malloc_mutex_assert_owner(tsdn, &base->mtx);

	extent_hooks_t *extent_hooks = base_extent_hooks_get(base);
	/*
	 * Drop mutex during base_block_alloc(), because an extent hook will be
	 * called.
	 */
	malloc_mutex_unlock(tsdn, &base->mtx);
	base_block_t *block = base_block_alloc(tsdn, base, extent_hooks,
	    base_ind_get(base), &base->pind_last, &base->extent_sn_next, size,
	    alignment); /* 实际分配内存 */
	malloc_mutex_lock(tsdn, &base->mtx);
	if (block == NULL) {
		return NULL;
	}
    /* 将block加入base->blocks链表中 */
	block->next = base->blocks;
	base->blocks = block;
	return &block->extent;
}

```



```c
static void *
base_extent_bump_alloc(base_t *base, extent_t *extent, size_t size, size_t alignment) {
	void *ret;
	size_t gap_size;
	ret = base_extent_bump_alloc_helper(extent, &gap_size, size, alignment);
	base_extent_bump_alloc_post(base, extent, gap_size, ret, size);
	return ret;
}
```



```c
/* 从extent中分配内存
 * @return 返回分配后的内存首地址
 */
static void *
base_extent_bump_alloc_helper(extent_t *extent, size_t *gap_size, size_t size,
    size_t alignment) {
	void *ret;

    /* 空隙大小 */
	*gap_size = ALIGNMENT_CEILING((uintptr_t)extent_addr_get(extent),
	    alignment) - (uintptr_t)extent_addr_get(extent);
    /* ret是对齐后的首地址 */
	ret = (void *)((uintptr_t)extent_addr_get(extent) + *gap_size);
	assert(extent_bsize_get(extent) >= *gap_size + size);
    /* 内存分配完成之后,需要更新元数据 */
	extent_binit(extent, (void *)((uintptr_t)extent_addr_get(extent) +
	    *gap_size + size), extent_bsize_get(extent) - *gap_size - size,
	    extent_sn_get(extent));
	return ret;
}
```



## 2.4 base内存回收

`jemalloc`暂时没有回收`base`所管理的内存.