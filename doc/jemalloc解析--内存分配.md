`jemalloc`一般通过`je_malloc`来分配内存:

```c
/* 内存分配 */
void JEMALLOC_NOTHROW *
JEMALLOC_ATTR(malloc) JEMALLOC_ALLOC_SIZE(1)
je_malloc(size_t size) {
	if (tsd_get_allocates() && unlikely(!malloc_initialized())) {
		return malloc_default(size);
	}

	tsd_t *tsd = tsd_get(false);
	if (unlikely(!tsd || !tsd_fast(tsd) || (size > SC_LOOKUP_MAXCLASS))) {
		return malloc_default(size);
	}
	/* 尝试快路径分配内存 */
	tcache_t *tcache = tsd_tcachep_get(tsd);
	if (unlikely(ticker_trytick(&tcache->gc_ticker))) {
		return malloc_default(size);
	}
	
	szind_t ind = sz_size2index_lookup(size); /* 计算内存大小的级别 */

	cache_bin_t *bin = tcache_small_bin_get(tcache, ind);
	bool tcache_success;
	void* ret = cache_bin_alloc_easy(bin, &tcache_success);

	if (tcache_success) {
		/* Fastpath success */
		return ret;
	}
	return malloc_default(size);
}
```

`jemalloc`内存分配,也是存在快路径的,所谓的快路径,就是直接从`arena`的`tcache`的`cache_bin`中取出缓存的内存.

如果快路径分配不成功,那么就通过`malloc_default`,走正常路径来分配内存.

# 1. 快路径内存分配

所谓的快路径,就是直接从`arena`的`tcache`的`cache_bin`中取出缓存的内存,原理和实现都非常简单,直接看`je_malloc`源码就可以了.

# 2.正常路径内存分配

当无法快速从`arena->tcache`缓存中得到匹配的内存的时候,就会走正常的内存分配逻辑,也就是调用`malloc_default`.

```c
typedef struct static_opts_s static_opts_t;
struct static_opts_s {
	bool may_overflow; /* 分配的大小是否可能会溢出 */

	bool bump_empty_aligned_alloc; /* 分配大小为0的内存块,是否要认为大小为1 */
	/*
	 * Whether to assert that allocations are not of size 0 (after any
	 * bumping).
	 */
	bool assert_nonempty_alloc;

	/*
	 * Whether or not to modify the 'result' argument to malloc in case of
	 * error.
	 */
	bool null_out_result_on_error;
	bool set_errno_on_error; /* 错误发生的时候,是否要设置错误号 */

	/*
	 * The minimum valid alignment for functions requesting aligned storage.
	 */
	size_t min_alignment;

	const char *oom_string; /* 内存不足时应当打出的string */
	/* The error string to use if the passed-in alignment is invalid. */
	const char *invalid_alignment_string;

	bool slow; /* 如果我们配置来跳过一些耗时的操作,那么这个值为false */
	/*
	 * Return size.
	 */
	bool usize;
};

typedef struct dynamic_opts_s dynamic_opts_t;
struct dynamic_opts_s {
	void **result; /* 内存分配的结构 */
	size_t usize;
	size_t num_items; /* 要分配的item的个数 */
	size_t item_size; /* 每一个item的大小 */
	size_t alignment;
	bool zero;
	unsigned tcache_ind;
	unsigned arena_ind;
};

/* 通过正常路径来分配内存
 * @param size 要分配的内存的大小
 */
void * malloc_default(size_t size) {
	void *ret;
	static_opts_t sopts;
	dynamic_opts_t dopts;

	static_opts_init(&sopts);
	dynamic_opts_init(&dopts);

	sopts.null_out_result_on_error = true;
	sopts.set_errno_on_error = true;
	sopts.oom_string = "<jemalloc>: Error in malloc(): out of memory\n";

	dopts.result = &ret; /* 要分配的内存放入ret指向指针处 */
	dopts.num_items = 1; /* 分配1个大小为size的内存块 */
	dopts.item_size = size;

	imalloc(&sopts, &dopts);
	/*
	 * Note that this branch gets optimized away -- it immediately follows
	 * the check on tsd_fast that sets sopts.slow.
	 */
	if (sopts.slow) {
		uintptr_t args[3] = {size};
		hook_invoke_alloc(hook_alloc_malloc, ret, (uintptr_t)ret, args);
	}
	return ret;
}
```

在设置完`sopts`以及`dopts`两个参数之后,`malloc_default`调用`imalloc`来分配内存:

```c
/* 内存分配
 * @param sopts, dopts 分配参数
 */
int
imalloc(static_opts_t *sopts, dynamic_opts_t *dopts) {
	if (tsd_get_allocates() && !imalloc_init_check(sopts, dopts)) {
		return ENOMEM;
	}

	/* We always need the tsd.  Let's grab it right away. */
	tsd_t *tsd = tsd_fetch();
	if (likely(tsd_fast(tsd))) {
		/* Fast and common path. */
		tsd_assert_fast(tsd);
		sopts->slow = false; /* 使用快路径来进行内存分配 */
		return imalloc_body(sopts, dopts, tsd);
	} else {
		if (!tsd_get_allocates() && !imalloc_init_check(sopts, dopts)) {
			return ENOMEM;
		}
		sopts->slow = true;
		return imalloc_body(sopts, dopts, tsd);
	}
}
```

`imalloc`最终会调用`imalloc_body`来分配内存:

```c
int
imalloc_body(static_opts_t *sopts, dynamic_opts_t *dopts, tsd_t *tsd) {
	/* Where the actual allocated memory will live. */
	void *allocation = NULL;
	/* Filled in by compute_size_with_overflow below. */
	size_t size = 0;
	/*
	 * For unaligned allocations, we need only ind.  For aligned
	 * allocations, or in case of stats or profiling we need usize.
	 *
	 * These are actually dead stores, in that their values are reset before
	 * any branch on their value is taken.  Sometimes though, it's
	 * convenient to pass them as arguments before this point.  To avoid
	 * undefined behavior then, we initialize them with dummy stores.
	 */
	szind_t ind = 0;
	size_t usize = 0;

	/* Reentrancy is only checked on slow path. */
	int8_t reentrancy_level;

	/*  计算用户想用的内存的大小 */
	if (unlikely(compute_size_with_overflow(sopts->may_overflow, dopts, &size))) {
		goto label_oom;
	}

	if (unlikely(dopts->alignment < sopts->min_alignment
	    || (dopts->alignment & (dopts->alignment - 1)) != 0)) {
		goto label_invalid_alignment;
	}

	/* This is the beginning of the "core" algorithm. */
	if (dopts->alignment == 0) {
		ind = sz_size2index(size); /* 计算size对应的size class在sc数组中的下标 */
		if (unlikely(ind >= SC_NSIZES)) {
			goto label_oom;
		}
	} else {
		if (sopts->bump_empty_aligned_alloc) {
			if (unlikely(size == 0)) {
				size = 1;
			}
		}
		usize = sz_sa2u(size, dopts->alignment);
		dopts->usize = usize;
		if (unlikely(usize == 0
		    || usize > SC_LARGE_MAXCLASS)) {
			goto label_oom;
		}
	}
	/* Validate the user input. */
	if (sopts->assert_nonempty_alloc) { /* 不允许分配大小为0的内存 */
		assert (size != 0);
	}
	check_entry_exit_locking(tsd_tsdn(tsd));

	/*
	 * If we need to handle reentrancy, we can do it out of a
	 * known-initialized arena (i.e. arena 0).
	 */
	reentrancy_level = tsd_reentrancy_level_get(tsd);
	if (sopts->slow && unlikely(reentrancy_level > 0)) {
		dopts->tcache_ind = TCACHE_IND_NONE;
		/* We know that arena 0 has already been initialized. */
		dopts->arena_ind = 0;
	}

   /*
	* If dopts->alignment > 0, then ind is still 0, but usize was
	* computed in the previous if statement.  Down the positive
	* alignment path, imalloc_no_sample ignores ind and size
	* (relying only on usize).
	*/
    allocation = imalloc_no_sample(sopts, dopts, tsd, size, usize, ind);
    if (unlikely(allocation == NULL)) {
        goto label_oom;
    }
	
	/* Success! */
	check_entry_exit_locking(tsd_tsdn(tsd));
	*dopts->result = allocation;
	return 0;

label_oom:
	// ...
label_invalid_alignment:
	// ...
}
```

`imalloc_body`最终会调用`imalloc_no_sample`来进行内存分配.

```c
/* 内存分配
 *
 */
/* ind is ignored if dopts->alignment > 0. */
JEMALLOC_ALWAYS_INLINE void *
imalloc_no_sample(static_opts_t *sopts, dynamic_opts_t *dopts, tsd_t *tsd,
    size_t size, size_t usize, szind_t ind) {
	tcache_t *tcache;
	arena_t *arena;

	/* Fill in the tcache. */
	if (dopts->tcache_ind == TCACHE_IND_AUTOMATIC) {
		if (likely(!sopts->slow)) {
			/* Getting tcache ptr unconditionally. */
			tcache = tsd_tcachep_get(tsd);
			assert(tcache == tcache_get(tsd));
		} else {
			tcache = tcache_get(tsd);
		}
	} else if (dopts->tcache_ind == TCACHE_IND_NONE) {
		tcache = NULL;
	} else {
		tcache = tcaches_get(tsd, dopts->tcache_ind);
	}

	/* Fill in the arena. */
	if (dopts->arena_ind == ARENA_IND_AUTOMATIC) {
		/*
		 * In case of automatic arena management, we defer arena
		 * computation until as late as we can, hoping to fill the
		 * allocation out of the tcache.
		 */
		arena = NULL;
	} else {
		arena = arena_get(tsd_tsdn(tsd), dopts->arena_ind, true);
	}

	if (unlikely(dopts->alignment != 0)) {
		return ipalloct(tsd_tsdn(tsd), usize, dopts->alignment, dopts->zero, tcache, arena);
	}
	return iallocztm(tsd_tsdn(tsd), size, ind, dopts->zero, tcache, false, arena, sopts->slow);
}
```

在获取了`tcache`以及`arena`之后,会调用`iallocztm`来进行内存分配:

```c
/* 内存分配
 * @param tsdn tsd句柄
 * @param size 要分配的内存大小
 * @param ind 与要分配的内存大小最匹配的size class在sc数组中的下标值
 * @param slow_path 是否要通过慢路径来分配内存
 */
JEMALLOC_ALWAYS_INLINE void *
iallocztm(tsdn_t *tsdn, size_t size, szind_t ind, bool zero, tcache_t *tcache,
    bool is_internal, arena_t *arena, bool slow_path) {
	void *ret;
	ret = arena_malloc(tsdn, arena, size, ind, zero, tcache, slow_path);
	return ret;
}
```

首先尝试从`arena`中进行内存分配:

```c
/* 从arena中分配内存
 * @param tcache 线程内存缓存池指针,主要为了避免加锁
 * @param size 内存块大小
 * @param ind 与要分配的内存大小最匹配的size class在sc数组中的下标值,你也可以认为这是大小级别
 */
void *
arena_malloc(tsdn_t *tsdn, arena_t *arena, size_t size, szind_t ind, bool zero,
    tcache_t *tcache, bool slow_path) {

	if (likely(tcache != NULL)) {
        /* 小内存分配 */
		if (likely(size <= SC_SMALL_MAXCLASS)) {
			return tcache_alloc_small(tsdn_tsd(tsdn), arena,
			    tcache, size, ind, zero, slow_path);
		}
        /* 大内存分配 */
		if (likely(size <= tcache_maxclass)) {
			return tcache_alloc_large(tsdn_tsd(tsdn), arena,
			    tcache, size, ind, zero, slow_path);
		}
		/* (size > tcache_maxclass) case falls through. */
		assert(size > tcache_maxclass);
	}
	return arena_malloc_hard(tsdn, arena, size, ind, zero);
}
```

## 2.1 通过tcache来分配小内存

`tcache_alloc_small`首先尝试从`tcache->bins_small[binind]`中获取对应`size_class`的内存,有的话直接将内存返回给用户.

```c
/* 在tcache中分配内存
 * @param zero 是否要将内存块清零
 * @param size 内存块大小
 * @param binind 内存级别,在一个区间内的内存块大小都属于同一个级别
 */
void *
tcache_alloc_small(tsd_t *tsd, arena_t *arena, tcache_t *tcache,
    size_t size, szind_t binind, bool zero, bool slow_path) {
	void *ret;
	cache_bin_t *bin;
	bool tcache_success;
	size_t usize JEMALLOC_CC_SILENCE_INIT(0);

	bin = tcache_small_bin_get(tcache, binind); /* 获取bin */
	ret = cache_bin_alloc_easy(bin, &tcache_success);
	if (unlikely(!tcache_success)) {
		bool tcache_hard_success;
		arena = arena_choose(tsd, arena);
		if (unlikely(arena == NULL)) {
			return NULL;
		}
        /* 如果分配失败,需要重新分配 */
		ret = tcache_alloc_small_hard(tsd_tsdn(tsd), arena, tcache,
		    bin, binind, &tcache_hard_success);
		if (tcache_hard_success == false) {
			return NULL;
		}
	}

	if (likely(!zero)) {
		if (slow_path && config_fill) {
			if (unlikely(opt_junk_alloc)) {
				arena_alloc_junk_small(ret, &bin_infos[binind], false);
			} else if (unlikely(opt_zero)) {
				memset(ret, 0, usize);
			}
		}
	} else {
		if (slow_path && config_fill && unlikely(opt_junk_alloc)) {
			arena_alloc_junk_small(ret, &bin_infos[binind], true);
		}
		memset(ret, 0, usize);
	}

	tcache_event(tsd, tcache);
	return ret;
}
```

如果不能直接从`bin_small[binind]`中获取到内存,那么调用`tcache_alloc_small_hard`,它所做的事情是,通过获取新的`slab`(或者说`extent`)对`tcache->bins_small[binind]`进行缓存内存块填充,然后再试图从`bins_small[binind]`中分配内存.

```c
/* 内存分配
 * @param tcache 线程内存缓存池
 * @param tbin
 */
void *
tcache_alloc_small_hard(tsdn_t *tsdn, arena_t *arena, tcache_t *tcache,
    cache_bin_t *tbin, szind_t binind, bool *tcache_success) {
	void *ret;

	arena_tcache_fill_small(tsdn, arena, tcache, tbin, binind,
	    config_prof ? tcache->prof_accumbytes : 0);
	if (config_prof) {
		tcache->prof_accumbytes = 0;
	}
	ret = cache_bin_alloc_easy(tbin, tcache_success);
	return ret;
}
```

我们来看一下,`tcache_alloc_small_hard`是如何来对`bin_small[binind]`进行内存块填充的,也就是下面的`arena_tcache_fill_small`函数:

首先,通过通过`bin->slabcur`来为`bin_small[binind]`来填充空闲的内存块,也就是调用`arena_slab_reg_alloc_batch`来进行填充.

```c
/* 将空闲的region个数减掉n */
static inline void
extent_nfree_sub(extent_t *extent, uint64_t n) {
	extent->e_bits -= (n << EXTENT_BITS_NFREE_SHIFT);
}
/* 在slab中批量分配内存
 * @param cnt 内存块个数
 * @param ptrs 数组,用于存储分配的内存
 * @param slab 用于描述一块内存的结构体
 */
static void
arena_slab_reg_alloc_batch(extent_t *slab, const bin_info_t *bin_info,
			   unsigned cnt, void** ptrs) {
	arena_slab_data_t *slab_data = extent_slab_data_get(slab); /* 获取extent的位图数据 */

	unsigned group = 0;
	bitmap_t g = slab_data->bitmap[group]; /* 位图数据,用于标识哪一块内存分配了,哪一块没有被分配 */
	unsigned i = 0;
	while (i < cnt) { /* 一共要分配cnt块内存出来 */
		while (g == 0) {
			g = slab_data->bitmap[++group];
		}
		size_t shift = group << LG_BITMAP_GROUP_NBITS;
		size_t pop = popcount_lu(g);
		if (pop > (cnt - i)) {
			pop = cnt - i;
		}

		/*
		 * Load from memory locations only once, outside the
		 * hot loop below.
		 */
		uintptr_t base = (uintptr_t)extent_addr_get(slab); /* 获得extent描述的内存块的首地址 */
		uintptr_t regsize = (uintptr_t)bin_info->reg_size; /* 获取extent描述内存块每次分配的内存的大小 */
		while (pop--) {
			size_t bit = cfs_lu(&g);
			size_t regind = shift + bit;
			*(ptrs + i) = (void *)(base + regsize * regind);
			i++;
		}
		slab_data->bitmap[group] = g; /* 标记对应的bit位 */
	}
	extent_nfree_sub(slab, cnt);
}

/* 用slab所描述的内存块中的空闲内存来填充cache_bin
 * @param binind 内存块级别
 * @param tbin 要填充的cache_bin
 */
void
arena_tcache_fill_small(tsdn_t *tsdn, arena_t *arena, tcache_t *tcache,
    cache_bin_t *tbin, szind_t binind, uint64_t prof_accumbytes) {
	unsigned i, nfill, cnt;

	unsigned binshard;
    /* 从arena->bins[binind].bin_shared[binind]中获取一个bin,也就是共享的bin */
	bin_t *bin = arena_bin_choose_lock(tsdn, arena, binind, &binshard);

	for (i = 0, nfill = (tcache_bin_info[binind].ncached_max >> tcache->lg_fill_div[binind]);
         i < nfill; i += cnt) {
		extent_t *slab;
        /* 如果bin->slabcur中还有剩余内存, 首先尝试从bin->slabcur中分配 */
		if ((slab = bin->slabcur) != NULL && extent_nfree_get(slab) > 0) {
			unsigned tofill = nfill - i;
			cnt = tofill < extent_nfree_get(slab) ? tofill : extent_nfree_get(slab);
            /* 从slab中分配内存块到tbin->avail数组中 */
			arena_slab_reg_alloc_batch(slab, &bin_infos[binind], cnt, tbin->avail - nfill + i);
		} else {
			cnt = 1;
			void *ptr = arena_bin_malloc_hard(tsdn, arena, bin, binind, binshard);
			/*
			 * OOM.  tbin->avail isn't yet filled down to its first
			 * element, so the successful allocations (if any) must
			 * be moved just before tbin->avail before bailing out.
			 */
			if (ptr == NULL) {
				if (i > 0) {
					memmove(tbin->avail - i, tbin->avail - nfill, i * sizeof(void *));
				}
				break;
			}
			/* Insert such that low regions get used first. */
			*(tbin->avail - nfill + i) = ptr;
		}
		if (config_fill && unlikely(opt_junk_alloc)) {
			for (unsigned j = 0; j < cnt; j++) {
				void* ptr = *(tbin->avail - nfill + i + j);
				arena_alloc_junk_small(ptr, &bin_infos[binind], true);
			}
		}
	}
	
	malloc_mutex_unlock(tsdn, &bin->lock);
	tbin->ncached = i;
	arena_decay_tick(tsdn, arena);
}
```

如果说`bin->slabcur`这`slab`已经没有空闲的内存可供分配了的话,那么尝试从`bin->slabs_nonfull`链表中获取一个拥有空闲内存块的`slab`来进行填充.这个正是`arena_bin_malloc_hard`要做的事情.

```c
/* 重新填充bin->slabcur
 * @return 分配的内存的首地址
 */
static void *
arena_bin_malloc_hard(tsdn_t *tsdn, arena_t *arena, bin_t *bin, szind_t binind, unsigned binshard) {
	const bin_info_t *bin_info;
	extent_t *slab;

	bin_info = &bin_infos[binind]; /* 获取描述信息 */
	if (!arena_is_auto(arena) && bin->slabcur != NULL) {
		arena_bin_slabs_full_insert(arena, bin, bin->slabcur);
		bin->slabcur = NULL;
	}
    /* 尝试从bin->slabs_nonfull中获取一个slab用于内存分配 */
	slab = arena_bin_nonfull_slab_get(tsdn, arena, bin, binind, binshard);
	if (bin->slabcur != NULL) {
		/*
		 * Another thread updated slabcur while this one ran without the
		 * bin lock in arena_bin_nonfull_slab_get().
		 */
		if (extent_nfree_get(bin->slabcur) > 0) { /* slab中仍然有空闲的内存 */
			void *ret = arena_slab_reg_alloc(bin->slabcur, bin_info);
			if (slab != NULL) {
				/*
				 * arena_slab_alloc() may have allocated slab,
				 * or it may have been pulled from
				 * slabs_nonfull.  Therefore it is unsafe to
				 * make any assumptions about how slab has
				 * previously been used, and
				 * arena_bin_lower_slab() must be called, as if
				 * a region were just deallocated from the slab.
				 */
				if (extent_nfree_get(slab) == bin_info->nregs) {
					arena_dalloc_bin_slab(tsdn, arena, slab, bin);
				} else {
					arena_bin_lower_slab(tsdn, arena, slab, bin);
				}
			}
			return ret;
		}
		/* 因为bin->slabcur已经无内存可供分配,所以放入bin->slabs_full链表 */
		arena_bin_slabs_full_insert(arena, bin, bin->slabcur); 
		bin->slabcur = NULL;
	}

	if (slab == NULL) { /* 如果始终获取不到slab,内存分配失败 */
		return NULL;
	}
	bin->slabcur = slab;
	return arena_slab_reg_alloc(slab, bin_info); /* 直接从slab中分配内存 */
}
```

`arena_slab_reg_alloc`可以直接进行内存分配:

```c
/* 在slab中进行内存的分配
 * @param bin_info bin的描述信息
 * @return 返回分配的内存地址
 */
static void *
arena_slab_reg_alloc(extent_t *slab, const bin_info_t *bin_info) {
	void *ret;
	arena_slab_data_t *slab_data = extent_slab_data_get(slab);
	size_t regind;

	regind = bitmap_sfu(slab_data->bitmap, &bin_info->bitmap_info);
    /* 获取regind指示的内存 */
	ret = (void *)((uintptr_t)extent_addr_get(slab) + (uintptr_t)(bin_info->reg_size * regind));
	extent_nfree_dec(slab);
	return ret;
}
```

我们重新来审视一下`arena_bin_nonfull_slab_get`:

```c
/* 尝试从bin的slabs_nonfull链表中获取一个slab */
static extent_t *
arena_bin_slabs_nonfull_tryget(bin_t *bin) {
	extent_t *slab = extent_heap_remove_first(&bin->slabs_nonfull);
	if (slab == NULL) {
		return NULL;
	}
	return slab;
}

/*
 * @param binind 内存级别
 */
static extent_t *
arena_bin_nonfull_slab_get(tsdn_t *tsdn, arena_t *arena, bin_t *bin,
    szind_t binind, unsigned binshard) {
	extent_t *slab;
	const bin_info_t *bin_info;

	/* Look for a usable slab. */
	slab = arena_bin_slabs_nonfull_tryget(bin);
	if (slab != NULL) {
		return slab;
	}
    /* 无法获取到空闲的slab */
	bin_info = &bin_infos[binind];

	/* Allocate a new slab. */
	malloc_mutex_unlock(tsdn, &bin->lock);
	/******************************/
    /* 分配新的slab */
	slab = arena_slab_alloc(tsdn, arena, binind, binshard, bin_info);
	/********************************/
	malloc_mutex_lock(tsdn, &bin->lock);
	if (slab != NULL) {
		return slab;
	}
	/*
	 * arena_slab_alloc() failed, but another thread may have made
	 * sufficient memory available while this one dropped bin->lock above,
	 * so search one more time.
	 */
	slab = arena_bin_slabs_nonfull_tryget(bin);
	if (slab != NULL) {
		return slab;
	}

	return NULL;
}
```

`arena_slab_alloc`用于分配一个`slab` :

```c
/* 分配extent结构 */
static extent_t *
arena_slab_alloc_hard(tsdn_t *tsdn, arena_t *arena,
    extent_hooks_t **r_extent_hooks, const bin_info_t *bin_info,
    szind_t szind) {
	extent_t *slab;
	bool zero, commit;

	zero = false;
	commit = true;
	slab = extent_alloc_wrapper(tsdn, arena, r_extent_hooks, NULL,
	    bin_info->slab_size, 0, PAGE, true, szind, &zero, &commit);

	if (config_stats && slab != NULL) {
		arena_stats_mapped_add(tsdn, &arena->stats,
		    bin_info->slab_size);
	}

	return slab;
}

/* slab的分配
 * @param tsdn
 * @param arena
 * @param binind
 */
static extent_t *
arena_slab_alloc(tsdn_t *tsdn, arena_t *arena, szind_t binind, unsigned binshard,
    const bin_info_t *bin_info) {
	extent_hooks_t *extent_hooks = EXTENT_HOOKS_INITIALIZER;
	szind_t szind = sz_size2index(bin_info->reg_size);
	bool zero = false;
	bool commit = true;
    /* 分配一个extent,分配规则,先尝试复用,不能复用,再分配
     * 这里优先复用arena->extents_dirty链表上的extent
     */
	extent_t *slab = extents_alloc(tsdn, arena, &extent_hooks,
	    &arena->extents_dirty, NULL, bin_info->slab_size, 0, PAGE, true, binind, &zero, &commit);
	if (slab == NULL && arena_may_have_muzzy(arena)) {
		slab = extents_alloc(tsdn, arena, &extent_hooks,
		    &arena->extents_muzzy, NULL, bin_info->slab_size, 0, PAGE, true, binind, &zero, &commit);
	}
	if (slab == NULL) {
        /* 如果不能复用之前的extent,那么实际分配一个extent */
		slab = arena_slab_alloc_hard(tsdn, arena, &extent_hooks, bin_info, szind);
		if (slab == NULL) {
			return NULL;
		}
	}

	/* Initialize slab internals. */
	arena_slab_data_t *slab_data = extent_slab_data_get(slab);
	extent_nfree_binshard_set(slab, bin_info->nregs, binshard);
	bitmap_init(slab_data->bitmap, &bin_info->bitmap_info, false);
	arena_nactive_add(arena, extent_size_get(slab) >> LG_PAGE);
	return slab;
}
```

### 2.1.1 extents的复用

为了加快`extent`的获分配速度,`jemalloc`对之前要释放的`extent`做了缓存,自然,要重新分配`extent`,速度最快的方式,自然是从缓存中找一下.

```c
/* 分配extent
 * @param extents extent构成的链表,它的来源可以是arena->extents_dirty,也可以是arena->extens_muzzy
 */
extent_t *
extents_alloc(tsdn_t *tsdn, arena_t *arena, extent_hooks_t **r_extent_hooks,
    extents_t *extents, void *new_addr, size_t size, size_t pad,
    size_t alignment, bool slab, szind_t szind, bool *zero, bool *commit) {
	/* 尝试先使用回收的extent */
	extent_t *extent = extent_recycle(tsdn, arena, r_extent_hooks, extents,
	    new_addr, size, pad, alignment, slab, szind, zero, commit, false);
	return extent;
}
```
为了减少分配的代价,我们总是优先重复使用之前已经释放的`extent`:

```c
/* 尝试复用extent
 * @param extents 可以从这个链表上查找extent来进行复用
 * @param new_addr 用于指定extent代表内存块的首地址,当然,大部分时候,这个值为NULL,不进行限定
 */
static extent_t *
extent_recycle(tsdn_t *tsdn, arena_t *arena, extent_hooks_t **r_extent_hooks,
    extents_t *extents, void *new_addr, size_t size, size_t pad,
    size_t alignment, bool slab, szind_t szind, bool *zero, bool *commit,
    bool growing_retained) {

	rtree_ctx_t rtree_ctx_fallback;
	rtree_ctx_t *rtree_ctx = tsdn_rtree_ctx(tsdn, &rtree_ctx_fallback); /* 获得arena的rtree_ctx */

	extent_t *extent = extent_recycle_extract(tsdn, arena, r_extent_hooks,
	    rtree_ctx, extents, new_addr, size, pad, alignment, slab,
	    growing_retained);
	if (extent == NULL) {
		return NULL;
	}

	extent = extent_recycle_split(tsdn, arena, r_extent_hooks, rtree_ctx,
	    extents, new_addr, size, pad, alignment, slab, szind, extent,
	    growing_retained);
	if (extent == NULL) {
		return NULL;
	}

	if (*commit && !extent_committed_get(extent)) {
		if (extent_commit_impl(tsdn, arena, r_extent_hooks, extent,
		    0, extent_size_get(extent), growing_retained)) {
			extent_record(tsdn, arena, r_extent_hooks, extents,
			    extent, growing_retained);
			return NULL;
		}
		if (!extent_need_manual_zero(arena)) {
			extent_zeroed_set(extent, true);
		}
	}

	if (extent_committed_get(extent)) {
		*commit = true;
	}
	if (extent_zeroed_get(extent)) {
		*zero = true;
	}

	if (pad != 0) {
		extent_addr_randomize(tsdn, extent, alignment);
	}
    
	if (slab) {
		extent_slab_set(extent, slab); /* 为extent打上slab标记,表示这块内存的用途是小内存分配 */
		extent_interior_register(tsdn, rtree_ctx, extent, szind);
	}

	if (*zero) {
		void *addr = extent_base_get(extent);
		if (!extent_zeroed_get(extent)) {
			size_t size = extent_size_get(extent);
			if (extent_need_manual_zero(arena) ||
			    pages_purge_forced(addr, size)) {
				memset(addr, 0, size);
			}
		}
	}
	return extent;
}
```

`extent_recycle_extract`实际所做的事情是,从`arena->extents_dirty`中回收`extent`,回收方式为`first_fit`:

```c
static extent_t *
extents_first_fit_locked(tsdn_t *tsdn, arena_t *arena, extents_t *extents, size_t size) {
	extent_t *ret = NULL;

	pszind_t pind = sz_psz2ind(extent_size_quantize_ceil(size)); /* 内存块大小级别 */
	if (!maps_coalesce && !opt_retain) {
		/*
		 * No split / merge allowed (Windows w/o retain). Try exact fit
		 * only.
		 */
		return extent_heap_empty(&extents->heaps[pind]) ? NULL : extent_heap_first(&extents->heaps[pind]);
	}
	/* 从满足条件的最低级别的extent开始寻找,没找到,就将级别提高 */
	for (pszind_t i = (pszind_t)bitmap_ffu(extents->bitmap, &extents_bitmap_info, (size_t)pind);
	    i < SC_NPSIZES + 1;
	    i = (pszind_t)bitmap_ffu(extents->bitmap, &extents_bitmap_info, (size_t)i+1)) {
		extent_t *extent = extent_heap_first(&extents->heaps[i]); /* 从extents中取出一个extent */
		/*
		 * In order to reduce fragmentation, avoid reusing and splitting
		 * large extents for much smaller sizes.
		 * 为了避免碎片化,尽量避免将大级别extents变更为小级别的extents,来满足分配需要.
		 *
		 * Only do check for dirty extents (delay_coalesce).
		 */
		if (extents->delay_coalesce &&
		    (sz_pind2sz(i) >> opt_lg_extent_max_active_fit) > size) {
			break;
		}
		if (ret == NULL || extent_snad_comp(extent, ret) < 0) {
			ret = extent;
		}
		if (i == SC_NPSIZES) {
			break;
		}
	}
	return ret;
}

/* 做first-fit匹配 
 * @param esize 内存块大小
 */
static extent_t *
extents_fit_locked(tsdn_t *tsdn, arena_t *arena, extents_t *extents, size_t esize, size_t alignment) {
	size_t max_size = esize + PAGE_CEILING(alignment) - PAGE;
	/* Beware size_t wrap-around. */
	if (max_size < esize) {
		return NULL;
	}

	extent_t *extent = extents_first_fit_locked(tsdn, arena, extents, max_size);
	if (alignment > PAGE && extent == NULL) {
		/*
		 * max_size guarantees the alignment requirement but is rather
		 * pessimistic.  Next we try to satisfy the aligned allocation
		 * with sizes in [esize, max_size).
		 */
		extent = extents_fit_alignment(extents, esize, max_size, alignment);
	}
	return extent;
}

/* 尝试从extents中移除extent,此extent满足给定的分配请求
 * @param new_addr 指定内存块首地址
 * @param size 内存块大小
 */
static extent_t *
extent_recycle_extract(tsdn_t *tsdn, arena_t *arena,
    extent_hooks_t **r_extent_hooks, rtree_ctx_t *rtree_ctx, extents_t *extents,
    void *new_addr, size_t size, size_t pad, size_t alignment, bool slab,
    bool growing_retained) {

	size_t esize = size + pad; /* 大小 */
	malloc_mutex_lock(tsdn, &extents->mtx);
	extent_hooks_assure_initialized(arena, r_extent_hooks);
	extent_t *extent;
	if (new_addr != NULL) { /* 大部分时候都不会限定extent的首地址 */
		extent = extent_lock_from_addr(tsdn, rtree_ctx, new_addr, false);
		if (extent != NULL) {
			/*
			 * We might null-out extent to report an error, but we
			 * still need to unlock the associated mutex after.
			 */
			extent_t *unlock_extent = extent;
			if (extent_arena_get(extent) != arena ||
			    extent_size_get(extent) < esize ||
			    extent_state_get(extent) !=
			    extents_state_get(extents)) {
				extent = NULL;
			}
			extent_unlock(tsdn, unlock_extent);
		}
	} else {
		extent = extents_fit_locked(tsdn, arena, extents, esize, alignment);
	}
	if (extent == NULL) {
		malloc_mutex_unlock(tsdn, &extents->mtx);
		return NULL;
	}

	extent_activate_locked(tsdn, arena, extents, extent);
	malloc_mutex_unlock(tsdn, &extents->mtx);
	return extent;
}
```

找到的`extent`并不一定完全满足我们的需求,有的时候,是要进行分裂的:

```c
static extent_t *
extent_recycle_split(tsdn_t *tsdn, arena_t *arena,
    extent_hooks_t **r_extent_hooks, rtree_ctx_t *rtree_ctx, extents_t *extents,
    void *new_addr, size_t size, size_t pad, size_t alignment, bool slab,
    szind_t szind, extent_t *extent, bool growing_retained) {
	extent_t *lead;
	extent_t *trail;
	extent_t *to_leak;
	extent_t *to_salvage;

	extent_split_interior_result_t result = extent_split_interior(
	    tsdn, arena, r_extent_hooks, rtree_ctx, &extent, &lead, &trail,
	    &to_leak, &to_salvage, new_addr, size, pad, alignment, slab, szind,
	    growing_retained);

	if (!maps_coalesce && result != extent_split_interior_ok
	    && !opt_retain) {
		/*
		 * Split isn't supported (implies Windows w/o retain).  Avoid
		 * leaking the extents.
		 */
		extent_deactivate(tsdn, arena, extents, to_leak);
		return NULL;
	}

	if (result == extent_split_interior_ok) {
		if (lead != NULL) {
			extent_deactivate(tsdn, arena, extents, lead);
		}
		if (trail != NULL) {
			extent_deactivate(tsdn, arena, extents, trail);
		}
		return extent;
	} else {
		/*
		 * We should have picked an extent that was large enough to
		 * fulfill our allocation request.
		 */
		if (to_salvage != NULL) {
			extent_deregister(tsdn, to_salvage);
		}
		if (to_leak != NULL) {
			void *leak = extent_base_get(to_leak);
			extent_deregister_no_gdump_sub(tsdn, to_leak);
			extents_abandon_vm(tsdn, arena, r_extent_hooks, extents,
			    to_leak, growing_retained);
		}
		return NULL;
	}
}
```

### 2.1.2 重新构建extent

如果没有`extent`可供复用,那么我们就需要走实际构建`extent`的流程.

```c
/* 分配extent结构,用作小内存分配
 *
 */
static extent_t *
arena_slab_alloc_hard(tsdn_t *tsdn, arena_t *arena,
    extent_hooks_t **r_extent_hooks, const bin_info_t *bin_info,
    szind_t szind) {
	extent_t *slab;
	bool zero, commit;

	zero = false;
	commit = true;
	slab = extent_alloc_wrapper(tsdn, arena, r_extent_hooks, NULL,
	    bin_info->slab_size, 0, PAGE, true, szind, &zero, &commit);

	return slab;
}
```

`extent_alloc_wrapper`用于实际的构建:

```c
extent_t *
extent_alloc_wrapper(tsdn_t *tsdn, arena_t *arena,
    extent_hooks_t **r_extent_hooks, void *new_addr, size_t size, size_t pad,
    size_t alignment, bool slab, szind_t szind, bool *zero, bool *commit) {

	extent_hooks_assure_initialized(arena, r_extent_hooks);

	extent_t *extent = extent_alloc_retained(tsdn, arena, r_extent_hooks,
	    new_addr, size, pad, alignment, slab, szind, zero, commit);
	if (extent == NULL) {
		if (opt_retain && new_addr != NULL) {
			/*
			 * When retain is enabled and new_addr is set, we do not
			 * attempt extent_alloc_wrapper_hard which does mmap
			 * that is very unlikely to succeed (unless it happens
			 * to be at the end).
			 */
			return NULL;
		}
		extent = extent_alloc_wrapper_hard(tsdn, arena, r_extent_hooks,
		    new_addr, size, pad, alignment, slab, szind, zero, commit);
	}
	return extent;
}
```

首先尝试从`arena->extens_retained`中回收`extent`来复用:

```c
static extent_t *
extent_alloc_retained(tsdn_t *tsdn, arena_t *arena,
    extent_hooks_t **r_extent_hooks, void *new_addr, size_t size, size_t pad,
    size_t alignment, bool slab, szind_t szind, bool *zero, bool *commit) {

	malloc_mutex_lock(tsdn, &arena->extent_grow_mtx);

	extent_t *extent = extent_recycle(tsdn, arena, r_extent_hooks,
	    &arena->extents_retained, new_addr, size, pad, alignment, slab,
	    szind, zero, commit, true); /* 尝试从从arena->extens_retained中回收extent */
	if (extent != NULL) {
		malloc_mutex_unlock(tsdn, &arena->extent_grow_mtx);
	} else if (opt_retain && new_addr == NULL) {
		extent = extent_grow_retained(tsdn, arena, r_extent_hooks, size,
		    pad, alignment, slab, szind, zero, commit);
		/* extent_grow_retained() always releases extent_grow_mtx. */
	} else {
		malloc_mutex_unlock(tsdn, &arena->extent_grow_mtx);
	}
	malloc_mutex_assert_not_owner(tsdn, &arena->extent_grow_mtx);
	return extent;
}
```

如果复用不成功的话,再来进行分配,也就是`extent_alloc_wrapper_hard`函数,这个函数在`extent`相关章节中有叙述,这里就不详细补充了,它具体做的事情是,通过`base`分配器,分配`extent`的元数据,然后从操作系统实际分配一块内存,作为`extent`所描述的内存块.

## 2.2 通过tcache来分配大内存

这里需要注意,大内存的分配,每次都需要一个`extent`.

`tcache_alloc_large`用于从`tcache`中分配大内存,它的基本思路是:

首先尝试从`tcache->bin_large[binind]`所指示的`cache_bin`中分配内存.

```c
JEMALLOC_ALWAYS_INLINE cache_bin_t *
tcache_large_bin_get(tcache_t *tcache, szind_t binind) {
	return &tcache->bins_large[binind - SC_NBINS];
}
/* 通过tcache来分配大内存
 * @param size 待分配的内存大小
 */
JEMALLOC_ALWAYS_INLINE void *
tcache_alloc_large(tsd_t *tsd, arena_t *arena, tcache_t *tcache, size_t size,
    szind_t binind, bool zero, bool slow_path) {
	void *ret;
	cache_bin_t *bin;
	bool tcache_success;

	bin = tcache_large_bin_get(tcache, binind); /* 根据内存大小级别获取对应的cache_bin */
	ret = cache_bin_alloc_easy(bin, &tcache_success); /* 尝试直接从cache_bin中进行分配 */
	if (unlikely(!tcache_success)) {
		/*
		 * Only allocate one large object at a time, because it's quite
		 * expensive to create one and not use it.
		 */
		arena = arena_choose(tsd, arena);
		if (unlikely(arena == NULL)) {
			return NULL;
		}

		ret = large_malloc(tsd_tsdn(tsd), arena, sz_s2u(size), zero);
		if (ret == NULL) {
			return NULL;
		}
	} else {
		size_t usize JEMALLOC_CC_SILENCE_INIT(0);

		/* Only compute usize on demand */
		if ((slow_path && config_fill) ||
		    unlikely(zero)) {
			usize = sz_index2size(binind);
			assert(usize <= tcache_maxclass);
		}

		if (likely(!zero)) {
			if (slow_path && config_fill) {
				if (unlikely(opt_junk_alloc)) {
					memset(ret, JEMALLOC_ALLOC_JUNK,
					    usize);
				} else if (unlikely(opt_zero)) {
					memset(ret, 0, usize);
				}
			}
		} else {
			memset(ret, 0, usize);
		}
	}

	tcache_event(tsd, tcache);
	return ret;
}
```

如果不成功,那么走`large_malloc`来分配内存.

```c
void *
large_palloc(tsdn_t *tsdn, arena_t *arena, size_t usize, size_t alignment, bool zero) {
	size_t ausize;
	extent_t *extent;
	bool is_zeroed;
	UNUSED bool idump JEMALLOC_CC_SILENCE_INIT(false);
	ausize = sz_sa2u(usize, alignment);
	if (unlikely(ausize == 0 || ausize > SC_LARGE_MAXCLASS)) {
		return NULL;
	}

	if (config_fill && unlikely(opt_zero)) {
		zero = true;
	}
	/*
	 * Copy zero into is_zeroed and pass the copy when allocating the
	 * extent, so that it is possible to make correct junk/zero fill
	 * decisions below, even if is_zeroed ends up true when zero is false.
	 */
	is_zeroed = zero;
	if (likely(!tsdn_null(tsdn))) {
		arena = arena_choose_maybe_huge(tsdn_tsd(tsdn), arena, usize);
	}
	if (unlikely(arena == NULL) || (extent = arena_extent_alloc_large(tsdn,
	    arena, usize, alignment, &is_zeroed)) == NULL) {
		return NULL;
	}

	/* See comments in arena_bin_slabs_full_insert(). */
	if (!arena_is_auto(arena)) {
		/* Insert extent into large. */
		malloc_mutex_lock(tsdn, &arena->large_mtx);
		extent_list_append(&arena->large, extent);
		malloc_mutex_unlock(tsdn, &arena->large_mtx);
	}

	if (zero) {
		assert(is_zeroed);
	} else if (config_fill && unlikely(opt_junk_alloc)) {
		memset(extent_addr_get(extent), JEMALLOC_ALLOC_JUNK,
		    extent_usize_get(extent));
	}

	arena_decay_tick(tsdn, arena);
	return extent_addr_get(extent);
}

void *
large_malloc(tsdn_t *tsdn, arena_t *arena, size_t usize, bool zero) {
	return large_palloc(tsdn, arena, usize, CACHELINE, zero);
}
```

整套分配流程和小内存分配如出一辙.

1. 从`arena->extents_dirty`中回收`extent`.
2. 从`arena->extents_muzzy`中回收`extent`.
3. 从`arena->extents_retained`中回收`extent`.
4. 如果`extent`回收失败,那么向内核申请内存,来构建新的`extent`.(`extent_alloc_wrapper`)

```c
/* extent可以简单认为是分配的内存
 * @param usize 内存块大小
 * @param alignment 对齐
 *
 */
extent_t *
arena_extent_alloc_large(tsdn_t *tsdn, arena_t *arena, size_t usize,
    size_t alignment, bool *zero) {
	extent_hooks_t *extent_hooks = EXTENT_HOOKS_INITIALIZER;

	witness_assert_depth_to_rank(tsdn_witness_tsdp_get(tsdn),
	    WITNESS_RANK_CORE, 0);

	szind_t szind = sz_size2index(usize);
	size_t mapped_add;
	bool commit = true;
    /* 优先复用extents_dirty上的extent */
	extent_t *extent = extents_alloc(tsdn, arena, &extent_hooks,
	    &arena->extents_dirty, NULL, usize, sz_large_pad, alignment, false,
	    szind, zero, &commit);
    /* 其次复用extents_muzzy上的extent */
	if (extent == NULL && arena_may_have_muzzy(arena)) {
		extent = extents_alloc(tsdn, arena, &extent_hooks,
		    &arena->extents_muzzy, NULL, usize, sz_large_pad, alignment,
		    false, szind, zero, &commit);
	}
	size_t size = usize + sz_large_pad;
	if (extent == NULL) {
        /* 没有找到才进行实际的分配 */
		extent = extent_alloc_wrapper(tsdn, arena, &extent_hooks, NULL,
		    usize, sz_large_pad, alignment, false, szind, zero,
		    &commit);
	} else if (config_stats) {
		mapped_add = 0;
	}

	if (extent != NULL) {
		arena_nactive_add(arena, size >> LG_PAGE);
	}

	return extent;
}
```

## 2.3 非tcache内存分配

如果不存在`tcache`的情况下,`jemalloc`会直接调用`arena_malloc_hard`来进行分配,当然,这种方法会增加分配的开销,如果内存充足的话,还是建议开启`tcache`.

```c
/* 在arena中进行内存分配 */
void *
arena_malloc_hard(tsdn_t *tsdn, arena_t *arena, size_t size, szind_t ind, bool zero) {
	if (likely(!tsdn_null(tsdn))) {
		arena = arena_choose_maybe_huge(tsdn_tsd(tsdn), arena, size);
	}
	if (unlikely(arena == NULL)) {
		return NULL;
	}
	if (likely(size <= SC_SMALL_MAXCLASS)) {
		return arena_malloc_small(tsdn, arena, ind, zero);
	}
	return large_malloc(tsdn, arena, sz_index2size(ind), zero);
}
```

我这里仅仅举一个小内存分配的例子.

```c
/* Choose a bin shard and return the locked bin.
 * @param tsdn tsd句柄
 * @param arena
 * @param binind 内存级别
 */
bin_t *
arena_bin_choose_lock(tsdn_t *tsdn, arena_t *arena, szind_t binind,
    unsigned *binshard) {
	bin_t *bin;
	if (tsdn_null(tsdn) || tsd_arena_get(tsdn_tsd(tsdn)) == NULL) {
		*binshard = 0;
	} else {
		*binshard = tsd_binshardsp_get(tsdn_tsd(tsdn))->binshard[binind];
	}
	assert(*binshard < bin_infos[binind].n_shards);
	bin = &arena->bins[binind].bin_shards[*binshard];
	malloc_mutex_lock(tsdn, &bin->lock); /* 加锁 */
	return bin;
}

/* 小内存的分配
 * @param binindx index值
 */
static void *
arena_malloc_small(tsdn_t *tsdn, arena_t *arena, szind_t binind, bool zero) {
	void *ret;
	bin_t *bin;
	size_t usize;
	extent_t *slab;

	usize = sz_index2size(binind);
	unsigned binshard;
	bin = arena_bin_choose_lock(tsdn, arena, binind, &binshard); /* 获取一个bin */

	if ((slab = bin->slabcur) != NULL && extent_nfree_get(slab) > 0) {
		ret = arena_slab_reg_alloc(slab, &bin_infos[binind]);
	} else {
		ret = arena_bin_malloc_hard(tsdn, arena, bin, binind, binshard);
	}

	if (ret == NULL) {
		malloc_mutex_unlock(tsdn, &bin->lock);
		return NULL;
	}

	malloc_mutex_unlock(tsdn, &bin->lock);

	if (!zero) {
		if (config_fill) {
			if (unlikely(opt_junk_alloc)) {
				arena_alloc_junk_small(ret,
				    &bin_infos[binind], false);
			} else if (unlikely(opt_zero)) {
				memset(ret, 0, usize);
			}
		}
	} else {
		if (config_fill && unlikely(opt_junk_alloc)) {
			arena_alloc_junk_small(ret, &bin_infos[binind], true);
		}
		memset(ret, 0, usize);
	}

	arena_decay_tick(tsdn, arena);
	return ret;
}
```

`arena_bin_choose_lock`从arena之中获取一个bin,如果`bin-->slab_cur`不为空,就直接从`bin->slab_cur`中进行分配(`arena_slab_reg_alloc`).

如果`bin->slab_cur`为空,那么就需要重新填充`bin->slab_cur`,然后再次尝试分配(`arena_bin_malloc_hard`).

以上两个函数在上面已经讲解过,就不再赘述.



