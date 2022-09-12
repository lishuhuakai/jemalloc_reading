#ifndef JEMALLOC_INTERNAL_RTREE_H
#define JEMALLOC_INTERNAL_RTREE_H

#include "jemalloc/internal/atomic.h"
#include "jemalloc/internal/mutex.h"
#include "jemalloc/internal/rtree_tsd.h"
#include "jemalloc/internal/sc.h"
#include "jemalloc/internal/tsd.h"

/*
 * This radix tree implementation is tailored to the singular purpose of
 * associating metadata with extents that are currently owned by jemalloc.
 *
 *******************************************************************************
 */

/* Number of high insignificant bits. */
/* LG_SIZEOF_PTR -- 64位系统下,大致为8字节,因此LG_SIZEOF_PTR为3, 如果LG_VADDR为64,则RTREE_NHIB为
 * (1 << 6) - 64 = 0, LG_VADDR为48的话,RTREE_NHIB为16 */
#define RTREE_NHIB ((1U << (LG_SIZEOF_PTR+3)) - LG_VADDR)
/* Number of low insigificant bits. */
#define RTREE_NLIB LG_PAGE /* PAGE大概占用了12bit,也就是4k */
/* Number of significant bits. */
#define RTREE_NSB (LG_VADDR - RTREE_NLIB) /* 有用的bit位数,64位系统下为52bit */
/* Number of levels in radix tree. */
#if RTREE_NSB <= 10
#  define RTREE_HEIGHT 1
#elif RTREE_NSB <= 36
#  define RTREE_HEIGHT 2
#elif RTREE_NSB <= 52
#  define RTREE_HEIGHT 3
#else
#  error Unsupported number of significant virtual address bits
#endif
/* Use compact leaf representation if virtual address encoding allows. */
#if RTREE_NHIB >= LG_CEIL(SC_NSIZES)
#  define RTREE_LEAF_COMPACT
#endif

/* Needed for initialization only. */
#define RTREE_LEAFKEY_INVALID ((uintptr_t)1)

typedef struct rtree_node_elm_s rtree_node_elm_t;
struct rtree_node_elm_s { /* 基数树的中间节点 */
	atomic_p_t	child; /* (rtree_{node,leaf}_elm_t *) */
};

/* 基数树叶子节点 */
struct rtree_leaf_elm_s {
#ifdef RTREE_LEAF_COMPACT
	/*
	 * Single pointer-width field containing all three leaf element fields.
	 * For example, on a 64-bit x64 system with 48 significant virtual
	 * memory address bits, the index, extent, and slab fields are packed as
	 * such:
	 *
	 * x: index
	 * e: extent
	 * b: slab
	 * 假定是一个64位的系统上,我们仅仅使用了48bit就可以表示三种信息,index占用了8bit
	 * extent占用了28bit, slab使用1bit足矣
	 *
	 *   00000000 xxxxxxxx eeeeeeee [...] eeeeeeee eeee000b
	 */
	atomic_p_t	le_bits;
#else
    /* 这里属于不节省内存的版本 */
	atomic_p_t	le_extent; /* (extent_t *) */
	atomic_u_t	le_szind; /* (szind_t) */
	atomic_b_t	le_slab; /* (bool) */
#endif
};

typedef struct rtree_level_s rtree_level_t;
struct rtree_level_s {
	/* Number of key bits distinguished by this level. */
    /* 在这一个层次(level),用于区分这个层次所使用的bit数目 */
	unsigned		bits;
	/*
	 * Cumulative number of key bits distinguished by traversing to
	 * corresponding tree level.
	 * Cumulative number -- 累计数
	 */
	unsigned		cumbits;
};

typedef struct rtree_s rtree_t;
/* Radix Tree 基数树 */
struct rtree_s {
	malloc_mutex_t		init_lock; /* 互斥锁 */
	/* Number of elements based on rtree_levels[0].bits. */
#if RTREE_HEIGHT > 1
    /* 中间节点,注意,这里的数组非常庞大,在64位系统之上,有1U << (52/3),也就是131072项 */
	rtree_node_elm_t	root[1U << (RTREE_NSB/RTREE_HEIGHT)];
#else
	rtree_leaf_elm_t	root[1U << (RTREE_NSB/RTREE_HEIGHT)];
#endif
};

/*
 * Split the bits into one to three partitions depending on number of
 * significant bits.  It the number of bits does not divide evenly into the
 * number of levels, place one remainder bit per level starting at the leaf
 * level.
 */
static const rtree_level_t rtree_levels[] = {
#if RTREE_HEIGHT == 1 /* 基数树仅有1层 */
	{RTREE_NSB, RTREE_NHIB + RTREE_NSB}
#elif RTREE_HEIGHT == 2 /* 基数树仅有2层 */
    /* {18, 34} => RTREE_NHIB为16, RTREE_NSB为36 */
	{RTREE_NSB/2, RTREE_NHIB + RTREE_NSB/2},
	/* {18, 52} */
	{RTREE_NSB/2 + RTREE_NSB%2, RTREE_NHIB + RTREE_NSB}
#elif RTREE_HEIGHT == 3 /* 基数树有3层,以64bit的LG_VADDR为例, RTREE_NHIB为0 */
     /* 第一层0-16bit,RTREE_NSB为52 ==> {17, 17}*/
	{RTREE_NSB/3, RTREE_NHIB + RTREE_NSB/3},
	/* 第二层17-33bit ==> {17, 34} */
	{RTREE_NSB/3 + RTREE_NSB%3/2,
	    RTREE_NHIB + RTREE_NSB/3*2 + RTREE_NSB%3/2},
	 /* 第三层对应34-51bit ==> { 18, 52 } */
	{RTREE_NSB/3 + RTREE_NSB%3 - RTREE_NSB%3/2, RTREE_NHIB + RTREE_NSB}
#else
#  error Unsupported rtree height
#endif
};

bool rtree_new(rtree_t *rtree, bool zeroed);

typedef rtree_node_elm_t *(rtree_node_alloc_t)(tsdn_t *, rtree_t *, size_t);
extern rtree_node_alloc_t *JET_MUTABLE rtree_node_alloc;

typedef rtree_leaf_elm_t *(rtree_leaf_alloc_t)(tsdn_t *, rtree_t *, size_t);
extern rtree_leaf_alloc_t *JET_MUTABLE rtree_leaf_alloc;

typedef void (rtree_node_dalloc_t)(tsdn_t *, rtree_t *, rtree_node_elm_t *);
extern rtree_node_dalloc_t *JET_MUTABLE rtree_node_dalloc;

typedef void (rtree_leaf_dalloc_t)(tsdn_t *, rtree_t *, rtree_leaf_elm_t *);
extern rtree_leaf_dalloc_t *JET_MUTABLE rtree_leaf_dalloc;
#ifdef JEMALLOC_JET
void rtree_delete(tsdn_t *tsdn, rtree_t *rtree);
#endif
rtree_leaf_elm_t *rtree_leaf_elm_lookup_hard(tsdn_t *tsdn, rtree_t *rtree,
    rtree_ctx_t *rtree_ctx, uintptr_t key, bool dependent, bool init_missing);

/* 获取叶子层的key(标识) */
JEMALLOC_ALWAYS_INLINE uintptr_t
rtree_leafkey(uintptr_t key) {
	unsigned ptrbits = ZU(1) << (LG_SIZEOF_PTR+3);
	unsigned cumbits = (rtree_levels[RTREE_HEIGHT-1].cumbits -
	    rtree_levels[RTREE_HEIGHT-1].bits);
	unsigned maskbits = ptrbits - cumbits;
	uintptr_t mask = ~((ZU(1) << maskbits) - 1);
	return (key & mask); /* 掩码操作,获取对应位置的bit */
}

JEMALLOC_ALWAYS_INLINE size_t
rtree_cache_direct_map(uintptr_t key) {
	unsigned ptrbits = ZU(1) << (LG_SIZEOF_PTR+3); /* 64位系统中,这个值为64 */
	unsigned cumbits = (rtree_levels[RTREE_HEIGHT-1].cumbits -
	    rtree_levels[RTREE_HEIGHT-1].bits);
	unsigned maskbits = ptrbits - cumbits;
	return (size_t)((key >> maskbits) & (RTREE_CTX_NCACHE - 1));
}

/* 从key中提取出第level层的key(标识) */
JEMALLOC_ALWAYS_INLINE uintptr_t
rtree_subkey(uintptr_t key, unsigned level) {
    /* 以第0层为例,key要左移64 - 17 = 47bit
     * 第1层,key要左移64-17-17 = 30bit
     * 第2层,key要左移12bit
     */
	unsigned ptrbits = ZU(1) << (LG_SIZEOF_PTR+3); /* 64位系统中,这个值为64 */
	unsigned cumbits = rtree_levels[level].cumbits;
	unsigned shiftbits = ptrbits - cumbits; /* key要左移的位数 */
	unsigned maskbits = rtree_levels[level].bits;
	uintptr_t mask = (ZU(1) << maskbits) - 1; /* 只要求获取对应的bit */
	return ((key >> shiftbits) & mask);
}

/*
 * Atomic getters.
 *
 * dependent: Reading a value on behalf of a pointer to a valid allocation
 *            is guaranteed to be a clean read even without synchronization,
 *            because the rtree update became visible in memory before the
 *            pointer came into existence.
 * !dependent: An arbitrary read, e.g. on behalf of ivsalloc(), may not be
 *             dependent on a previous rtree write, which means a stale read
 *             could result if synchronization were omitted here.
 */
#  ifdef RTREE_LEAF_COMPACT
JEMALLOC_ALWAYS_INLINE uintptr_t
rtree_leaf_elm_bits_read(tsdn_t *tsdn, rtree_t *rtree,
    rtree_leaf_elm_t *elm, bool dependent) {
	return (uintptr_t)atomic_load_p(&elm->le_bits, dependent
	    ? ATOMIC_RELAXED : ATOMIC_ACQUIRE);
}

JEMALLOC_ALWAYS_INLINE extent_t *
rtree_leaf_elm_bits_extent_get(uintptr_t bits) {
#    ifdef __aarch64__
	/*
	 * aarch64 doesn't sign extend the highest virtual address bit to set
	 * the higher ones.  Instead, the high bits gets zeroed.
	 */
	uintptr_t high_bit_mask = ((uintptr_t)1 << LG_VADDR) - 1;
	/* Mask off the slab bit. */
	uintptr_t low_bit_mask = ~(uintptr_t)1;
	uintptr_t mask = high_bit_mask & low_bit_mask;
	return (extent_t *)(bits & mask);
#    else
	/* Restore sign-extended high bits, mask slab bit. */
	return (extent_t *)((uintptr_t)((intptr_t)(bits << RTREE_NHIB) >>
	    RTREE_NHIB) & ~((uintptr_t)0x1));
#    endif
}

JEMALLOC_ALWAYS_INLINE szind_t
rtree_leaf_elm_bits_szind_get(uintptr_t bits) {
	return (szind_t)(bits >> LG_VADDR);
}

JEMALLOC_ALWAYS_INLINE bool
rtree_leaf_elm_bits_slab_get(uintptr_t bits) {
	return (bool)(bits & (uintptr_t)0x1);
}

#  endif

JEMALLOC_ALWAYS_INLINE extent_t *
rtree_leaf_elm_extent_read(tsdn_t *tsdn, rtree_t *rtree,
    rtree_leaf_elm_t *elm, bool dependent) {
#ifdef RTREE_LEAF_COMPACT
	uintptr_t bits = rtree_leaf_elm_bits_read(tsdn, rtree, elm, dependent);
	return rtree_leaf_elm_bits_extent_get(bits);
#else
	extent_t *extent = (extent_t *)atomic_load_p(&elm->le_extent, dependent
	    ? ATOMIC_RELAXED : ATOMIC_ACQUIRE);
	return extent;
#endif
}

JEMALLOC_ALWAYS_INLINE szind_t
rtree_leaf_elm_szind_read(tsdn_t *tsdn, rtree_t *rtree,
    rtree_leaf_elm_t *elm, bool dependent) {
#ifdef RTREE_LEAF_COMPACT
	uintptr_t bits = rtree_leaf_elm_bits_read(tsdn, rtree, elm, dependent);
	return rtree_leaf_elm_bits_szind_get(bits);
#else
	return (szind_t)atomic_load_u(&elm->le_szind, dependent ? ATOMIC_RELAXED
	    : ATOMIC_ACQUIRE);
#endif
}

JEMALLOC_ALWAYS_INLINE bool
rtree_leaf_elm_slab_read(tsdn_t *tsdn, rtree_t *rtree,
    rtree_leaf_elm_t *elm, bool dependent) {
#ifdef RTREE_LEAF_COMPACT
	uintptr_t bits = rtree_leaf_elm_bits_read(tsdn, rtree, elm, dependent);
	return rtree_leaf_elm_bits_slab_get(bits);
#else
	return atomic_load_b(&elm->le_slab, dependent ? ATOMIC_RELAXED :
	    ATOMIC_ACQUIRE);
#endif
}

static inline void
rtree_leaf_elm_extent_write(tsdn_t *tsdn, rtree_t *rtree,
    rtree_leaf_elm_t *elm, extent_t *extent) {
#ifdef RTREE_LEAF_COMPACT
	uintptr_t old_bits = rtree_leaf_elm_bits_read(tsdn, rtree, elm, true);
	uintptr_t bits = ((uintptr_t)rtree_leaf_elm_bits_szind_get(old_bits) <<
	    LG_VADDR) | ((uintptr_t)extent & (((uintptr_t)0x1 << LG_VADDR) - 1))
	    | ((uintptr_t)rtree_leaf_elm_bits_slab_get(old_bits));
	atomic_store_p(&elm->le_bits, (void *)bits, ATOMIC_RELEASE);
#else
	atomic_store_p(&elm->le_extent, extent, ATOMIC_RELEASE);
#endif
}

static inline void
rtree_leaf_elm_szind_write(tsdn_t *tsdn, rtree_t *rtree,
    rtree_leaf_elm_t *elm, szind_t szind) {
	assert(szind <= SC_NSIZES);

#ifdef RTREE_LEAF_COMPACT
	uintptr_t old_bits = rtree_leaf_elm_bits_read(tsdn, rtree, elm,
	    true);
	uintptr_t bits = ((uintptr_t)szind << LG_VADDR) |
	    ((uintptr_t)rtree_leaf_elm_bits_extent_get(old_bits) &
	    (((uintptr_t)0x1 << LG_VADDR) - 1)) |
	    ((uintptr_t)rtree_leaf_elm_bits_slab_get(old_bits));
	atomic_store_p(&elm->le_bits, (void *)bits, ATOMIC_RELEASE);
#else
	atomic_store_u(&elm->le_szind, szind, ATOMIC_RELEASE);
#endif
}

static inline void
rtree_leaf_elm_slab_write(tsdn_t *tsdn, rtree_t *rtree,
    rtree_leaf_elm_t *elm, bool slab) {
#ifdef RTREE_LEAF_COMPACT
	uintptr_t old_bits = rtree_leaf_elm_bits_read(tsdn, rtree, elm,
	    true);
	uintptr_t bits = ((uintptr_t)rtree_leaf_elm_bits_szind_get(old_bits) <<
	    LG_VADDR) | ((uintptr_t)rtree_leaf_elm_bits_extent_get(old_bits) &
	    (((uintptr_t)0x1 << LG_VADDR) - 1)) | ((uintptr_t)slab);
	atomic_store_p(&elm->le_bits, (void *)bits, ATOMIC_RELEASE);
#else
	atomic_store_b(&elm->le_slab, slab, ATOMIC_RELEASE);
#endif
}

static inline void
rtree_leaf_elm_write(tsdn_t *tsdn, rtree_t *rtree,
    rtree_leaf_elm_t *elm, extent_t *extent, szind_t szind, bool slab) {
#ifdef RTREE_LEAF_COMPACT
	uintptr_t bits = ((uintptr_t)szind << LG_VADDR) |
	    ((uintptr_t)extent & (((uintptr_t)0x1 << LG_VADDR) - 1)) |
	    ((uintptr_t)slab);
	atomic_store_p(&elm->le_bits, (void *)bits, ATOMIC_RELEASE);
#else
	rtree_leaf_elm_slab_write(tsdn, rtree, elm, slab);
	rtree_leaf_elm_szind_write(tsdn, rtree, elm, szind);
	/*
	 * Write extent last, since the element is atomically considered valid
	 * as soon as the extent field is non-NULL.
	 */
	rtree_leaf_elm_extent_write(tsdn, rtree, elm, extent);
#endif
}

static inline void
rtree_leaf_elm_szind_slab_update(tsdn_t *tsdn, rtree_t *rtree,
    rtree_leaf_elm_t *elm, szind_t szind, bool slab) {
	assert(!slab || szind < SC_NBINS);

	/*
	 * The caller implicitly assures that it is the only writer to the szind
	 * and slab fields, and that the extent field cannot currently change.
	 */
	rtree_leaf_elm_slab_write(tsdn, rtree, elm, slab);
	rtree_leaf_elm_szind_write(tsdn, rtree, elm, szind);
}

JEMALLOC_ALWAYS_INLINE rtree_leaf_elm_t *
rtree_leaf_elm_lookup(tsdn_t *tsdn, rtree_t *rtree, rtree_ctx_t *rtree_ctx,
    uintptr_t key, bool dependent, bool init_missing) {
	assert(key != 0);
    /* dependent和init_missing一定要有一个为false */
	assert(!dependent || !init_missing);

	size_t slot = rtree_cache_direct_map(key);
	uintptr_t leafkey = rtree_leafkey(key); /* 获取叶子层的key */
	assert(leafkey != RTREE_LEAFKEY_INVALID);

	/* Fast path: L1 direct mapped cache. */
	if (likely(rtree_ctx->cache[slot].leafkey == leafkey)) {
		rtree_leaf_elm_t *leaf = rtree_ctx->cache[slot].leaf;
		assert(leaf != NULL);
		uintptr_t subkey = rtree_subkey(key, RTREE_HEIGHT-1);
		return &leaf[subkey];
	}
	/*
	 * Search the L2 LRU cache.  On hit, swap the matching element into the
	 * slot in L1 cache, and move the position in L2 up by 1.
	 * 在L2 LRU cache中查找,如果命中的话,和L1 cache中的对应位置交换,总之就是为了加快下一次的
	 * 匹配速度
	 */
#define RTREE_CACHE_CHECK_L2(i) do {					\
	if (likely(rtree_ctx->l2_cache[i].leafkey == leafkey)) {	\
		rtree_leaf_elm_t *leaf = rtree_ctx->l2_cache[i].leaf;	\
		assert(leaf != NULL);					\
		if (i > 0) {						\
			/* Bubble up by one. */				\
			rtree_ctx->l2_cache[i].leafkey =		\
				rtree_ctx->l2_cache[i - 1].leafkey;	\
			rtree_ctx->l2_cache[i].leaf =			\
				rtree_ctx->l2_cache[i - 1].leaf;	\
			rtree_ctx->l2_cache[i - 1].leafkey =		\
			    rtree_ctx->cache[slot].leafkey;		\
			rtree_ctx->l2_cache[i - 1].leaf =		\
			    rtree_ctx->cache[slot].leaf;		\
		} else {						\
			rtree_ctx->l2_cache[0].leafkey =		\
			    rtree_ctx->cache[slot].leafkey;		\
			rtree_ctx->l2_cache[0].leaf =			\
			    rtree_ctx->cache[slot].leaf;		\
		}							\
		rtree_ctx->cache[slot].leafkey = leafkey;		\
		rtree_ctx->cache[slot].leaf = leaf;			\
		uintptr_t subkey = rtree_subkey(key, RTREE_HEIGHT-1);	\
		return &leaf[subkey];					\
	}								\
} while (0)
	/* Check the first cache entry. */
	RTREE_CACHE_CHECK_L2(0);
	/* Search the remaining cache elements. */
	for (unsigned i = 1; i < RTREE_CTX_NCACHE_L2; i++) {
		RTREE_CACHE_CHECK_L2(i); /* 遍历每一个元素 */
	}
#undef RTREE_CACHE_CHECK_L2

	return rtree_leaf_elm_lookup_hard(tsdn, rtree, rtree_ctx, key,
	    dependent, init_missing);
}

/* 往基数树中添加表项
 * @param rtree 基数树
 */
static inline bool
rtree_write(tsdn_t *tsdn, rtree_t *rtree, rtree_ctx_t *rtree_ctx, uintptr_t key,
    extent_t *extent, szind_t szind, bool slab) {
	/* Use rtree_clear() to set the extent to NULL. */
	assert(extent != NULL);
    /* 首先查找 */
	rtree_leaf_elm_t *elm = rtree_leaf_elm_lookup(tsdn, rtree, rtree_ctx,
	    key, false, true);
	if (elm == NULL) {
		return true;
	}

	assert(rtree_leaf_elm_extent_read(tsdn, rtree, elm, false) == NULL);
    /* 更新elm->le_extent, elm->le_szind, ele->le_slab的值 */
	rtree_leaf_elm_write(tsdn, rtree, elm, extent, szind, slab);

	return false;
}

JEMALLOC_ALWAYS_INLINE rtree_leaf_elm_t *
rtree_read(tsdn_t *tsdn, rtree_t *rtree, rtree_ctx_t *rtree_ctx, uintptr_t key,
    bool dependent) {
	rtree_leaf_elm_t *elm = rtree_leaf_elm_lookup(tsdn, rtree, rtree_ctx,
	    key, dependent, false);
	if (!dependent && elm == NULL) {
		return NULL;
	}
	assert(elm != NULL);
	return elm;
}

JEMALLOC_ALWAYS_INLINE extent_t *
rtree_extent_read(tsdn_t *tsdn, rtree_t *rtree, rtree_ctx_t *rtree_ctx,
    uintptr_t key, bool dependent) {
	rtree_leaf_elm_t *elm = rtree_read(tsdn, rtree, rtree_ctx, key,
	    dependent);
	if (!dependent && elm == NULL) {
		return NULL;
	}
	return rtree_leaf_elm_extent_read(tsdn, rtree, elm, dependent);
}

JEMALLOC_ALWAYS_INLINE szind_t
rtree_szind_read(tsdn_t *tsdn, rtree_t *rtree, rtree_ctx_t *rtree_ctx,
    uintptr_t key, bool dependent) {
	rtree_leaf_elm_t *elm = rtree_read(tsdn, rtree, rtree_ctx, key,
	    dependent);
	if (!dependent && elm == NULL) {
		return SC_NSIZES;
	}
	return rtree_leaf_elm_szind_read(tsdn, rtree, elm, dependent);
}

/*
 * rtree_slab_read() is intentionally omitted because slab is always read in
 * conjunction with szind, which makes rtree_szind_slab_read() a better choice.
 */

JEMALLOC_ALWAYS_INLINE bool
rtree_extent_szind_read(tsdn_t *tsdn, rtree_t *rtree, rtree_ctx_t *rtree_ctx,
    uintptr_t key, bool dependent, extent_t **r_extent, szind_t *r_szind) {
	rtree_leaf_elm_t *elm = rtree_read(tsdn, rtree, rtree_ctx, key,
	    dependent);
	if (!dependent && elm == NULL) {
		return true;
	}
	*r_extent = rtree_leaf_elm_extent_read(tsdn, rtree, elm, dependent);
	*r_szind = rtree_leaf_elm_szind_read(tsdn, rtree, elm, dependent);
	return false;
}

/*
 * Try to read szind_slab from the L1 cache.  Returns true on a hit,
 * and fills in r_szind and r_slab.  Otherwise returns false.
 *
 * Key is allowed to be NULL in order to save an extra branch on the
 * fastpath.  returns false in this case.
 */
JEMALLOC_ALWAYS_INLINE bool
rtree_szind_slab_read_fast(tsdn_t *tsdn, rtree_t *rtree, rtree_ctx_t *rtree_ctx,
			    uintptr_t key, szind_t *r_szind, bool *r_slab) {
	rtree_leaf_elm_t *elm;

	size_t slot = rtree_cache_direct_map(key);
	uintptr_t leafkey = rtree_leafkey(key);
	assert(leafkey != RTREE_LEAFKEY_INVALID);

	if (likely(rtree_ctx->cache[slot].leafkey == leafkey)) {
		rtree_leaf_elm_t *leaf = rtree_ctx->cache[slot].leaf;
		assert(leaf != NULL);
		uintptr_t subkey = rtree_subkey(key, RTREE_HEIGHT-1);
		elm = &leaf[subkey];

#ifdef RTREE_LEAF_COMPACT
		uintptr_t bits = rtree_leaf_elm_bits_read(tsdn, rtree,
							  elm, true);
		*r_szind = rtree_leaf_elm_bits_szind_get(bits);
		*r_slab = rtree_leaf_elm_bits_slab_get(bits);
#else
		*r_szind = rtree_leaf_elm_szind_read(tsdn, rtree, elm, true);
		*r_slab = rtree_leaf_elm_slab_read(tsdn, rtree, elm, true);
#endif
		return true;
	} else {
		return false;
	}
}

/*
 * @param key 首地址,其实也作为key
 */
JEMALLOC_ALWAYS_INLINE bool
rtree_szind_slab_read(tsdn_t *tsdn, rtree_t *rtree, rtree_ctx_t *rtree_ctx,
    uintptr_t key, bool dependent, szind_t *r_szind, bool *r_slab) {
    /* 从基数树中获取对应元素 */
	rtree_leaf_elm_t *elm = rtree_read(tsdn, rtree, rtree_ctx, key, dependent);
	if (!dependent && elm == NULL) {
		return true;
	}
#ifdef RTREE_LEAF_COMPACT
    /* 获取分配信息 */
	uintptr_t bits = rtree_leaf_elm_bits_read(tsdn, rtree, elm, dependent);
	*r_szind = rtree_leaf_elm_bits_szind_get(bits);
	*r_slab = rtree_leaf_elm_bits_slab_get(bits);
#else
	*r_szind = rtree_leaf_elm_szind_read(tsdn, rtree, elm, dependent);
	*r_slab = rtree_leaf_elm_slab_read(tsdn, rtree, elm, dependent);
#endif
	return false;
}

static inline void
rtree_szind_slab_update(tsdn_t *tsdn, rtree_t *rtree, rtree_ctx_t *rtree_ctx,
    uintptr_t key, szind_t szind, bool slab) {
	assert(!slab || szind < SC_NBINS);

	rtree_leaf_elm_t *elm = rtree_read(tsdn, rtree, rtree_ctx, key, true);
	rtree_leaf_elm_szind_slab_update(tsdn, rtree, elm, szind, slab);
}

static inline void
rtree_clear(tsdn_t *tsdn, rtree_t *rtree, rtree_ctx_t *rtree_ctx,
    uintptr_t key) {
	rtree_leaf_elm_t *elm = rtree_read(tsdn, rtree, rtree_ctx, key, true);
	assert(rtree_leaf_elm_extent_read(tsdn, rtree, elm, false) !=
	    NULL);
	rtree_leaf_elm_write(tsdn, rtree, elm, NULL, SC_NSIZES, false);
}

#endif /* JEMALLOC_INTERNAL_RTREE_H */
