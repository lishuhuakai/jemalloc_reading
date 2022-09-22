# 1. 结构体的定义

`jemalloc`使用`rtree`来加快查找速度.这里的`rtree`实际是一棵基数树.

我们首先来看一些`rtree`结构的定义:

```c
// rtree.h
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
	atomic_p_t	le_extent; /* (extent_t *),这里记录的是指针 */
	atomic_u_t	le_szind; /* (szind_t) */
	atomic_b_t	le_slab; /* (bool) */
#endif
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
```

接下来的梳理都以64位操作系统为例子:

```c
/* Number of high insignificant bits. */
/* LG_SIZEOF_PTR64位系统下,大致为8字节,因此RTREE_NHIB为 ((1U << 11) - 64) ?? */
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

/*
 * Split the bits into one to three partitions depending on number of
 * significant bits.  It the number of bits does not divide evenly into the
 * number of levels, place one remainder bit per level starting at the leaf
 * level.
 */
static const rtree_level_t rtree_levels[] = {
#if RTREE_HEIGHT == 1 /* 基数树仅有1层 */
	{RTREE_NSB, RTREE_NHIB + RTREE_NSB}
#elif RTREE_HEIGHT == 2
	{RTREE_NSB/2, RTREE_NHIB + RTREE_NSB/2},
	{RTREE_NSB/2 + RTREE_NSB%2, RTREE_NHIB + RTREE_NSB}
#elif RTREE_HEIGHT == 3 /* 基数树有3层,以64bit的虚拟地址为例 */
     /* 第一层0-16bit,RTREE_NSB为52 ==> {17, RTREE_NHIB+17}*/
	{RTREE_NSB/3, RTREE_NHIB + RTREE_NSB/3},
	/* 第二层17-33bit ==> {17, RTREE_NHIB + 34} */
	{RTREE_NSB/3 + RTREE_NSB%3/2,
	    RTREE_NHIB + RTREE_NSB/3*2 + RTREE_NSB%3/2},
	 /* 第三层对应34-51bit ==> { 18, RTREE_NHIB + 52 } */
	{RTREE_NSB/3 + RTREE_NSB%3 - RTREE_NSB%3/2, RTREE_NHIB + RTREE_NSB}
#else
#  error Unsupported rtree height
#endif
};
```

# 2. rtree相关的操作函数

## 2.1 rtree的初始化

每一颗新创建的基数树都需要调用`rtree_new`来进行初始化.

```c
/*
 * Only the most significant bits of keys passed to rtree_{read,write}() are
 * used.
 * 基数树初始化
 */
bool
rtree_new(rtree_t *rtree, bool zeroed) {
#ifdef JEMALLOC_JET
	if (!zeroed) {
		memset(rtree, 0, sizeof(rtree_t)); /* Clear root. */
	}
#else
	assert(zeroed);
#endif

	if (malloc_mutex_init(&rtree->init_lock, "rtree", WITNESS_RANK_RTREE,
	    malloc_mutex_rank_exclusive)) {
		return true;
	}

	return false;
}
```

## 2.2 获得rtree的key

```c
/* 获取叶子层的key */
JEMALLOC_ALWAYS_INLINE uintptr_t
rtree_leafkey(uintptr_t key) {
	unsigned ptrbits = ZU(1) << (LG_SIZEOF_PTR+3);
	unsigned cumbits = (rtree_levels[RTREE_HEIGHT-1].cumbits - rtree_levels[RTREE_HEIGHT-1].bits);
	unsigned maskbits = ptrbits - cumbits;
	uintptr_t mask = ~((ZU(1) << maskbits) - 1);
	return (key & mask); /* 掩码操作,获取对应位置的bit */
}

/* 从key中提取出第level层的key */
JEMALLOC_ALWAYS_INLINE uintptr_t
rtree_subkey(uintptr_t key, unsigned level) {
    /* 以第0层为例,key要左移64 - 17 = 47bit
     * 第1层,key要左移64-17-17 = 30bit
     * 第2层,key要左移12bit
     */
	unsigned ptrbits = ZU(1) << (LG_SIZEOF_PTR+3);
	unsigned cumbits = rtree_levels[level].cumbits;
	unsigned shiftbits = ptrbits - cumbits; /* key要左移的位数 */
	unsigned maskbits = rtree_levels[level].bits;
	uintptr_t mask = (ZU(1) << maskbits) - 1; /* 只要求获取对应的bit */
	return ((key >> shiftbits) & mask);
}
```

## 2.3 往rtree中插入数据

往基数树中插入数据,要经过`rtree_write`.需要注意的是,这里的基数树都以指针作为`key`.

```c
/* 往基数树中添加表项
 * @param rtree 基数树
 * @param rtree_ctx 基数树的上下文,这个东西和基数树相配合,可以加快查找速度
 */
static inline bool
rtree_write(tsdn_t *tsdn, rtree_t *rtree, rtree_ctx_t *rtree_ctx, uintptr_t key,
    extent_t *extent, szind_t szind, bool slab) {
    /* 首先查找 */
	rtree_leaf_elm_t *elm = rtree_leaf_elm_lookup(tsdn, rtree, rtree_ctx, key, false, true);
	if (elm == NULL) {
		return true;
	}
    /* 更新elm->le_extent, elm->le_szind, ele->le_slab的值 */
	rtree_leaf_elm_write(tsdn, rtree, elm, extent, szind, slab);
	return false;
}
```

在写入之前,首先要进行查找,首先优先在`rtree_ctx`中查找,如果找不到的话,再到`rtree`中查找:

```c
JEMALLOC_ALWAYS_INLINE rtree_leaf_elm_t *
rtree_leaf_elm_lookup(tsdn_t *tsdn, rtree_t *rtree, rtree_ctx_t *rtree_ctx,
    uintptr_t key, bool dependent, bool init_missing) {

	size_t slot = rtree_cache_direct_map(key);
	uintptr_t leafkey = rtree_leafkey(key);
	/* Fast path: L1 direct mapped cache. */
	if (likely(rtree_ctx->cache[slot].leafkey == leafkey)) {
		rtree_leaf_elm_t *leaf = rtree_ctx->cache[slot].leaf;
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
		if (i > 0) {								\
			rtree_ctx->l2_cache[i].leafkey =		\
				rtree_ctx->l2_cache[i - 1].leafkey;	\
			rtree_ctx->l2_cache[i].leaf =			\
				rtree_ctx->l2_cache[i - 1].leaf;	\
			rtree_ctx->l2_cache[i - 1].leafkey =	\
			    rtree_ctx->cache[slot].leafkey;		\
			rtree_ctx->l2_cache[i - 1].leaf =		\
			    rtree_ctx->cache[slot].leaf;		\
		} else {									\
			rtree_ctx->l2_cache[0].leafkey =		\
			    rtree_ctx->cache[slot].leafkey;		\
			rtree_ctx->l2_cache[0].leaf =			\
			    rtree_ctx->cache[slot].leaf;		\
		}											\
		rtree_ctx->cache[slot].leafkey = leafkey;	\
		rtree_ctx->cache[slot].leaf = leaf;			\
		uintptr_t subkey = rtree_subkey(key, RTREE_HEIGHT-1);	\
		return &leaf[subkey];						\
	}												\
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
```

我们来看一下,在`rtree`中的查找函数`rtree_leaf_elm_lookup_hard`:

```c
/* 执行查找操作
 * @param key 查找的key
 * @param init_missing 如果没有找到,就创建
 */
rtree_leaf_elm_t *
rtree_leaf_elm_lookup_hard(tsdn_t *tsdn, rtree_t *rtree, rtree_ctx_t *rtree_ctx,
    uintptr_t key, bool dependent, bool init_missing) {
	rtree_node_elm_t *node; /* 基数树中间节点 */
	rtree_leaf_elm_t *leaf; /* 基数树叶子节点 */
#if RTREE_HEIGHT > 1
	node = rtree->root;
#else
	leaf = rtree->root;
#endif

#define RTREE_GET_CHILD(level) {						\
		if (level != 0 && !dependent &&					\
		    unlikely(!rtree_node_valid(node))) {		\
			return NULL;								\
		}												\
		uintptr_t subkey = rtree_subkey(key, level);	\
		if (level + 2 < RTREE_HEIGHT) {					\
			node = init_missing ?						\
			    rtree_child_node_read(tsdn, rtree,		\
			    &node[subkey], level, dependent) :		\
			    rtree_child_node_tryread(&node[subkey],	\
			    dependent);								\
		} else {						   				\
			leaf = init_missing ?						\
			    rtree_child_leaf_read(tsdn, rtree,		\
			    &node[subkey], level, dependent) :		\
			    rtree_child_leaf_tryread(&node[subkey],	\
			    dependent);								\
		}												\
	}
	/*
	 * Cache replacement upon hard lookup (i.e. L1 & L2 rtree cache miss):
	 * (1) evict last entry in L2 cache; (2) move the collision slot from L1
	 * cache down to L2; and 3) fill L1.
	 */
#define RTREE_GET_LEAF(level) {						\
		if (!dependent && unlikely(!rtree_leaf_valid(leaf))) {	\
			return NULL;							\
		}											\
		if (RTREE_CTX_NCACHE_L2 > 1) {				\
			memmove(&rtree_ctx->l2_cache[1],		\
			    &rtree_ctx->l2_cache[0],			\
			    sizeof(rtree_ctx_cache_elm_t) *		\
			    (RTREE_CTX_NCACHE_L2 - 1));			\
		}											\
		size_t slot = rtree_cache_direct_map(key);	\
		rtree_ctx->l2_cache[0].leafkey =			\
		    rtree_ctx->cache[slot].leafkey;			\
		rtree_ctx->l2_cache[0].leaf =				\
		    rtree_ctx->cache[slot].leaf;			\
		uintptr_t leafkey = rtree_leafkey(key);		\
		rtree_ctx->cache[slot].leafkey = leafkey;	\
		rtree_ctx->cache[slot].leaf = leaf;			\
		uintptr_t subkey = rtree_subkey(key, level);\
		return &leaf[subkey];						\
	}
	if (RTREE_HEIGHT > 1) {
		RTREE_GET_CHILD(0) /* 找到第0层的节点 */
	}
	if (RTREE_HEIGHT > 2) {
		RTREE_GET_CHILD(1) /* 找到第1层的节点 */
	}
	if (RTREE_HEIGHT > 3) {
		for (unsigned i = 2; i < RTREE_HEIGHT-1; i++) {
			RTREE_GET_CHILD(i) /* 这里会更新rtree_ctx,加快下一次的查找速度 */
		}
	}
	RTREE_GET_LEAF(RTREE_HEIGHT-1)
#undef RTREE_GET_CHILD
#undef RTREE_GET_LEAF
	not_reached();
}
```

如果查找的时候,没有找到对应的中间节点,会调用`rtree_child_node_read`:

```c
/* 创建节点 */
static rtree_node_elm_t *
rtree_node_init(tsdn_t *tsdn, rtree_t *rtree, unsigned level,
    atomic_p_t *elmp) {
	malloc_mutex_lock(tsdn, &rtree->init_lock);
	/*
	 * If *elmp is non-null, then it was initialized with the init lock
	 * held, so we can get by with 'relaxed' here.
	 */
	rtree_node_elm_t *node = atomic_load_p(elmp, ATOMIC_RELAXED);
	if (node == NULL) {
		node = rtree_node_alloc(tsdn, rtree, ZU(1) <<
		    rtree_levels[level].bits); /* 注意这里分配的数组的大小也是非常夸张的 */
		if (node == NULL) {
			malloc_mutex_unlock(tsdn, &rtree->init_lock);
			return NULL;
		}
		/*
		 * Even though we hold the lock, a later reader might not; we
		 * need release semantics.
		 */
		atomic_store_p(elmp, node, ATOMIC_RELEASE);
	}
	malloc_mutex_unlock(tsdn, &rtree->init_lock);
	return node;
}

/* 读取中间节点,如果没有的话,需要创建 */
static rtree_node_elm_t *
rtree_child_node_read(tsdn_t *tsdn, rtree_t *rtree, rtree_node_elm_t *elm,
    unsigned level, bool dependent) {
	rtree_node_elm_t *node;

	node = rtree_child_node_tryread(elm, dependent);
	if (!dependent && unlikely(!rtree_node_valid(node))) {
		node = rtree_node_init(tsdn, rtree, level + 1, &elm->child);
	}
	return node;
}
```

如果查找的时候,没有找到对应的叶子节点,会调用:

```c
static rtree_leaf_elm_t *
rtree_leaf_init(tsdn_t *tsdn, rtree_t *rtree, atomic_p_t *elmp) {
	malloc_mutex_lock(tsdn, &rtree->init_lock);
	/*
	 * If *elmp is non-null, then it was initialized with the init lock
	 * held, so we can get by with 'relaxed' here.
	 */
	rtree_leaf_elm_t *leaf = atomic_load_p(elmp, ATOMIC_RELAXED);
	if (leaf == NULL) {
		leaf = rtree_leaf_alloc(tsdn, rtree, ZU(1) <<
		    rtree_levels[RTREE_HEIGHT-1].bits); /* 这里使用的是另外一套内存分配器 */
		if (leaf == NULL) {
			malloc_mutex_unlock(tsdn, &rtree->init_lock);
			return NULL;
		}
		/*
		 * Even though we hold the lock, a later reader might not; we
		 * need release semantics.
		 */
		atomic_store_p(elmp, leaf, ATOMIC_RELEASE);
	}
	malloc_mutex_unlock(tsdn, &rtree->init_lock);
	return leaf;
}

static rtree_leaf_elm_t *
rtree_child_leaf_tryread(rtree_node_elm_t *elm, bool dependent) {
	rtree_leaf_elm_t *leaf;

	if (dependent) {
		leaf = (rtree_leaf_elm_t *)atomic_load_p(&elm->child, ATOMIC_RELAXED);
	} else {
		leaf = (rtree_leaf_elm_t *)atomic_load_p(&elm->child, ATOMIC_ACQUIRE);
	}
	return leaf;
}

static rtree_leaf_elm_t *
rtree_child_leaf_read(tsdn_t *tsdn, rtree_t *rtree, rtree_node_elm_t *elm,
    unsigned level, bool dependent) {
	rtree_leaf_elm_t *leaf;

	leaf = rtree_child_leaf_tryread(elm, dependent);
	if (!dependent && unlikely(!rtree_leaf_valid(leaf))) {
		leaf = rtree_leaf_init(tsdn, rtree, &elm->child);
	}
	assert(!dependent || leaf != NULL);
	return leaf;
}
```

## 2.4 rtree的查找

查找的内容其实已经包含到了基数树的插入部分.

```c
JEMALLOC_ALWAYS_INLINE rtree_leaf_elm_t *
rtree_read(tsdn_t *tsdn, rtree_t *rtree, rtree_ctx_t *rtree_ctx, uintptr_t key,
    bool dependent) {
	rtree_leaf_elm_t *elm = rtree_leaf_elm_lookup(tsdn, rtree, rtree_ctx,
	    key, dependent, false); /* 注意这里的false,表示没有找到,就不创建 */
	if (!dependent && elm == NULL) {
		return NULL;
	}
	return elm;
}
```

## 2.5 其他

1. 基数树中的叶子表项中,记录的是`extent`,`sind`, `slab`信息.

2. 实际上,`rtree`只有一个实例, `extent_rtree`,初始化函数如下:

```c
// extent.c
rtree_t		extents_rtree;

/* extent模块的初始化 */
bool
extent_boot(void) {
    if (rtree_new(&extents_rtree, true)) { /* 创建基数树,用于快速索引 */
        return true;
    }

    if (mutex_pool_init(&extent_mutex_pool, "extent_mutex_pool",
                        WITNESS_RANK_EXTENT_POOL)) {
        return true;
    }

    if (have_dss) {
        extent_dss_boot();
    }

    return false;
}
```

   