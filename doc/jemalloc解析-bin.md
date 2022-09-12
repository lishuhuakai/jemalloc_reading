# 1. 结构体定义

## 1.1 bin

`bin`结构体主要用来存放`slab`(用于小内存分配的`extent`的别名).

```c
typedef struct bin_s bin_t;

struct bin_s {
	/* All operations on bin_t fields require lock ownership. */
	malloc_mutex_t		lock;

	/*
	 * Current slab being used to service allocations of this bin's size
	 * class.  slabcur is independent of slabs_{nonfull,full}; whenever
	 * slabcur is reassigned, the previous slab must be deallocated or
	 * inserted into slabs_{nonfull,full}.
	 */
	extent_t		*slabcur; /* 当前正在使用的slab */

	/*
	 * Heap of non-full slabs.  This heap is used to assure that new
	 * allocations come from the non-full slab that is oldest/lowest in
	 * memory.
	 */
	extent_heap_t		slabs_nonfull;  /* 非满slab */

	/* List used to track full slabs. */
	extent_list_t		slabs_full; /* 满slab */
	// ...
};

/* A set of sharded bins of the same size class. */
typedef struct bins_s bins_t;
struct bins_s {
	/* Sharded bins.  Dynamically sized. */
	bin_t *bin_shards;
};
```

在arena结构中,有这样一个字段 `bins_t bins[SC_NBINS]`,专门用于记录与此`arena`相关联的`bin`,一个size class对应数组中的一个实例.

## 1.2 bin_info

`bin_info`实例和`bin`关系密切,主要用于描述`bin`.

```c
/* bin(容器)中包含很多extents,它们被slab分配器使用 */

/*
 * Read-only information associated with each element of arena_t's bins array
 * is stored separately, partly to reduce memory usage (only one copy, rather
 * than one per arena), but mainly to avoid false cacheline sharing.
 *
 * Each slab has the following layout:
 *
 *   /--------------------\
 *   | region 0           |
 *   |--------------------|
 *   | region 1           |
 *   |--------------------|
 *   | ...                |
 *   | ...                |
 *   | ...                |
 *   |--------------------|
 *   | region nregs-1     |
 *   \--------------------/
 */
typedef struct bin_info_s bin_info_t;
/* bin的描述信息 */
struct bin_info_s {
	/* Size of regions in a slab for this bin's size class. */
	size_t			reg_size;  /* 每个region的大小 */

	/* Total size of a slab for this bin's size class. */
	size_t			slab_size; /* size class的完整大小 */

	/* Total number of regions in a slab for this bin's size class. */
	uint32_t		nregs; /* region的个数 */

	/* Number of sharded bins in each arena for this size class. */
	uint32_t		n_shards;

	/*
	 * Metadata used to manipulate bitmaps for slabs associated with this
	 * bin.
	 */
	bitmap_info_t		bitmap_info;
};
```



# 2. bin相关的操作函数

## 2.1 bin的初始化

```c
bool
bin_init(bin_t *bin) {
	if (malloc_mutex_init(&bin->lock, "bin", WITNESS_RANK_BIN, malloc_mutex_rank_exclusive)) {
		return true;
	}
	bin->slabcur = NULL;
	extent_heap_new(&bin->slabs_nonfull);
	extent_list_init(&bin->slabs_full);
	return false;
}
```

在`jemalloc`整个系统初始化的时候,会调用`bin_boot`来初始化`bin`这个子模块.

```c
bin_info_t bin_infos[SC_NBINS]; /* 全局变量 */

void
bin_boot(sc_data_t *sc_data, unsigned bin_shard_sizes[SC_NBINS]) {
	assert(sc_data->initialized);
	bin_infos_init(sc_data, bin_shard_sizes, bin_infos); /* 使用size class的信息来初始化bin_info */
}
```

`bin_infos_init`做的事情很简单,那就是用一个`bin_info`来描述一个size class.

```c
/* 初始化bin_infos数组
 * @param sc_data
 */
static void
bin_infos_init(sc_data_t *sc_data, unsigned bin_shard_sizes[SC_NBINS],
    bin_info_t bin_infos[SC_NBINS]) {
    /* 前SC_NBINS个 */
	for (unsigned i = 0; i < SC_NBINS; i++) {
		bin_info_t *bin_info = &bin_infos[i];
		sc_t *sc = &sc_data->sc[i]; /* 获得第i个size class */
		bin_info->reg_size = ((size_t)1U << sc->lg_base)+ ((size_t)sc->ndelta << sc->lg_delta); /* 每一个region的大小 */
		bin_info->slab_size = (sc->pgs << LG_PAGE); /* bin中管理的slab的大小 */
		bin_info->nregs =
		    (uint32_t)(bin_info->slab_size / bin_info->reg_size); /* 每一个slab可以划分的region的个数 */
		bin_info->n_shards = bin_shard_sizes[i];
		bitmap_info_t bitmap_info = BITMAP_INFO_INITIALIZER(bin_info->nregs); /* 分配位图信息 */
		bin_info->bitmap_info = bitmap_info;
	}
}
```

