#ifndef JEMALLOC_INTERNAL_PROF_STRUCTS_H
#define JEMALLOC_INTERNAL_PROF_STRUCTS_H

#include "jemalloc/internal/ckh.h"
#include "jemalloc/internal/mutex.h"
#include "jemalloc/internal/prng.h"
#include "jemalloc/internal/rb.h"

/* 记录回溯的堆栈 */
struct prof_bt_s {
	/* Backtrace, stored as len program counters. */
	void		**vec;  /* 每一层地址 */
	unsigned	len;    /* 层数 */
};

#ifdef JEMALLOC_PROF_LIBGCC
/* Data structure passed to libgcc _Unwind_Backtrace() callback functions. */
typedef struct {
	prof_bt_t	*bt;
	unsigned	max;
} prof_unwind_data_t;
#endif

struct prof_accum_s {
#ifndef JEMALLOC_ATOMIC_U64
	malloc_mutex_t	mtx;
	uint64_t	accumbytes; /* 累计分配了多少字节 */
#else
	atomic_u64_t	accumbytes;
#endif
};

struct prof_cnt_s {
	/* Profiling counters. */
	uint64_t	curobjs;     /* 分配的object的数目 */
	uint64_t	curbytes;    /* 分配的字节数 */
	uint64_t	accumobjs;   /* 累计分配的object的数目 */
	uint64_t	accumbytes; /* 累计分配的字节数 */
};

typedef enum {
	prof_tctx_state_initializing, /* 有一个线程正在初始化这个结构 */
	prof_tctx_state_nominal,
	prof_tctx_state_dumping,
	prof_tctx_state_purgatory /* Dumper must finish destroying. */
} prof_tctx_state_t;

/* prof thread context */
struct prof_tctx_s {
	/* Thread data for thread that performed the allocation. */
	prof_tdata_t		*tdata; /* 执行分配操作的线程的thread data */

	/*
	 * Copy of tdata->thr_{uid,discrim}, necessary because tdata may be
	 * defunct during teardown.
	 */
	uint64_t		thr_uid;
	uint64_t		thr_discrim;

	/* Profiling counters, protected by tdata->lock. */
	prof_cnt_t		cnts;

	/* Associated global context. */
	prof_gctx_t		*gctx;

	/*
	 * UID that distinguishes multiple tctx's created by the same thread,
	 * but coexisting in gctx->tctxs.  There are two ways that such
	 * coexistence can occur:
	 * - A dumper thread can cause a tctx to be retained in the purgatory
	 *   state.
	 * - Although a single "producer" thread must create all tctx's which
	 *   share the same thr_uid, multiple "consumers" can each concurrently
	 *   execute portions of prof_tctx_destroy().  prof_tctx_destroy() only
	 *   gets called once each time cnts.cur{objs,bytes} drop to 0, but this
	 *   threshold can be hit again before the first consumer finishes
	 *   executing prof_tctx_destroy().
	 */
	uint64_t		tctx_uid;

	/* Linkage into gctx's tctxs. */
	rb_node(prof_tctx_t)	tctx_link;

	/*
	 * True during prof_alloc_prep()..prof_malloc_sample_object(), prevents
	 * sample vs destroy race.
	 */
	bool			prepared;

	/* Current dump-related state, protected by gctx->lock. */
	prof_tctx_state_t	state;

	/*
	 * Copy of cnts snapshotted during early dump phase, protected by
	 * dump_mtx.
	 */
	prof_cnt_t		dump_cnts;
};
typedef rb_tree(prof_tctx_t) prof_tctx_tree_t;

/* prof global context */
struct prof_gctx_s {
	/* Protects nlimbo, cnt_summed, and tctxs. */
	malloc_mutex_t		*lock;

	/*
	 * Number of threads that currently cause this gctx to be in a state of
	 * limbo due to one of:
	 *   - Initializing this gctx.
	 *   - Initializing per thread counters associated with this gctx.
	 *   - Preparing to destroy this gctx.
	 *   - Dumping a heap profile that includes this gctx.
	 * nlimbo must be 1 (single destroyer) in order to safely destroy the
	 * gctx.
	 */
	/* limbo -- 处于不定的状态 */
	unsigned		nlimbo; /* 由于是多线程,nlimbo类似于引用计数 */

	/*
	 * Tree of profile counters, one for each thread that has allocated in
	 * this context.
	 */
	prof_tctx_tree_t	tctxs; /* 这里事实上是一颗红黑树,记录了每个线程的分配信息 */

	/* Linkage for tree of contexts to be dumped. */
	rb_node(prof_gctx_t)	dump_link;

	/* Temporary storage for summation during dump. */
	prof_cnt_t		cnt_summed; /* 临时变量,主要用于统计分配了多少字节,多少object */

	/* Associated backtrace. */
	prof_bt_t		bt; /* 记录下对应的堆栈信息 */

	/* Backtrace vector, variable size, referred to by bt. */
	void			*vec[1];
};
typedef rb_tree(prof_gctx_t) prof_gctx_tree_t;

/* 线程的prof信息 */
struct prof_tdata_s {
	malloc_mutex_t		*lock;

	/* Monotonically increasing unique thread identifier. */
	uint64_t		thr_uid;

	/*
	 * Monotonically increasing discriminator among tdata structures
	 * associated with the same thr_uid.
	 */
	uint64_t		thr_discrim;

	/* Included in heap profile dumps if non-NULL. */
	char			*thread_name;

	bool			attached;
	bool			expired;

	rb_node(prof_tdata_t)	tdata_link;

	/*
	 * Counter used to initialize prof_tctx_t's tctx_uid.  No locking is
	 * necessary when incrementing this field, because only one thread ever
	 * does so.
	 */
	uint64_t		tctx_uid_next;

	/*
	 * Hash of (prof_bt_t *)-->(prof_tctx_t *).  Each thread tracks
	 * backtraces for which it has non-zero allocation/deallocation counters
	 * associated with thread-specific prof_tctx_t objects.  Other threads
	 * may write to prof_tctx_t contents when freeing associated objects.
	 */
	ckh_t			bt2tctx; /* hash表,key (prof_bt_t *), val(prof_tctx_t) */

	/* Sampling state. */
	uint64_t		prng_state;

	/* State used to avoid dumping while operating on prof internals. */
	bool			enq;
	bool			enq_idump;
	bool			enq_gdump;

	/*
	 * Set to true during an early dump phase for tdata's which are
	 * currently being dumped.  New threads' tdata's have this initialized
	 * to false so that they aren't accidentally included in later dump
	 * phases.
	 */
	bool			dumping;

	/*
	 * True if profiling is active for this tdata's thread
	 * (thread.prof.active mallctl).
	 */
	bool			active;

	/* Temporary storage for summation during dump. */
	prof_cnt_t		cnt_summed;

	/* Backtrace vector, used for calls to prof_backtrace(). */
	void			*vec[PROF_BT_MAX];
};
typedef rb_tree(prof_tdata_t) prof_tdata_tree_t;

#endif /* JEMALLOC_INTERNAL_PROF_STRUCTS_H */
