/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2018, DUKELEC, Inc.
 * All rights reserved.
 *
 * Reference and copy from:
 *  https://www.remlab.net/op/futex-condvar.shtml
 *  https://locklessinc.com/articles/locks/
 *  https://locklessinc.com/articles/mutex_cv_futex/
 *
 * TODO: use priority-inheritance futexes
 *
 * Organized by: Duke Fong <duke@dukelec.com>
 */

#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <limits.h>

#include "cd_utils.h"
#include "cd_debug.h"
#include "cd_futex.h"

#define atomic_xadd(P, V)       __sync_fetch_and_add((P), (V))
#define cmpxchg(P, O, N)        __sync_val_compare_and_swap((P), (O), (N))
#define atomic_inc(P)           __sync_add_and_fetch((P), 1)
#define atomic_dec(P)           __sync_add_and_fetch((P), -1)
#define atomic_add(P, V)        __sync_add_and_fetch((P), (V))
#define atomic_set_bit(P, V)    __sync_or_and_fetch((P), 1<<(V))
#define atomic_clear_bit(P, V)  __sync_and_and_fetch((P), ~(1<<(V)))

/* Pause instruction to prevent excess processor bus usage */
#define cpu_relax() asm volatile("pause\n": : :"memory")

/* Atomic exchange (of various sizes) */
static inline void *xchg_64(void *ptr, void *x)
{
    __asm__ __volatile__("xchgq %0,%1"
                :"=r" ((unsigned long long) x)
                :"m" (*(volatile long long *)ptr), "0" ((unsigned long long) x)
                :"memory");

    return x;
}

static inline unsigned xchg_32(void *ptr, unsigned x)
{
    __asm__ __volatile__("xchgl %0,%1"
                :"=r" ((unsigned) x)
                :"m" (*(volatile unsigned *)ptr), "0" (x)
                :"memory");

    return x;
}


static int sys_futex(void *addr1, int op, int val1,
        struct timespec *timeout, void *addr2, int val3)
{
    return syscall(SYS_futex, addr1, op, val1, timeout, addr2, val3);
}


int cd_mutex_init(cd_mutex_t *m, void *_a)
{
    (void) _a;
    *m = 0;
    return 0;
}

int cd_mutex_lock(cd_mutex_t *m)
{
    int i, c;

    /* Spin and try to take lock */
    for (i = 0; i < 100; i++)
    {
        c = cmpxchg(m, 0, 1);
        if (!c)
            return 0;

        cpu_relax();
    }

    /* The lock is now contended */
    if (c == 1)
        c = xchg_32(m, 2);

    while (c) {
        /* Wait in the kernel */
        sys_futex(m, FUTEX_WAIT, 2, NULL, NULL, 0);
        c = xchg_32(m, 2);
    }

    return 0;
}

int cd_mutex_unlock(cd_mutex_t *m)
{
    int i;

    /* Unlock, and if not contended then exit. */
    if (*m == 2)
        *m = 0;
    else if (xchg_32(m, 0) == 1)
        return 0;

    /* Spin and hope someone takes the lock */
    for (i = 0; i < 200; i++) {
        if (*m) {
            /* Need to set to state 2 because there may be waiters */
            if (cmpxchg(m, 1, 2))
                return 0;
        }
        cpu_relax();
    }

    /* We need to wake someone up */
    sys_futex(m, FUTEX_WAKE, 1, NULL, NULL, 0);

    return 0;
}

int cd_mutex_trylock(cd_mutex_t *m)
{
    /* Try to take the lock, if is currently unlocked */
    unsigned c = cmpxchg(m, 0, 1);
    if (!c)
        return 0;
    return EBUSY;
}


int cd_cond_init(cd_cond_t *c, void *_a)
{
    (void) _a;

    /* Sequence variable doesn't actually matter, but keep valgrind happy */
    c->seq = 0;

    return 0;
}

int cd_cond_signal(cd_cond_t *c)
{
    /* We are waking someone up */
    atomic_add(&c->seq, 1);

    /* Wake up a thread */
    sys_futex(&c->seq, FUTEX_WAKE, 1, NULL, NULL, 0);

    return 0;
}

int cd_cond_broadcast(cd_cond_t *c)
{
    /* We are waking everyone up */
    atomic_add(&c->seq, 1);

    /* Wake one thread, and requeue the rest on the mutex */
    sys_futex(&c->seq, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);

    return 0;
}

int cd_cond_wait(cd_cond_t *c, cd_mutex_t *m)
{
    int seq = c->seq;

    cd_mutex_unlock(m);

    sys_futex(&c->seq, FUTEX_WAIT, seq, NULL, NULL, 0);

    while (xchg_32(m, 2))
        sys_futex(m, FUTEX_WAIT, 2, NULL, NULL, 0);

    return 0;
}

