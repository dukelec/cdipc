/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2018, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author: Duke Fong <duke@dukelec.com>
 */

#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <limits.h>
#include <sys/types.h>
#include <stdatomic.h>

#include "cd_utils.h"
#include "cd_debug.h"
#include "cd_futex.h"

static __thread int _tid = 0;

#define b_cmpxchg(P, O, N)  __sync_bool_compare_and_swap((P), (O), (N))


static int sys_futex(void *addr1, int op, int val1,
        const struct timespec *timeout, void *addr2, int val3)
{
    int r = syscall(SYS_futex, addr1, op, val1, timeout, addr2, val3);

    return r == 0 ? 0 : errno;
}


int cd_mutex_init(cd_mutex_t *m, void *_a)
{
    (void) _a;
    *m = 0;
    return 0;
}

int cd_mutex_lock(cd_mutex_t *m, const struct timespec *abstime)
{
    if (!_tid)
        _tid = syscall(SYS_gettid);
    if (b_cmpxchg(m, 0, _tid))
        return 0;

    // absolute timeout, measured against the CLOCK_REALTIME
    // if m == 0, set m to cur pid
    // if m != 0, set FUTEX_WAITERS of m
    // all 0 and NULL are ignored
    return sys_futex(m, FUTEX_LOCK_PI, 0, abstime, NULL, 0);
}

int cd_mutex_unlock(cd_mutex_t *m)
{
    if (!_tid)
        _tid = syscall(SYS_gettid);
    if (b_cmpxchg(m, _tid, 0))
        return 0;

    // all 0 and NULL are ignored
    return sys_futex(m, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
}

int cd_mutex_trylock(cd_mutex_t *m)
{
    if (!_tid)
        _tid = syscall(SYS_gettid);
    if (b_cmpxchg(m, 0, _tid))
        return 0;

    // all 0 and NULL are ignored
    return sys_futex(m, FUTEX_TRYLOCK_PI, 0, NULL, NULL, 0);
}


int cd_cond_init(cd_cond_t *c, void *_a)
{
    (void) _a;
    c->c = 0;
    c->m = 0;
    return 0;
}

int cd_cond_signal(cd_cond_t *c)
{
    atomic_fetch_add(&c->c, 1);

    return sys_futex(&c->c, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &c->m, c->c);
    // return EAGAIN if *addr1 != val3 at the time of the call
}

int cd_cond_broadcast(cd_cond_t *c)
{
    int r;
    atomic_fetch_add(&c->c, 1);

    r = sys_futex(&c->c, FUTEX_CMP_REQUEUE_PI, 1, (void *)INT_MAX, &c->m, c->c);
    // return EAGAIN if *addr1 != val3 at the time of the call
    return r;
}

int cd_cond_wait(cd_cond_t *c, cd_mutex_t *m, const struct timespec *abstime)
{
    int r;
    int seq;

    seq = c->c;
    cd_mutex_unlock(m);

    // val3 (last arg) is ignored
    r = sys_futex(&c->c, FUTEX_WAIT_REQUEUE_PI, seq, abstime, &c->m, 0);
    // return EAGAIN if *addr1 != val1 at the time of the call

    cd_mutex_unlock(&c->m);

    cd_mutex_lock(m, NULL);
    return r == EAGAIN ? 0 : r;
}
