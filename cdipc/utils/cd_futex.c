/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2018, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author: Duke Fong <d@d-l.io>
 */

#include <pthread.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <limits.h>
#include <unistd.h>

#include "cd_utils.h"
#include "cd_debug.h"
#include "cd_futex.h"

static __thread int _tid = 0;

#define b_cmpxchg(P, O, N)  __sync_bool_compare_and_swap((P), (O), (N))


static int sys_futex(void *addr1, int op, int val1,
        const struct timespec *timeout, void *addr2, int val3)
{
    // FUTEX_CMP_REQUEUE_PI returns a positive count on success
    return syscall(SYS_futex, addr1, op, val1, timeout, addr2, val3) < 0 ? errno : 0;
}

static void tid_reset(void)
{
    _tid = 0;
}

// a forked child must not keep using the parent's tid
__attribute__((constructor)) static void tid_init(void)
{
    pthread_atfork(NULL, NULL, tid_reset);
}

static int get_tid(void)
{
    if (!_tid)
        _tid = syscall(SYS_gettid);
    return _tid;
}


int cd_mutex_init(cd_mutex_t *m, void *_a)
{
    (void) _a;
    *m = 0;
    return 0;
}

int cd_mutex_lock(cd_mutex_t *m, const struct timespec *abstime)
{
    int r, retry = 0;
    int tid = get_tid();

    if (b_cmpxchg(m, 0, tid))
        return 0;

    while (true) {
        int v = *m;
        // absolute timeout, measured against the CLOCK_REALTIME
        // if m == 0, set m to cur pid
        // if m != 0, set FUTEX_WAITERS of m
        // all 0 and NULL are ignored
        r = sys_futex(m, FUTEX_LOCK_PI, 0, abstime, NULL, 0);

        // owner died with waiters: EINVAL until the waiter that kernel picked fixes the tid
        if (r == EINVAL && retry++ < 1000) {
            usleep(1000);
            continue;
        }
        if (r != ESRCH)
            return r;

        // owner died holding the lock, take over if the same dead tid is still there
        int cur = *m;
        if ((cur & FUTEX_TID_MASK) && !((cur ^ v) & FUTEX_TID_MASK) && b_cmpxchg(m, cur, tid))
            return EOWNERDEAD;
    }
}

int cd_mutex_unlock(cd_mutex_t *m)
{
    if (b_cmpxchg(m, get_tid(), 0))
        return 0;

    // all 0 and NULL are ignored
    return sys_futex(m, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
}

int cd_mutex_trylock(cd_mutex_t *m)
{
    if (b_cmpxchg(m, 0, get_tid()))
        return 0;

    // all 0 and NULL are ignored
    return sys_futex(m, FUTEX_TRYLOCK_PI, 0, NULL, NULL, 0);
}


int cd_cond_init(cd_cond_t *c, void *_a)
{
    (void) _a;
    c->c = 0;
    c->m = 0;
    c->w = 0;
    return 0;
}

// wake one waiter, requeue up to nr_requeue more onto c->m
static int cond_wake(cd_cond_t *c, int nr_requeue)
{
    int r, retry = 0;

    __sync_fetch_and_add(&c->c, 1);
    if (!c->w)
        return 0;

    while (true) {
        r = sys_futex(&c->c, FUTEX_CMP_REQUEUE_PI, 1,
                (void *)(long)nr_requeue, &c->m, c->c);
        // return EAGAIN if *addr1 != val3 at the time of the call

        if (r == ESRCH) { // c->m is held by a dead waiter, reset it
            b_cmpxchg(&c->m, c->m, 0);
        } else if (r == EINVAL && retry++ < 1000) { // c->m is being handed over, as in cd_mutex_lock
            usleep(1000);
        } else {
            return r;
        }
    }
}

int cd_cond_signal(cd_cond_t *c)
{
    return cond_wake(c, 0);
}

int cd_cond_broadcast(cd_cond_t *c)
{
    return cond_wake(c, INT_MAX);
}

int cd_cond_wait(cd_cond_t *c, cd_mutex_t *m, const struct timespec *abstime)
{
    int r;
    int seq;

    seq = c->c;
    c->w++;
    cd_mutex_unlock(m);

    // val3 (last arg) is ignored
    r = sys_futex(&c->c, FUTEX_WAIT_REQUEUE_PI, seq, abstime, &c->m, 0);
    // return EAGAIN if *addr1 != val1 at the time of the call

    if (!r) // only success returns with c->m held
        cd_mutex_unlock(&c->m);

    cd_mutex_lock(m, NULL);
    c->w--;
    return r == EAGAIN ? 0 : r;
}
