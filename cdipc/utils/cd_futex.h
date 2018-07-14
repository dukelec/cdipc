/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2018, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author: Duke Fong <duke@dukelec.com>
 */

#ifndef __CD_FUTEX_H__
#define __CD_FUTEX_H__

typedef int cd_mutex_t;

typedef struct {
    cd_mutex_t  c;
    cd_mutex_t  m;
} cd_cond_t;

int cd_mutex_init(cd_mutex_t *m, void *_a);
int cd_mutex_lock(cd_mutex_t *m, int tid, const struct timespec *abstime);
int cd_mutex_unlock(cd_mutex_t *m, int tid);
int cd_mutex_trylock(cd_mutex_t *m, int tid);

int cd_cond_init(cd_cond_t *c, void *_a);
int cd_cond_signal(cd_cond_t *c);
int cd_cond_broadcast(cd_cond_t *c);
int cd_cond_wait(cd_cond_t *c, cd_mutex_t *m, int tid,
        const struct timespec *abstime);

#endif
