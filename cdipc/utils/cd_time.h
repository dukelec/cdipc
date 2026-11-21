/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2018, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author: Duke Fong <d@d-l.io>
 */

#ifndef __CD_TIME_H__
#define __CD_TIME_H__

#include <stdint.h>
#include <time.h>

#define NSEC_PER_SEC    (1000000000)

static inline int64_t tv2us(const struct timespec *tv)
{
        return ((int64_t)tv->tv_sec * NSEC_PER_SEC + tv->tv_nsec) / 1000;
}

static inline void us2tv(int64_t us, struct timespec *tv)
{
        int64_t u = us * 1000;
        tv->tv_nsec = u % NSEC_PER_SEC;
        tv->tv_sec = u / NSEC_PER_SEC;
}

#endif
