/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2018, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author: Duke Fong <duke@dukelec.com>
 */

#ifndef __CD_TIME_H__
#define __CD_TIME_H__

#define NSEC_PER_SEC    (1000000000)

static long tv2us(const struct timespec *tv)
{
        return (tv->tv_sec * NSEC_PER_SEC + tv->tv_nsec) / 1000;
}

static void us2tv(long us, struct timespec *tv)
{
        long long u = us * 1000;
        tv->tv_nsec = u % NSEC_PER_SEC;
        tv->tv_sec = u / NSEC_PER_SEC;
}

#endif
