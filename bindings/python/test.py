#!/usr/bin/env python3
# Software License Agreement (MIT License)
#
# Copyright (c) 2018, DUKELEC, Inc.
# All rights reserved.
#
# Author: Duke Fong <duke@dukelec.com>

from cdipc import *
import signal

signal.signal(signal.SIGINT, signal.SIG_DFL) # allow exit by ctrl-c

now = timespec()
abstime = timespec()

ch = cdipc_ch_t()
cdipc_open(ch, "test", CDIPC_SUB, 0)
cdipc_recover(ch)

clock_gettime(CLOCK_MONOTONIC, now)
us2tv(tv2us(now) + 5000 * 1000, abstime);
nd = cdipc_sub_get(ch, abstime)

if nd:
    print('read data:', buf_read(nd.dat, nd.len))
    buf_write(nd.dat, b'new-dat')
    nd.len = len(b'new-dat')
    print('after modify data:', buf_read(nd.dat, nd.len))
    cdipc_sub_free(ch, nd)
else:
    print('timeout')

