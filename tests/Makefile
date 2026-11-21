#
# Software License Agreement (MIT License)
#
# Copyright (c) 2026, DUKELEC, Inc.
# All rights reserved.
#
# Author: Duke Fong <duke@dukelec.com>
#

CFLAGS = -I.. -O2 -Wall -MMD -MP
LDLIBS = -L../cdipc -lcdipc -lpthread -lrt
RUN = LD_LIBRARY_PATH=$(CURDIR)/../cdipc

TARGETS = test_cdipc stress

all: $(TARGETS)

$(TARGETS): %: %.c Makefile ../cdipc/libcdipc.so
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

-include $(TARGETS:=.d)

test: all
	$(RUN) ./test_cdipc
	$(RUN) ./stress normal 3
	$(RUN) ./stress kill 3

test-ws:
	$(RUN) PYTHONPATH=$(CURDIR)/../bindings/python python3 test_ws_server.py

.PHONY: all test test-ws clean

clean:
	rm -f $(TARGETS) $(TARGETS:=.d)
