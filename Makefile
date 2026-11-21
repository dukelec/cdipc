#
# Software License Agreement (MIT License)
#
# Copyright (c) 2017, DUKELEC, Inc.
# All rights reserved.
#
# Author: Duke Fong <duke@dukelec.com>
#

ifeq ($(PREFIX),)
	PREFIX := /usr/local
endif

main:
	$(MAKE) -C cdipc
	$(MAKE) -C tools/cli_tool
	$(MAKE) -C bindings/python

test:
	$(MAKE) -C cdipc
	$(MAKE) -C tests test

test-ws: main
	$(MAKE) -C tests test-ws

.PHONY: clean test test-ws

clean:
	$(MAKE) -C cdipc clean
	$(MAKE) -C tools/cli_tool clean
	$(MAKE) -C bindings/python clean
	$(MAKE) -C tests clean

install:
	$(MAKE) -C cdipc install
	$(MAKE) -C tools/cli_tool install
	$(MAKE) -C bindings/python install
	install -m 755 tools/cdipc_ws_server.py $(DESTDIR)$(PREFIX)/bin/

