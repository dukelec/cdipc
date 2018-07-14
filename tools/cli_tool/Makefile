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

INCLUDES = \
../.. \
.

C_SOURCES = \
cdipc_tool.c


GIT_VERSION := $(shell git describe --dirty --always --tags)

CC = gcc

BUILD_DIR = build
TARGET = cdipc

OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(C_SOURCES)))

I_INCLUDES = $(foreach includedir,$(INCLUDES),-I$(includedir))
CFLAGS = $(I_INCLUDES) -DSW_VER=\"$(GIT_VERSION)\"
LDFLAGS = -lcdipc -lrt

DEPS = $(foreach includedir,$(INCLUDES),$(wildcard $(includedir)/*.h))

$(BUILD_DIR)/%.o: %.c $(DEPS) Makefile | $(BUILD_DIR)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR):
	mkdir $@

.PHONY: clean

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

install:
	install -d $(DESTDIR)$(PREFIX)/bin/
	install -m 755 cdipc $(DESTDIR)$(PREFIX)/bin/

