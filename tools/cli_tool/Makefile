#
# Software License Agreement (MIT License)
#
# Copyright (c) 2017, DUKELEC, Inc.
# All rights reserved.
#
# Author: Duke Fong <d@d-l.io>
#

ifeq ($(PREFIX),)
	PREFIX := /usr/local
endif

INCLUDES = \
../.. \
.

C_SOURCES = \
cdipc_tool.c \
../../cdipc/utils/cd_list.c \
../../cdipc/utils/cd_args.c


GIT_VERSION := $(shell git describe --dirty --always --tags)

CC = gcc

BUILD_DIR = build
TARGET = cdipc

OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(C_SOURCES)))

I_INCLUDES = $(foreach includedir,$(INCLUDES),-I$(includedir))
CFLAGS = $(I_INCLUDES) -DSW_VER=\"$(GIT_VERSION)\" -O2 -Wall -MMD -MP
LDFLAGS = -lcdipc -lrt -L../../cdipc

$(BUILD_DIR)/%.o: %.c Makefile | $(BUILD_DIR)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR):
	mkdir $@

-include $(OBJECTS:.o=.d)

.PHONY: clean

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

install:
	install -d $(DESTDIR)$(PREFIX)/bin/
	install -m 755 cdipc $(DESTDIR)$(PREFIX)/bin/

