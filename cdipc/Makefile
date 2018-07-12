#
# Software License Agreement (MIT License)
#
# Copyright (c) 2018, DUKELEC, Inc.
# All rights reserved.
#
# Author: Duke Fong <duke@dukelec.com>
#

INCLUDES = \
./utils \
./

C_SOURCES = \
./cdipc.c \
./utils/rlist.c \
./utils/cd_futex.c


GIT_VERSION := $(shell git describe --dirty --always --tags)

CC = gcc

BUILD_DIR = build
TARGET = libcdipc.so

OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(C_SOURCES)))

I_INCLUDES = $(foreach includedir,$(INCLUDES),-I$(includedir))
CFLAGS = $(I_INCLUDES) -DSW_VER=\"$(GIT_VERSION)\" -fPIC
LDFLAGS = -lrt -shared

DEPS = $(foreach includedir,$(INCLUDES),$(wildcard $(includedir)/*.h))

$(BUILD_DIR)/%.o: %.c $(DEPS) Makefile | $(BUILD_DIR)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJECTS)
	gcc -o $@ $^ $(LDFLAGS)

$(BUILD_DIR):
	mkdir $@

.PHONY: clean

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

