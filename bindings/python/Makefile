#
# Software License Agreement (MIT License)
#
# Copyright (c) 2017, DUKELEC, Inc.
# All rights reserved.
#
# Author: Duke Fong <duke@dukelec.com>
#

ifeq ($(PY_SITE_DIR),)
	PY_SITE_DIR := $(shell python3 -c "import site; print(site.getsitepackages()[0])")
endif

PY_INC_DIR := $(shell python3 -c "import sysconfig; print(sysconfig.get_paths()['include'])")

BUILD_DIR = build

INCLUDES = \
../..

C_SOURCES = \
$(BUILD_DIR)/swig_cdipc_wrap.c


GIT_VERSION := $(shell git describe --dirty --always --tags)

CC = gcc

TARGET = _cdipc.so

OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(C_SOURCES)))

I_INCLUDES = $(foreach includedir,$(INCLUDES),-I$(includedir))
CFLAGS = $(I_INCLUDES) -DSW_VER=\"$(GIT_VERSION)\" -fPIC -I$(PY_INC_DIR)
LDFLAGS = -lcdipc -lpthread -lrt -shared

DEPS = $(foreach includedir,$(INCLUDES),$(wildcard $(includedir)/*.h))

main: $(TARGET)
	@

$(BUILD_DIR)/swig_cdipc_wrap.c: ../swig_cdipc.i | $(BUILD_DIR)
	swig -o $(BUILD_DIR)/swig_cdipc_wrap.c -outdir ./ -python ../swig_cdipc.i

$(BUILD_DIR)/%.o: %.c $(DEPS) Makefile | $(BUILD_DIR)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR):
	mkdir $@

.PHONY: clean

clean:
	rm -rf cdipc.py $(BUILD_DIR) $(TARGET)

install:
	install -m 644 _cdipc.so $(PY_SITE_DIR)/
	install -m 644 cdipc.py $(PY_SITE_DIR)/
	install -m 644 cd_args.py $(PY_SITE_DIR)/

