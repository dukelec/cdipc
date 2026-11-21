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
CFLAGS = $(I_INCLUDES) -DSW_VER=\"$(GIT_VERSION)\" -fPIC -O2 -MMD -MP -I$(PY_INC_DIR)
LDFLAGS = -lcdipc -lpthread -lrt -shared -L../../cdipc

main: $(TARGET)
	@

$(BUILD_DIR)/swig_cdipc_wrap.c: ../swig_cdipc.i | $(BUILD_DIR)
	swig -MMD -MP -MF $(BUILD_DIR)/swig.d -threads -o $(BUILD_DIR)/swig_cdipc_wrap.c -outdir ./ -python ../swig_cdipc.i

$(BUILD_DIR)/%.o: %.c Makefile | $(BUILD_DIR)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR):
	mkdir $@

-include $(BUILD_DIR)/*.d

.PHONY: clean

clean:
	rm -rf cdipc.py $(BUILD_DIR) $(TARGET)

install:
	install -d $(DESTDIR)$(PY_SITE_DIR)/
	install -m 644 _cdipc.so $(DESTDIR)$(PY_SITE_DIR)/
	install -m 644 cdipc.py $(DESTDIR)$(PY_SITE_DIR)/
	install -m 644 cd_args.py $(DESTDIR)$(PY_SITE_DIR)/

