# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2013-2019 Xilinx, Inc.

CWARNINGS	:= -Wall -Wundef -Wstrict-prototypes -Wpointer-arith \
		   -Wnested-externs

PYTHON_VER	:= $(shell python3 -V 2>&1 | \
			sed 's/Python \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/')
PYTHON_VER_MAJOR:= $(shell python3 -V 2>&1 | \
			sed 's/Python \([0-9][0-9]*\)\.[0-9][0-9]*.*/\1/')
PYTHON_CFLAGS	+= $(shell python3-config --cflags 2>/dev/null)
PYTHON_LIBS	:= $(shell python3-config --libs 2>/dev/null)

ifeq ($(PYTHON_CFLAGS),)
PYTHON_CFLAGS	:= -fno-strict-aliasing -fPIC -I/usr/include/python$(PYTHON_VER)
PYTHON_LIBS	:= -lpython$(PYTHON_VER)
endif

# On SLES11, '$ python-config --cflags' doesn't include -fPIC but it
# is needed to properly compile PYTHON_SRCS.
PYTHON_CFLAGS   += -fPIC

CFLAGS += $(PYTHON_CFLAGS)
CFLAGS += -Werror $(CWARNINGS) -g -O2 -DNDEBUG
LIBS   += $(PYTHON_LIBS)

MMAKE_LIBS	:= $(LINK_CIUL_LIB) $(LINK_CPLANE_LIB)
MMAKE_LIB_DEPS	:= $(CIUL_LIB_DEPEND) $(CPLANE_LIB_DEPEND)

SRCS := filter_string cluster_protocol

OBJS := $(patsubst %,%.o,$(SRCS))

%.o: %.c
	$(CC) $(CFLAGS) $(MMAKE_INCLUDE) -c $< -o $@

all: cluster_protocol.so

cluster_protocol.so: $(OBJS) $(MMAKE_LIB_DEPS)
	$(CC) -shared -g -Wl,-E $^ $(MMAKE_LIBS) $(PYTHON_LIBS) -o $@

clean:
	@$(MakeClean)
	rm -f *.o *.so *.pyc
