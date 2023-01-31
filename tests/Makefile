# SPDX-License-Identifier: MIT
# X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.


# XXX
ifndef SOLAR_CAPTURE_TREE
SOLAR_CAPTURE_TREE := ..
endif

INCDIRS += -I$(SOLAR_CAPTURE_TREE)/src/include \
	   -I$(ONLOAD_TREE)/src/include

CFLAGS := -g -Wall -Werror -pthread

LIBPATHS := -L$(SOLAR_CAPTURE_TREE)/src/
LIBS := -lsolarcapture -pthread -ldl -lm

APPS := two_threads #four_threads rss

all: $(patsubst %,%c,$(APPS))

%.o: %.c
	$(CC) $(CFLAGS) $(INCDIRS) -o $@ -c $<

%c: %.o
	$(CC) -o $@ $<  $(LIBPATHS) $(LIBS)

clean:
	rm -f pcapc counterc two_threadsc four_threadsc rssc filtersc *.o

ifndef ONLOAD_TREE
$(error Error: ONLOAD_TREE is not set)
endif

ONLOAD_BUILD	:= $(ONLOAD_TREE)/build/gnu_x86_64
EFVI_INC	:= -I$(ONLOAD_TREE)/src/include
EFVI_DEP	:= $(ONLOAD_BUILD)/lib/ciul/libciul1.a
EFVI_LINK	:= $(ONLOAD_BUILD)/lib/ciul/libciul1.a
LICLIBPATH := $(SOLAR_CAPTURE_TREE)/src/lib/
LICLIBS := $(LICLIBPATH)libsolarcapture0.a $(EFVI_LINK)
