# SPDX-License-Identifier: MIT
# X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.


SC_VER_MAJ ?= 1

TGTS := unmanaged_mailbox unmanaged_thread
OBJS := $(patsubst %,%.o,$(TGTS))

CFLAGS          := -Werror $(CWARNINGS) -g -O2 -DNDEBUG

SC_LINK         := -lsolarcapture${SC_VER_MAJ}

.SUFFIXES:

all: $(TGTS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

%: %.o
	$(CC) $(CFLAGS) $< $(SC_LINK) -o $@

clean:
	rm -rf *.o $(TGTS)
