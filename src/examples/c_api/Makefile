# SPDX-License-Identifier: MIT
# X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.

SC_VER_MAJ ?= 1
EXECS      := c_api c_api_with_tap pred_stats
CFLAGS     := -Werror $(CWARNINGS) -g -O2 -DNDEBUG -I.
SC_LINK    := -lsolarcapture${SC_VER_MAJ}

all: $(EXECS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

$(EXECS): % : %.o
	$(CC) $(CFLAGS) $< $(SC_LINK) -o $@

clean:
	rm -rf *.o $(EXECS)
