# SPDX-License-Identifier: MIT
# X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.


SC_VER_MAJ ?= 1

CWARNINGS	:= -Wall
CFLAGS		:= -Werror $(CWARNINGS) -g -O2
SC_LINK         := -lsolarcapture${SC_VER_MAJ}


c_api_export: c_api_export.o pkt_ring.o split_to_rings.o
	$(CC) $(CFLAGS) $^ $(SC_LINK) -lpthread -o $@

clean:
	rm -f *.o c_api_export
