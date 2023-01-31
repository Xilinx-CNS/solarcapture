# SPDX-License-Identifier: MIT
# X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.


CFLAGS		:= -Wall -Werror -g -O2 -fPIC
LINK_SC		:= -lsolarcapture1

ifdef SC_TREE
SC_CFLAGS	:= -I$(SC_TREE)/src/include
LINK_SC		:= -L$(SC_TREE)/src/lib -lsolarcapture0
endif


.PHONY: all clean

all: sampled.so

clean:
	rm *.o *.so

%.o: %.c
	$(CC) $(CFLAGS) $(SC_CFLAGS) -c $< -o $@

%.so: %.o
	$(CC) $(CFLAGS) $(SC_CFLAGS) -shared -Wl,-E \
	  $< $(LINK_SC) -o $@
