# SPDX-License-Identifier: MIT
# X-SPDX-Copyright-Text: Copyright (C) 2026, Advanced Micro Devices, Inc.

# Standalone build for cluster_client, a minimal solar_clusterd reference
# client (ON-17615).
#
# Assumes Onload is installed on this host from its source RPM or DEB
# package: ef_vi headers under /usr/include/etherfabric/ and libciul under
# the standard system library directories, both on the compiler's default
# search paths. If Onload isn't installed, install the onload package
# first (build/install the source RPM or DEB), then re-run make.
#
# Links statically against libciul1.a (rather than the dynamic libciul.so)
# so the binary always matches the ABI of the headers it was built
# against and needs no LD_LIBRARY_PATH at runtime.

CC       := gcc
CFLAGS   += -Wall -g -O2
LDLIBS   += -lciul1 -lm -lpthread -lrt -lresolv -lanl

TARGET   := cluster_client

all: $(TARGET)

$(TARGET): cluster_client.c
	$(CC) $(CFLAGS) -o $@ cluster_client.c $(LDLIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
