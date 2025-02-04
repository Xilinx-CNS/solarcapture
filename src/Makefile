# SPDX-License-Identifier: MIT
# X-SPDX-Copyright-Text: Copyright (C) 2023, Advanced Micro Devices, Inc.

# SC_PYTHON is used to specify a custom python binary path.
# SC_PYTHON_CONFIG is used to specify a custom python-config binary path
# (Both must be python3, python2 is no longer supported)

prefix          ?= usr
TOP_DIR         := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))..)
SRCDIR          := ${TOP_DIR}/src
DOCSDIR         := ${TOP_DIR}/docs

# These are used by "make tarball"
DESTDIR         := $(TOP_DIR)/build_products/
BIN_DIR         := $(prefix)/bin
SBIN_DIR        := $(prefix)/sbin
INC_DIR         := $(prefix)/include
LIB_DIR         := $(prefix)/lib64
DOC_DIR         := $(prefix)/share/doc


# Versioning:
# This release of SolarCapture has major version 1.  This must never be
# changed!  (If we wish to break backwards compatibility, we will release
# SolarCapture2).

# The minor version is bumped whenever a release extends the API by adding
# new features.  Such changes must always be backwards compatible with
# earlier releases.  API extensions must properly versioned in both the
# headers and the linker script.

# The release version is reset to zero whenever the minor version is
# bumped.  The release version is bumped for any released change that does
# not extend the API.  (eg. A bug fix or a change to a command line tool).

# SC_VER_BUILD is the commit hash.

SC_VER_MAJ	:= 1
SC_VER_MIN	:= 7
SC_VER_REL	:= 1
# This gets a hash from the files we're using if we want to do that instead
# SC_VER_BUILD    := $(shell { find ${SRCDIR} -regex ".*\.[ch]" | sort | xargs md5sum | md5sum | cut -d' ' -f1; } )
# If we don't have a git tag, just say unknown
SC_VER_BUILD    := $(shell git rev-parse HEAD 2>/dev/null || echo "unknown" )

SC_VER_STR	:= $(SC_VER_MAJ).$(SC_VER_MIN).$(SC_VER_REL).$(SC_VER_BUILD)

# The version of the libsolarcapture shared library is the API version defined
# by SC_API_VER_MAX in src/include/solar_capture_ext.h.

# For compatibility with GNU make < 4.3
H := \#
_VER_INC := -I${SRCDIR}/include
SCLIB_VER_MAJOR := ${SC_VER_MAJ}
SCLIB_VER_MINOR := $(shell { echo "${H}include \"solar_capture_ext.h\""; echo "SC_API_VER_MAX"; } | cpp ${_VER_INC} | tail -1 )
SCLIB_VER_PATCH := 0

ifndef ARCH
ARCH		:= $(shell uname -m)
endif

WITH_SSE ?= $(shell echo $(ARCH) | egrep -q 'x86_64|i.86' && echo 1 )
SC_USE_SSE := ${WITH_SSE}

EFVI_LIB        := $(shell find /usr/lib64 /usr/lib /usr/lib32 -name libciul1.a 2>/dev/null | head -n1 )

LIBSC_REALNAME	:= libsolarcapture${SCLIB_VER_MAJOR}.so.${SCLIB_VER_MINOR}.${SCLIB_VER_PATCH}
LIBSC_SONAME	:= libsolarcapture${SCLIB_VER_MAJOR}.so
LIBSC_LINKNAME	:= libsolarcapture${SCLIB_VER_MAJOR}.so
LIBSC_STATIC	:= libsolarcapture${SCLIB_VER_MAJOR}.a

SC_BUILD	:= $(shell /bin/pwd)
SC_LIB		:= lib
SC_LIB_DBG	:= lib/debug
SC_INC		:= -Iinclude
SC_LINK		:= -L$(SC_LIB) -Wl,-rpath,$(SC_BUILD)/$(SC_LIB) \
		   -Wl,--enable-new-dtags
SC_LINK_LIB	:= -lsolarcapture$(SC_VER_MAJ)
SC_LINK         += ${SC_LINK_LIB}
CWARNINGS	:= -Wall -Wundef -Wstrict-prototypes -Wpointer-arith \
		   -Wnested-externs -Wno-address-of-packed-member -Wno-unused-result
CXXWARNINGS	:= -Wall -Wundef -Wpointer-arith
CFLAGS		:= -Werror $(CWARNINGS) -O2 -DNDEBUG
CFLAGS_DBG	:= -Werror $(CWARNINGS) -rdynamic
ifeq ($(STRIP_LIBS),1)
CFLAGS_DBG	+= -O2
STRIP		:= strip
else
CFLAGS		+= -g
CFLAGS_DBG	+= -ggdb3
STRIP		:= true
endif
SOFLAGS		:= -fPIC -shared -Wl,-E

CORE_SRCS	:= sc_vi sc_thread sc_node_impl sc_mailbox sc_nodes_lookup \
		   sc_stream sc_stats sc_misc sc_debug sc_attr sc_netif	\
		   sc_pkt_pool sc_topology sc_log sc_event sc_object	\
		   sc_iovec sc_memory sc_ef_vi sc_injector \
		   sc_vi_monitor sc_epoll sc_interface \
		   sc_shm_endpoint sc_bitmask

BUILTIN_OBJS	:= components/sc_writer.o		\
		   components/sc_hash_table.o		\
		   components/sc_perf_writer.o		\
		   components/sc_eos_fwd.o		\
		   components/sc_reader.o		\
		   components/sc_arista_ts.o	\
		   components/sc_arista7150_ts.o	\
		   components/sc_arista7280_64bit_ts.o	\
		   components/sc_arista7280_48bit_ts.o	\
		   components/sc_cpacket_ts.o	\
		   components/sc_filter.o		\
		   components/sc_pcap_packer.o		\
		   components/sc_ps_to_ps_packer.o	\
		   components/sc_block_writer.o		\
		   components/sc_tap.o			\
		   components/sc_fd_reader.o		\
		   components/sc_fd_writer.o		\
		   components/sc_ts_adjust.o		\
		   components/sc_pacer.o		\
		   components/sc_rt_pacer.o		\
		   components/sc_stopcock.o		\
		   components/sc_signal_vi.o		\
		   components/sc_repeater.o		\
		   components/sc_line_reader.o		\
		   components/sc_tracer.o		\
		   components/sc_header_editor.o	\
		   components/sc_exit.o			\
		   components/sc_merge_sorter.o		\
		   components/sc_shm_import.o		\
		   components/sc_shm_export.o		\
		   components/sc_shm_broadcast.o		\
		   components/sc_rate_monitor.o		\
		   components/sc_snap.o			\
		   components/sc_sim_work.o		\
		   components/sc_ref_count_undo.o	\
		   components/sc_batch_limiter.o	\
		   components/sc_no_op.o		\
		   components/sc_vss.o			\
		   components/sc_pool_forwarder.o	\
		   components/sc_range_filter.o		\
		   components/sc_timestamp_filter.o	\
		   components/sc_io_demux.o		\
		   components/sc_append_to_list.o	\
		   components/sc_delay_line.o		\
		   components/sc_strip_vlan.o		\
		   components/sc_pktgen.o		\
		   components/sc_subnode_helper.o	\
		   components/sc_flow_balancer.o	\
		   components/sc_ps_packer.o		\
		   components/sc_ps_unpacker.o		\
		   components/sc_vi_node.o		\
		   components/sc_tunnel.o		\
		   components/sc_rr_spreader.o		\
		   components/sc_rr_gather.o		\
		   components/sc_token_bucket_shaper.o	\
		   components/sc_cpacket_encap.o	\
		   components/sc_pass_n.o		\
		   components/sc_wrap_undo.o		\
		   components/sc_tuntap.o		\
		   components/bpf_predicate.o

BUILTIN_DBG_OBJS:= $(patsubst %.o,%.dbg.o,$(BUILTIN_OBJS))

ifndef SC_PYTHON
SC_PYTHON	:= /usr/bin/python3
endif
ifndef SC_PYTHON_CONFIG
SC_PYTHON_CONFIG := /usr/bin/python3-config
endif
PYTHON_CFLAGS	:= $(shell $(SC_PYTHON_CONFIG) --cflags 2>/dev/null)
PYTHON_LIBS	:= $(shell $(SC_PYTHON_CONFIG) --libs 2>/dev/null)
ifeq ($(PYTHON_CFLAGS),)
PYTHON_VER	:= $(shell $(SC_PYTHON) -V 2>&1 | \
			sed 's/Python \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/')
PYTHON_CFLAGS	:= -fno-strict-aliasing -fPIC \
		     -I/usr/include/python$(PYTHON_VER)
PYTHON_LIBS	:= -lpython$(PYTHON_VER)
endif

# On SLES11, '$ python-config --cflags' doesn't include -fPIC but it
# is needed to properly compile PYTHON_SRCS.
PYTHON_CFLAGS   += -fPIC

PYTHON_SRCS	:= sc_python
PYTHON_OBJS	:= $(patsubst %,core/%.o,$(PYTHON_SRCS))

EXAMPLES	:= examples/c_api/c_api				\
		   examples/c_api/c_api_with_tap		\
		   examples/unmanaged/unmanaged_thread		\
		   examples/unmanaged/unmanaged_mailbox		\
		   examples/extensions_api/reflect.so		\
		   examples/extensions_api/reflect_v2.so	\
		   examples/c_api_export/c_api_export		\
		   examples/libpcap_customised/sampled.so

_TEST_NODES	:= measure_ipg scatter sender touch append_ts oprabin \
			tickler always_busy timestamp_inspection \
			seq32 seq32_check sorepkt back_pressure check_cap_len \
			jitter dump_pkts dropper connection_id \
			tcp_seq_drop io_flooder pkt_deserialiser \
			pkt_serialiser subnode_prep wrap \
			eos_indicator hold_n

TEST_NODES	:= $(patsubst %,test/nodes/sct_%.so,$(_TEST_NODES))

TEST_APPS	:= test/cplusplus					\
		test/leak_detect					\
		test/libpcap/pcap_inject_trivial			\
		test/libpcap/pcap_timestamp				\
		test/libpcap/pcap_cluster				\
		test/libpcap/pcap_close					\
		test/libpcap/pcap_selectable_fd				\
		test/libpcap/pcap_findalldevs				\
		test/af_packet/fanout

PCAP		:= libpcap-1.5.3
PCAP_VER	:= $(shell echo $(PCAP) | sed 's/.*-//')
EMBED_PCAP_DIR	:= build-pcap
EMBED_PCAP	:= $(EMBED_PCAP_DIR)/libpcap.a
SC_PCAP_DIR	:= build-pcap-sfsc
SC_PCAP_SRCS	:= $(PCAP)/pcap-sfsc.c $(PCAP)/pcap-sfsc.h $(PCAP)/pcap-int.h \
		   $(PCAP)/pcap-sfsc-poolnode.c $(PCAP)/pcap-sfsc-poolnode.h
_SC_PCAP_TGT	:= $(SC_PCAP_DIR)/libpcap.so.$(PCAP_VER) \
		   $(SC_PCAP_DIR)/libpcap.a
SC_PCAP_TGT	:= $(SC_LIB)/pcap/libpcap.so.$(PCAP_VER) $(SC_LIB)/pcap/libpcap.so.1 \
		   $(SC_LIB)/pcap/libpcap.a

LIBSC_TGT	:= $(SC_LIB)/$(LIBSC_LINKNAME) \
		   $(SC_LIB_DBG)/$(LIBSC_LINKNAME)

PYTHON_TGT	:= python/solar_capture/solar_capture_c.so

DEFAULT_TGT	:= ${LIBSC_TGT} ${PYTHON_TGT} \
		   $(EXAMPLES) test_nodes $(TEST_APPS)

CORE_OBJS	:= $(patsubst %,core/%.o,$(CORE_SRCS))
CORE_DBG_OBJS	:= $(patsubst %.o,%.dbg.o,$(CORE_OBJS))

.PHONY: default_all all libpcap libsolarcapture

default_all: $(DEFAULT_TGT)

all: $(DEFAULT_TGT) $(SC_PCAP_TGT) docs_pdf

libpcap: $(SC_PCAP_TGT)

libsolarcapture: $(SC_LIB)/$(LIBSC_STATIC)


.PHONY: all_nonpython all_python
all_nonpython: ${LIBSC_TGT} ${SC_PCAP_TGT}
all_python:    ${PYTHON_TGT}

.PHONY: docs docs_pdf internal_docs test_nodes test_apps
docs:
	cd ../docs && rm -rf c_bindings && doxygen doxyfile_solar_capture || echo Unable to build documentation

docs_pdf: docs
	cd ../docs/c_bindings/latex && \
		pdflatex refman.tex && pdflatex refman.tex || echo Unable to convert documentation to pdf

internal_docs:
	( cd ../docs && cat doxyfile_solar_capture ; echo "INTERNAL_DOCS=YES" ) | doxygen -

test_nodes: $(TEST_NODES)

test_apps: $(TEST_APPS)


$(CORE_OBJS) $(CORE_DBG_OBJS): core/*.h include/*.h include/*/*.h
$(CORE_OBJS) $(CORE_DBG_OBJS): SC_CFLAGS += -fPIC
$(CORE_OBJS) $(CORE_DBG_OBJS): SC_CFLAGS += -DSC_VER='"$(SC_VER_STR)"'
$(BUILTIN_OBJS) $(BUILTIN_DBG_OBJS):  include/*.h include/*/*.h
$(BUILTIN_OBJS) $(BUILTIN_DBG_OBJS): SC_CFLAGS += -fPIC
$(PYTHON_OBJS): SC_CFLAGS += $(PYTHON_CFLAGS)
$(PYTHON_OBJS): SC_CFLAGS += -DSC_VER='"$(SC_VER_STR)"'

%.o: %.c
	$(CC) $(CFLAGS) $(SC_CFLAGS) $(SC_INC) -c $< -o $@

%.dbg.o: %.c
	$(CC) $(CFLAGS_DBG) $(SC_CFLAGS) $(SC_INC) -c $< -o $@


AUTOCONF_PATH ?= $(shell dirname $(shell which autoconf))
# configure.in is the definitive -- ensure configure is up-to-date
$(PCAP)/configure: $(PCAP)/configure.in
	rm -f "$@"
	cd $(PCAP) && $(AUTOCONF_PATH)/autoconf
	chmod +x "$@"

# Build static libpcap (without SolarCapture support) to embed in
# SolarCapture.  This is needed for bpf filtering support.
$(EMBED_PCAP_DIR)/libpcap.a: $(PCAP)/configure
	rm -rf $(EMBED_PCAP_DIR)
	mkdir $(EMBED_PCAP_DIR)
	cd $(EMBED_PCAP_DIR) && \
	  LIBPCAP_NO_WERROR=true ../$(PCAP)/configure --disable-shared \
	                       --disable-dbus --without-sfsc \
	                       --without-libnl --disable-canusb
	LIBPCAP_NO_WERROR=true $(MAKE) -C $(EMBED_PCAP_DIR) libpcap.a

# Build shared libpcap with SolarCapture support.
$(SC_PCAP_DIR)/config.h: \
		$(PCAP)/configure $(SC_LIB)/$(LIBSC_LINKNAME) \
		$(SC_LIB)/$(LIBSC_STATIC)
	rm -rf $(SC_PCAP_DIR)
	mkdir $(SC_PCAP_DIR)
	cd $(SC_PCAP_DIR) && export SC_VER_MAJ=$(SC_VER_MAJ) && \
	  LIBPCAP_NO_WERROR=true ../$(PCAP)/configure --with-sfsc=..
# Only way to have multiple targets is to use a pattern rule...
build%/libpcap.so.$(PCAP_VER) build%/libpcap.a: \
		$(SC_PCAP_DIR)/config.h $(SC_PCAP_SRCS) \
		$(SC_LIB)/$(LIBSC_STATIC)
	LIBPCAP_NO_WERROR=true $(MAKE) -C $(SC_PCAP_DIR)
%/libpcap.so.$(PCAP_VER) %/libpcap.so.1 %/libpcap.a: $(_SC_PCAP_TGT)
	mkdir -p $(SC_LIB)/pcap
	cp -a $(_SC_PCAP_TGT) $(SC_LIB)/pcap
	ln -sf libpcap.so.$(PCAP_VER) $(SC_LIB)/pcap/libpcap.so.1

$(SC_LIB)/$(LIBSC_LINKNAME): \
		$(CORE_OBJS) $(BUILTIN_OBJS) \
		$(EFVI_LIB) $(EMBED_PCAP_DIR)/libpcap.a \
		core/libsolarcapture.ldscript
	mkdir -p $(SC_LIB)
	LIBPCAP_NO_WERROR=true \
	        $(CC) $(CFLAGS) $(SOFLAGS) -Wl,-soname,$(LIBSC_SONAME) \
		-Wl,--version-script=core/libsolarcapture.ldscript \
		$(CORE_OBJS) $(BUILTIN_OBJS) \
		$(EFVI_LIB) $(EMBED_PCAP) -ldl -lm -lrt -laio -lz \
		-o $(SC_LIB)/$(LIBSC_REALNAME)
	$(STRIP) --strip-unneeded $(SC_LIB)/$(LIBSC_REALNAME)
	rm -f $(SC_LIB)/$(LIBSC_LINKNAME)
	ln -s $(LIBSC_REALNAME) $(SC_LIB)/$(LIBSC_LINKNAME)

$(SC_LIB_DBG)/$(LIBSC_LINKNAME): \
		$(CORE_DBG_OBJS) $(BUILTIN_DBG_OBJS) \
		$(EFVI_LIB) $(EMBED_PCAP_DIR)/libpcap.a \
		core/libsolarcapture.ldscript
	mkdir -p $(SC_LIB_DBG)
	LIBPCAP_NO_WERROR=true \
                $(CC) $(CFLAGS) $(SOFLAGS) -Wl,-soname,$(LIBSC_SONAME) \
		-Wl,--version-script=core/libsolarcapture.ldscript \
		$(CORE_DBG_OBJS) $(BUILTIN_DBG_OBJS) \
		$(EFVI_LIB) $(EMBED_PCAP) -ldl -lm -lrt -laio -lz \
		-o $(SC_LIB_DBG)/$(LIBSC_REALNAME)
	$(STRIP) --strip-unneeded $(SC_LIB_DBG)/$(LIBSC_REALNAME)
	rm -f $(SC_LIB_DBG)/$(LIBSC_LINKNAME)
	ln -s $(LIBSC_REALNAME) $(SC_LIB_DBG)/$(LIBSC_LINKNAME)

$(SC_LIB)/$(LIBSC_STATIC): \
		$(CORE_OBJS) $(BUILTIN_OBJS) \
		$(EFVI_LIB) $(EMBED_PCAP_DIR)/libpcap.a
	mkdir -p $(SC_LIB)
	rm -rf efvi_tmp
	mkdir efvi_tmp
	cd efvi_tmp && ar x $(EFVI_LIB)
	ar cr $(SC_LIB)/$(LIBSC_STATIC) $(CORE_OBJS) $(BUILTIN_OBJS) \
		efvi_tmp/*.o
	rm -rf efvi_tmp


$(PYTHON_TGT): $(PYTHON_OBJS) $(SC_LIB)/$(LIBSC_LINKNAME)
	$(CC) -shared -g -Wl,-E $(PYTHON_OBJS) $(SC_LINK)	\
		$(PYTHON_LIBS) -o $@


components/bpf_predicate.o:          SC_INC += -I$(PCAP)
components/bpf_predicate.dbg.o:      SC_INC += -I$(PCAP)

ifeq (${SC_USE_SSE},1)
components/sc_delay_line.o:          SC_CFLAGS += -msse4.2 -DWITH_SSE_HASH
components/sc_delay_line.dbg.o:      SC_CFLAGS += -msse4.2 -DWITH_SSE_HASH
components/sc_ps_to_ps_packer.o:     SC_CFLAGS += -msse4.1 -DWITH_SSE_HASH
components/sc_ps_to_ps_packer.dbg.o: SC_CFLAGS += -msse4.1 -DWITH_SSE_HASH
components/sc_hash_table.o:          SC_CFLAGS += -msse4.2 -DWITH_SSE_HASH
components/sc_hash_table.dbg.o:      SC_CFLAGS += -msse4.2 -DWITH_SSE_HASH
endif

components/%.o: SC_INC += -Icomponents

test/libpcap/%: SC_INC += -I$(PCAP)
test/libpcap/%: SC_LINK_LIB := $(SC_LIB)/pcap/libpcap.so.1 -ldl -lpthread -pthread -lrt
test/%: SC_LINK_LIB += -lpthread -pthread -lrt
${TEST_APPS}: $(SC_LIB)/pcap/libpcap.so.1

examples/%.so: examples/%.c $(SC_LIB)/$(LIBSC_LINKNAME) \
		include/*.h include/*/*.h
	$(CC) $(CFLAGS) $(SC_CFLAGS) $(SOFLAGS) $(SC_INC) $< $(SC_LINK) -o $@

test/nodes/%.so: test/nodes/%.c $(SC_LIB)/$(LIBSC_LINKNAME) \
		include/*.h include/*/*.h
	$(CC) $(CFLAGS) $(SC_CFLAGS) $(SOFLAGS) $(SC_INC) $< $(SC_LINK) -o $@

# Rule to build stand alone version of built-in components.  (Only works
# for components that don't use internal APIs).
components/%.so: components/%.o $(SC_LIB)/$(LIBSC_LINKNAME)
	$(CC) $(CFLAGS) $(SC_CFLAGS) $(SOFLAGS) $(SC_INC) $< $(SC_LINK) -o $@

examples/%: examples/%.c $(SC_LIB)/$(LIBSC_LINKNAME) include/*.h include/*/*.h
	$(CC) $(CFLAGS) $(SC_CFLAGS) $(SC_INC)			\
		$(filter %.c %.o %.so,$^) $(SC_LINK) -lpthread -o $@

examples/c_api_export/c_api_export:			\
		examples/c_api_export/pkt_ring.o	\
		examples/c_api_export/split_to_rings.o

test/%: test/%.c $(SC_LIB)/$(LIBSC_LINKNAME) include/*.h include/*/*.h
	$(CC) $< $(SC_INC) -L${SC_LIB} $(SC_LINK_LIB) \
	$(FLAGS) -o $@

test/%: test/%.cc $(SC_LIB)/$(LIBSC_LINKNAME) include/*.h include/*/*.h
	$(CXX) $< $(SC_INC) -L${SC_LIB} $(SC_LINK_LIB) \
	$(CXXWARNINGS) -Werror -g -o $@ ${SC_CFLAGS}

.PHONY: unit_tests
unit_tests: all
	make -C unit_tests

.PHONY: run run_unit_tests
run run_unit_tests: unit_tests
	@echo "Running unit tests"
	make -C unit_tests run TESTS="${TESTS}"


# pkg_clean is a restricted clean used by the deb packaging.
# In the deb src tarball, the doxygen files are precompiled and there is
# no unit_test dir.
.PHONY: pkg_clean clean
pkg_clean:
	find . -name '*.o' -exec rm {} \;
	find . -name '*.so' -exec rm {} \;
	find . -name '*.pyc' -exec rm {} \;
	find . -name '*.a' -exec rm {} \;
	rm -f $(EXAMPLES) $(TEST_APPS) *.o *.so *.so.* *.a
	rm -rf $(EMBED_PCAP_DIR) $(SC_PCAP_DIR) $(SC_LIB)
	rm -rf $(PCAP)/configure
	rm -rf $(DESTDIR)

clean: pkg_clean
	rm -rf ../docs/c_bindings
	make -C unit_tests clean
	rm -f solar_capture-$(SC_VER_STR).tgz


.PHONY: install_python install_core install_live install_pro install_nonpython
.PHONY: install_internal

PY_SITE_DIR     := $$($(SC_PYTHON) -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())" )

py_sitelib_dir := $(DESTDIR)${PY_SITE_DIR}/solar_capture
docdir    := $(DESTDIR)$(DOC_DIR)/solar_capture-$(SC_VER_STR)
bindir    := $(DESTDIR)$(BIN_DIR)
sbindir   := $(DESTDIR)$(SBIN_DIR)
incdir    := $(DESTDIR)$(INC_DIR)
libdir    := $(DESTDIR)$(LIB_DIR)
sclibdir  := $(libdir)/solar_capture
pclibdir  := $(sclibdir)/libpcap
tnlibdir  := ${sclibdir}/test_nodes
srcscpy   := $(SRCDIR)/python/solar_capture

install_python:
	mkdir -p $(bindir)
	install -m 755 ${SRCDIR}/solar_capture_monitor $(bindir)
	install -m 755 ${SRCDIR}/solar_capture_doc     $(bindir)

	mkdir -p $(py_sitelib_dir)
	install -m 644 $(srcscpy)/__init__.py              $(py_sitelib_dir)
	install -m 644 $(srcscpy)/cli.py                   $(py_sitelib_dir)
	install -m 644 $(srcscpy)/shm.py                   $(py_sitelib_dir)
	install -m 644 $(srcscpy)/stats.py                 $(py_sitelib_dir)
	install -m 644 $(srcscpy)/tabulate.py              $(py_sitelib_dir)
	install -m 644 ${SRCDIR}/${PYTHON_TGT}             $(py_sitelib_dir)
	mkdir -p $(py_sitelib_dir)_tools
	install -m 644 $(srcscpy)_tools/__init__.py   $(py_sitelib_dir)_tools
	install -m 644 $(srcscpy)_tools/dot.py        $(py_sitelib_dir)_tools

	mkdir -p $(docdir)
	install -m 644 ${DOCSDIR}/README       $(docdir)
	install -m 644 ${DOCSDIR}/ReleaseNotes $(docdir)
	install -m 644 ${DOCSDIR}/ChangeLog    $(docdir)

	mkdir -p ${docdir}/c_api
	cp -pr ${DOCSDIR}/c_bindings/html/* ${docdir}/c_api || true
	mkdir -p $(docdir)/examples/
	cp -pr $(SRCDIR)/examples/* $(docdir)/examples/ || true

install_core:
	mkdir -p $(libdir)
	install -m 755 ${SRCDIR}/lib/${LIBSC_REALNAME} $(libdir)

	mkdir -p $(sclibdir)/debug
	install -m 755 ${SRCDIR}/lib/debug/${LIBSC_REALNAME} $(sclibdir)/debug

        # Create version symlinks for installed shared libs
	/sbin/ldconfig -n $(libdir) $(sclibdir)/debug

	mkdir -p $(incdir)
	install -m 644 ${SRCDIR}/include/solar_capture.h $(incdir)
	install -m 644 ${SRCDIR}/include/solar_capture_ext.h $(incdir)

	mkdir -p $(incdir)/solar_capture
	install -m 644 -t $(incdir)/solar_capture ${SRCDIR}/include/solar_capture/*.h

	mkdir -p $(incdir)/solar_capture/nodes
	install -m 644 -t $(incdir)/solar_capture/nodes ${SRCDIR}/include/solar_capture/nodes/*.h

	mkdir -p $(bindir)
	install -m 755 ${SRCDIR}/solar_debug $(bindir)

install_live:
	mkdir -p $(bindir)
	install -m 755 ${SRCDIR}/solar_libpcap $(bindir)
	install -m 755 ${SRCDIR}/solar_balancer $(bindir)
	install -m 755 ${SRCDIR}/solar_css_tunnel_bridge $(bindir)

	mkdir -p $(pclibdir)
	install -m 755 ${SRCDIR}/lib/pcap/libpcap.so.1.* $(pclibdir)
        # Create version symlinks for installed shared libs
	/sbin/ldconfig -n $(pclibdir)

install_pro:
	mkdir -p $(bindir)
	install -m 755 ${SRCDIR}/solar_capture $(bindir)
	install -m 755 ${SRCDIR}/solar_replay  $(bindir)


install_internal: ${TEST_NODES} ${TEST_APPS}
	mkdir -p ${tnlibdir}
	mkdir -p $(incdir)/sc_internal
	mkdir -p $(sbindir)
	install -m 755 -t ${tnlibdir}           ${SRCDIR}/test/nodes/*.so
	install -m 644 -t ${incdir}             ${SRCDIR}/include/sc_internal.h
	install -m 644 -t ${incdir}/sc_internal ${SRCDIR}/include/sc_internal/*.h
	install -m 755 -t ${sbindir} \
	    test/libpcap/pcap_inject_trivial \
	    test/libpcap/pcap_timestamp \
	    test/libpcap/pcap_cluster \
	    test/libpcap/pcap_close \
	    test/libpcap/pcap_selectable_fd \
	    test/libpcap/pcap_findalldevs


install_nonpython: install_core install_live install_pro

tarball: install_python install_nonpython docs_pdf
	rm ${DESTDIR}/solar_capture-$(SC_VER_STR).tgz || true
	tar czf solar_capture-$(SC_VER_STR).tgz -C ${DESTDIR} .
	cp solar_capture-$(SC_VER_STR).tgz ${DESTDIR}/solar_capture-$(SC_VER_STR).tgz

version: $(info ${SC_VER_STR})

.PHONY: install

install:
	# This release makefile is not smart enough to handle all the Linux distributions out there.
	# (The rpm-creation machinery was too heavily tied to our internal systems for us to be able to
	# open source it)
	# So no fully-automated install is available.
	# Try "make tarball" instead, which will output a build products directory (and tgz)
	# Check that you like that layout, and if you do, you can untar to '/' to slot it all in.

