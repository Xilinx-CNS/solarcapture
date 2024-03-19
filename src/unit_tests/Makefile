# SPDX-License-Identifier: MIT
# X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.


TOP_DIR    := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))../..)
SRC_DIR    := $(TOP_DIR)/src
UT_TOP     := $(TOP_DIR)/build/ut

UT_SRC_TOP := $(SRC_DIR)/unit_tests
BIN_PATH    := $(UT_TOP)/bin
LIB_DIR    := ${SRC_DIR}/lib/

OBJ_PATH    := $(UT_TOP)/obj

# ----------------------------------------------------------------------------

CC = gcc -fprofile-arcs -ftest-coverage -fPIE
CYTHON = cython

INCLUDES := -I${SRC_DIR}/include -I${UT_SRC_TOP}/include \
	-I$(ONLOAD_TREE)/src/include

DEFINES  := -DUT_TEST

LIBS :=

CFLAGS   := -g -O0 -std=gnu89
LDFLAGS  := -g -L${LIB_DIR}

LIBCHECK := -lcheck -lrt -lpthread -lm	-lsubunit

# Required library for Ubuntu
# But for RedHat we need to create a stub
-lsubunit:
	echo '!<arch>' > ${LIB_DIR}/libsubunit.a

# Disable built-in rules
%: %.c
%: %.d
%: %.o

$(OBJ_PATH)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -c $< -o $@
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -MM -MT $@ $< -o $(OBJ_PATH)/$*.d

$(LIB_PATH)/%.so: $(OBJ_PATH)/%.o
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -shared -Wl,-E -o $@ $< $(LIBS)


.PHONY: default
default: all

UT_DEPS :=
UT_EXES :=
ALL_SRCS :=

# Include all the subsiduary Makefile fragments
# Each appends its local target to UT_EXES and defines local rules to build it
include sc_arista_ts/Makefile.test.inc
include sc_cpacket_ts/Makefile.test.inc
include sc_hash_table/Makefile.test.inc
include sc_flow_balancer/Makefile.test.inc


# Include dependency targets
ifeq ($(filter clean distclean,$(MAKECMDGOALS)),)
-include $(ALL_SRCS:$(SRC_DIR)/%.c=$(OBJ_PATH)/%.d)
endif

# ----------------------------------------------------------------------------

.PHONY: all
all:
	$(MAKE) build

.PHONY: build
build: $(UT_EXES) $(UT_DEPS)


.PHONY: clean
clean:
	rm -fr $(UT_TOP)

# ----------------------------------------------------------------------------

.PHONY: run ${RUN_TARGETS}
run: all
	${SRC_DIR}/unit_tests/run_tests.sh ${TESTS}

${RUN_TARGETS}: all
	${SRC_DIR}/unit_tests/run_tests.sh $(subst run_,,$@)

.PHONY: run_vg ${VG_RUN_TARGETS}
run_vg: all
	${SRC_DIR}/unit_tests/run_tests.sh --xml --valgrind ${TESTS}

${VG_RUN_TARGETS}: all
	${SRC_DIR}/unit_tests/run_tests.sh --xml --valgrind ${$@:run_%_vg=%}



.PHONY: help
help:
	@echo
	@echo "The following targets to run tests are available:"
	@echo "    run                     All C tests"
	@echo "    run TESTS=\"c=a,b\"     Selected C tests"
	@echo
	@echo "The following targets run a functional group of tests:"
	@for t in ${RUN_TARGETS}; do \
	  echo "    $$t"; \
	done
	@echo
	@echo "Append _vg to any 'run' target to use valgrind."
	@echo "For a full test run of all tests using valgrind use:"
	@echo "    run_all_vg"
	@echo
