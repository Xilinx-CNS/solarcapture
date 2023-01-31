# SPDX-License-Identifier: MIT
# X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.


#-----------------------------------------------------------------------------
# sc_cpacket_ts
# Files are relative to src dir

ut_sc_cpacket_ts_SRCS := \
	$(SRC_DIR)/unit_tests/sc_cpacket_ts/ut_cpacket_ts.c \
	$(SRC_DIR)/unit_tests/node_stubs.c

ut_sc_cpacket_ts_OBJS := $(ut_sc_cpacket_ts_SRCS:$(SRC_DIR)/%.c=$(OBJ_PATH)/%.o)

${ut_sc_cpacket_ts_OBJS}: $(MAKEFILE_LIST)
${ut_sc_cpacket_ts_OBJS}: INCLUDES += -I$(SRC_DIR)/components -I$(SRC_DIR)/include -I$(SRC_DIR)/core


${BIN_PATH}/ut_sc_cpacket_ts: ${ut_sc_cpacket_ts_OBJS} ${LIBCHECK} ${MAKEFILE_LIST}
	mkdir -p $(@D)
	${CC} ${LDFLAGS} -o $@ ${ut_sc_cpacket_ts_OBJS} ${LIBCHECK}


UT_EXES  += ${BIN_PATH}/ut_sc_cpacket_ts
ALL_SRCS += ${ut_sc_cpacket_ts_SRCS}
