# SPDX-License-Identifier: MIT
# X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.


#-----------------------------------------------------------------------------
# Files are absolute paths
ut_hash_table_SRCS := \
	$(SRC_DIR)/unit_tests/sc_hash_table/ut_hash_table.c

ut_hash_table_OBJS := $(ut_hash_table_SRCS:$(SRC_DIR)/%.c=$(OBJ_PATH)/%.o)

${ut_hash_table_OBJS}: $(MAKEFILE_LIST)
${ut_hash_table_OBJS}: INCLUDES += -I$(SRC_DIR)/components

${BIN_PATH}/ut_hash_table: $(ut_hash_table_OBJS) ${LIBCHECK}
	@mkdir -p $(dir $@)
	$(CC) ${LDFLAGS} -o $@ $(ut_hash_table_OBJS) ${LIBCHECK}

UT_EXES  += ${BIN_PATH}/ut_hash_table
ALL_SRCS += ${ut_hash_table_SRCS}
