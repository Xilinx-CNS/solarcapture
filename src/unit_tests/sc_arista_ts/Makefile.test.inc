# SPDX-License-Identifier: MIT
# X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.


#-----------------------------------------------------------------------------
# sc_arista_ts
# Files are relative to src dir

ut_sc_arista_ts_cmn_SRCS := \
	${SRC_DIR}/unit_tests/node_stubs.c

ut_sc_arista_ts_cmn_OBJS := ${ut_sc_arista_ts_cmn_SRCS:${SRC_DIR}/%.c=${OBJ_PATH}/%.o}

${ut_sc_arista_ts_cmn_OBJS}: ${MAKEFILE_LIST}
${ut_sc_arista_ts_cmn_OBJS}: INCLUDES += -I${SRC_DIR}/components -I${SRC_DIR}/include -I${SRC_DIR}/core
${OBJ_PATH}/unit_tests/sc_arista_ts/ut_arista%_ts.o: ${MAKEFILE_LIST}
${OBJ_PATH}/unit_tests/sc_arista_ts/ut_arista%_ts.o: INCLUDES += -I${SRC_DIR}/components -I${SRC_DIR}/include -I${SRC_DIR}/core

${BIN_PATH}/ut_sc_arista7150_ts: ${OBJ_PATH}/unit_tests/sc_arista_ts/ut_arista7150_ts.o ${ut_sc_arista_ts_cmn_OBJS} ${LIBCHECK}
	mkdir -p ${@D}
	${CC} ${LDFLAGS} -o $@ $< ${ut_sc_arista_ts_cmn_OBJS} ${LIBCHECK} -lm

${BIN_PATH}/ut_sc_arista7280_64bit_ts: ${OBJ_PATH}/unit_tests/sc_arista_ts/ut_arista7280_64bit_ts.o ${ut_sc_arista_ts_cmn_OBJS} ${LIBCHECK}
	mkdir -p ${@D}
	${CC} ${LDFLAGS} -o $@ $< ${ut_sc_arista_ts_cmn_OBJS} ${LIBCHECK} -lm

${BIN_PATH}/ut_sc_arista7280_48bit_ts: ${OBJ_PATH}/unit_tests/sc_arista_ts/ut_arista7280_48bit_ts.o ${ut_sc_arista_ts_cmn_OBJS} ${LIBCHECK}
	mkdir -p ${@D}
	${CC} ${LDFLAGS} -o $@ $< ${ut_sc_arista_ts_cmn_OBJS} ${LIBCHECK} -lm

ALL_SRCS += ${ut_sc_arista_ts_cmn_SRCS}

UT_EXES  += ${BIN_PATH}/ut_sc_arista7150_ts
UT_EXES  += ${BIN_PATH}/ut_sc_arista7280_64bit_ts
UT_EXES  += ${BIN_PATH}/ut_sc_arista7280_48bit_ts
ALL_SRCS += ${SRC_DIR}/unit_tests/sc_arista_ts/ut_arista7150_ts.c
ALL_SRCS += ${SRC_DIR}/unit_tests/sc_arista_ts/ut_arista7280_64bit_ts.c
ALL_SRCS += ${SRC_DIR}/unit_tests/sc_arista_ts/ut_arista7280_48bit_ts.c
