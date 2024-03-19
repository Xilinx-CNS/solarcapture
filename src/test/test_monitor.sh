#bin/bash
# SPDX-License-Identifier: MIT
# X-SPDX-Copyright-Text: Copyright (C) 2024, Advanced Micro Devices, Inc.

# Test solar_capture_monitor
# invoke solar_capture, then solar_capture_monitor, wait, then exit
# This is intended to just check that the python parts of solar_capture_monitor work

TEST_NAME=$(basename $0)

# Verbose output goes here, normal output to stdout/stderr
LOGFILE=${TEST_NAME}.log
# And the pass/fail line goes here
RESULTFILE=${TEST_NAME}.out

function get_interface() {
  ### Find the n-th SolarCapture-viable interface
  ### (Defaulting to the first)
  NUM=1
  if [[ "$1" != "" ]]; then
    NUM = $1
  fi
  PCI=$(
  ls -d /sys/bus/pci/drivers/sfc/* |
     grep pci |
     head -n1 |
     xargs basename
  )
  ls -l /sys/class/net |
    grep ${PCI} |
    column -s "= " -t |
    tr -s ' \t' |
    cut -d' ' -f9
}

LAST_FAIL=0
function output_result() {
  # Usage: output_result test_name return_value [expected_value=0]
  TEST=$1
  RVAL=$2
  PASS=0
  if [[ "$3" != "" ]]; then
    PASS=$3
  fi

  # TODO: LINENO is this line - should be the line that invoked this function, somehow
  # Format the output like the C-utils so that we can get a pass/fail total
  if [[ ${RVAL} == ${PASS} ]]; then
    echo "$0:${LINENO}:P:${TEST_NAME}:TEST_${TEST}:$RVAL: Passed" >> $RESULTFILE
  else
    echo "$0:${LINENO}:F:${TEST_NAME}:TEST_${TEST}:$RVAL: Failed" >> $RESULTFILE
    LAST_FAIL=${RVAL}
  fi
}

# Front-end we intend to invoke (note, we are being run from build/ut/)
TOOLS_DIR="../../src/"
SC=${TOOLS_DIR}solar_capture
SCM=${TOOLS_DIR}solar_capture_monitor

# The commands to pass into it, multiple tests
INSTANT_SUBCOMMANDS+=( dump )
INSTANT_SUBCOMMANDS+=( list )
INSTANT_SUBCOMMANDS+=( nodes )
INSTANT_SUBCOMMANDS+=( dot )
ENDURING_SUBCOMMANDS+=( line_rate )
ENDURING_SUBCOMMANDS+=( line_total )
ENDURING_SUBCOMMANDS+=( nodes_rate )

# Default arguments for solar capture
SPEC="udp:1.2.3.4:5"
FIRST_INTERFACE=`get_interface 2> $LOGFILE`
# Test that we were able to find an applicable interface
if [[ "$FIRST_INTERFACE" == "" ]]; then
  output_result get_sfc_interface 2
else
  output_result get_sfc_interface 0
fi

# Need an output file
TEMPFILE=$(mktemp --suffix=.pcap})
# magic for the tmpfile to be removed when this script ends, even if killed
exec {FD_W}>"$TEMPFILE"  # Create file descriptor for writing, using first number available
exec {FD_R}<"$TEMPFILE"  # Create file descriptor for reading, using first number available
rm "$TEMPFILE"  # Delete the file, but file descriptors keep available for this script

# Build SC command line
SC_CMD="python3 ${SC}			\
	interface=${FIRST_INTERFACE}	\
	output=${TEMPFILE}		\
	streams=${SPEC}			\
	"

# Start solarcapture
${SC_CMD} >> ${LOGFILE} 2>&1 & SC_PID=$!
# Ensure we kill it on exit
trap 'kill ${SC_PID}' EXIT HUP TERM INT

echo "Started SolarCapture.  Pid: ${SC_PID}" >> ${LOGFILE}

# Run all the sub commands one at a time - first the ones that run once then exit
for SUB in ${INSTANT_SUBCOMMANDS[@]}; do
  SCM_CMD="python3 ${SCM} ${SUB}"
  echo "Testing: ${SCM_CMD}" >> ${LOGFILE}

  ${SCM_CMD} >> ${LOGFILE} 2>&1
  RVAL=$?

  output_result ${SUB} ${RVAL}
done

# Then run the ones that run until killed - telling them to exit.
# TODO: Could run in paralell to save waiting for each one, would save 2s per run
for SUB in ${ENDURING_SUBCOMMANDS[@]}; do
  SCM_CMD="timeout 1 python3 ${SCM} ${SUB}"
  echo "Testing: ${SCM_CMD}" >> $LOGFILE

  # Wrap to allow ncurses to work - need to pretend to be running a wide enough terminal
  # Use script as well as stty, primarily to prevent it corrupting
  # the real terminal when the script exits.
  script -qefc "stty cols 1024; ${SCM_CMD}" >> ${LOGFILE} 2>&1
  RVAL=$?

  # Expect to be killed by the timeout, returning 124
  output_result ${SUB} ${RVAL} 124
done

# Cleanly stop SolarCapture
echo "Terminate SolarCapture" >> ${LOGFILE}
kill ${SC_PID} >> ${LOGFILE} 2>&1

exit ${LAST_FAIL}
