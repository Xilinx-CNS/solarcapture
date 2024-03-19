#bin/bash

# Simple script to invoke the solar_capture front end, wait, then exit
# This is intended to just check that the solar_capture library can load

# Usage:
#	invoke_wrapper		Captures default stream (udp:1.2.3.4:5) on first sfc interface
#	invoke_wrapper SPEC	Captures specified stream (SPEC) on first sfc interface
#	invoke_wrapper MULTIPLE ARGS	Passes all the specified args for solar_capture
#					You must set interface= and output= yourself.
# It is expected that you'll run this from build/ut

# Verbose output goes here, normal output to stdout/stderr
LOGFILE=$(basename $0).log
# And the pass/fail line goes here
RESULTFILE=$(basename $0).out
# Expected format for that line:
# 	$0:${LINENO}:${X}:Invoke wrapper:TEST_get_sfc_interface:${CODE}: ${Verbose}
# Where:
#    ${X} is "P" (pass) "F" (Fail) or "E" (internal error)
#    ${CODE} is the return code to indicate what the problem was (usually 0 for a pass)
#    ${Verbose} is some more human-readable detail if applicable.

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

# Front-end we intend to invoke (note, we are being run from build/ut/)
SC="../../src/solar_capture"
# Default arguments
FIRST_INTERFACE=`get_interface 2> $LOGFILE`
SPEC="udp:1.2.3.4:5"
ARGS=""

# Test that we were able to find an applicable interface
if [[ "$FIRST_INTERFACE" == "" ]]; then
  # ENOENT seems suitable
  echo "$0:${LINENO}:F:Invoke wrapper:TEST_get_sfc_interface:2: Failed" >> $RESULTFILE
else
  echo "$0:${LINENO}:P:Invoke wrapper:TEST_get_sfc_interface:0: Passed" >> $RESULTFILE
fi

# Need an output file
TEMPFILE=$(mktemp --suffix=.pcap})
# magic for the tmpfile to be removed when this script ends, even if killed
exec {FD_W}>"$TEMPFILE"  # Create file descriptor for writing, using first number available
exec {FD_R}<"$TEMPFILE"  # Create file descriptor for reading, using first number available
rm "$TEMPFILE"  # Delete the file, but file descriptors keep available for this script

# Build SC command line, from input or defaults
if [[ $# -gt 0 ]]; then
  SPEC=$1
fi

if [[ $# -gt 1 ]]; then
  ARGS="'$*'"
else
  ARGS="				\
	interface=$FIRST_INTERFACE	\
	output=$TEMPFILE		\
	streams=$SPEC			\
	"
fi

# This is what we're going to run
CMD="timeout 1s python3 $SC $ARGS"

# Do so
echo "Testing: $CMD" >> $LOGFILE
$CMD >> $LOGFILE 2>&1
RVAL=$?

# Format the output like the C-utils so that we can get a pass/fail total
if [[ $RVAL == 124 ]]; then
  echo "$0:${LINENO}:P:Invoke wrapper:TEST_basic_invocation:$RVAL: Passed" >> $RESULTFILE
  RVAL=0
else
  echo "$0:${LINENO}:F:Invoke wrapper:TEST_basic_invocation:$RVAL: Failed" >> $RESULTFILE
fi

exit $RVAL
