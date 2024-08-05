#!/bin/bash

# Simple script to loopback some packets and capture them
# This is intended to just check that the hardware timestamping function works properly
# It is expected that you'll run this from build/ut -
# and you're going to need to be root (or at lest CAP_NET_ADMIN) for this one.

# Verbose output goes here, normal output to stdout/stderr
LOGFILE=$(basename $0).log
# And the pass/fail line goes here
RESULTFILE=$(basename $0).out
# Expected format for that line:
#       $0:${LINENO}:${X}:Invoke wrapper:TEST_get_sfc_interface:${CODE}: ${Verbose}
# Where:
#    ${X} is "P" (pass) "F" (Fail) or "E" (internal error)
#    ${CODE} is the return code to indicate what the problem was (usually 0 for a pass)
#    ${Verbose} is some more human-readable detail if applicable.

MCAST=224.1.2.3
PORT=5555
SC="../../src/solar_capture"


# Must be root, or abort
whoami | grep root > /dev/null
RVAL=$?
if [[ $RVAL != 0 ]]; then
  echo "$0 needs root"
  echo "$0:${LINENO}:E:HardwareTimestamps:TEST_requires_root:$RVAL: Failed" >> $RESULTFILE
  exit
fi



# Need an output file
PCAP=$(mktemp --suffix=.pcap)
# magic for the tmpfile to be removed when this script ends, even if killed
exec {FD_W}>"$PCAP"  # Create file descriptor for writing, using first number available
exec {FD_R}<"$PCAP"  # Create file descriptor for reading, using first number available
rm "$PCAP"  # Delete the file, but file descriptors keep available for this script

START_TIME=`date +%s`

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

# Need an interface to send through
IF=`get_interface`
if [[ "$IF" == "" ]]; then
  # ENOENT seems suitable
  echo "$0:${LINENO}:F:HardwareTimestamps:TEST_get_sfc_interface:2: Failed" >> $RESULTFILE
else
  echo "$0:${LINENO}:P:HardwareTimestamps:TEST_get_sfc_interface:0: Passed" >> $RESULTFILE
fi
echo "Using interface: $IF" >> $LOGFILE

# Make sure sfptpd is running
service sfptpd start >> $LOGFILE 2>&1
if [[ $? == 0 ]]; then
  echo "$0:${LINENO}:P:HardwareTimestamps:TEST_start_sfptpd:0:Starting sfptpd OK" >> $RESULTFILE
else
  echo "$0:${LINENO}:F:HardwareTimestamps:TEST_start_sfptpd:$?:Starting sfptpd Failed" >> $RESULTFILE
fi
sleep 1
service sfptpd status 2>&1 | grep "Active:.*running" >> $LOGFILE 2>&1
if [[ $? == 0 ]]; then
  echo "$0:${LINENO}:P:HardwareTimestamps:TEST_sfptpd_status:0:Running - OK" >> $RESULTFILE
else
  echo "$0:${LINENO}:F:HardwareTimestamps:TEST_sfptpd_status:$?:Failed" >> $RESULTFILE
fi

# Make sure you're in full-feature mode
ethtool -i $IF | grep "firmware-version:.*rx0 tx0" >> $LOGFILE 2>&1
if [[ $? == 0 ]]; then
  echo "$0:${LINENO}:P:HardwareTimestamps:TEST_fullfeature:0:Card mode OK" >> $RESULTFILE
else
  echo "$0:${LINENO}:F:HardwareTimestamps:TEST_fullfeature:34:Card not in full feature mode" >> $RESULTFILE
fi

# Make sure route is correct
ROUTE="${MCAST}/32 dev ${IF}"
ip route add $ROUTE >> $LOGFILE 2>&1
if [[ $? == 0 ]]; then
  echo "$0:${LINENO}:P:HardwareTimestamps:TEST_route:0:OK" >> $RESULTFILE
else
  echo "Desired route was: $ROUTE" >> $LOGFILE
  echo "$0:${LINENO}:F:HardwareTimestamps:TEST_route:$?:Failed" >> $RESULTFILE
fi

# Bring up Solarcapture (in egress sniff mode) with a temporary output file
SC_ATTR="require_hw_timestamps=1"
ARGS="interface=$IF output=$PCAP mode=sniff capture_point=egress"
CMD="$SC $ARGS"
echo "Starting $CMD" >> $LOGFILE
python3 $CMD >> $LOGFILE 2>&1 &
SC_PID=$!
RVAL=$?
# Ensure it is terminated on exit
trap 'kill ${SC_PID} 2>/dev/null' EXIT HUP TERM INT
echo "Started SolarCapture with pid: $SC_PID" >> $LOGFILE 2>&1

if [[ $RVAL == 0 ]]; then
  echo "$0:${LINENO}:P:HardwareTimestamps:TEST_solarcapture:0:SolarCapture started OK" >> $RESULTFILE
else
  echo "$0:${LINENO}:F:HardwareTimestamps:TEST_solarcapture:$RVAL:SolarCapture failed to start" >> $RESULTFILE
fi
sleep 1

# Send a couple of packets, via this loopback route
EF_MCAST_SEND=2 echo "packet" | onload nc -u $MCAST $PORT >> $LOGFILE 2>&1
EF_MCAST_SEND=2 echo "packet" | onload nc -u $MCAST $PORT >> $LOGFILE 2>&1
echo "Two packets sent" >> $LOGFILE

# Stop SolarCapture
kill $SC_PID
wait $SC_PID

# Check that the timestamps in the pcap file are sensible
DUMPTEXT=`tcpdump -vvvnntt -r $PCAP 2>> $LOGFILE`
echo -e "$DUMPTEXT" >> $LOGFILE

# Expect output something like:
# 15:57:29.184357 IP (tos 0x0, ttl 1, id 14336, offset 0, flags [DF], proto UDP (17), length 35)
#     192.168.1.11.44002 > 224.1.2.3.31337: [udp sum ok] UDP, length 7
# 15:57:30.097647 IP (tos 0x0, ttl 1, id 15360, offset 0, flags [DF], proto UDP (17), length 35)
#     192.168.1.11.41206 > 224.1.2.3.31337: [udp sum ok] UDP, length 7

# Expect exactly 2 packets
LINES=`echo -e "$DUMPTEXT" | grep IP | wc -l`
echo "Got $LINES packets" >> $LOGFILE

if [[ "$LINES" == "2" ]]; then
  # Check that each time is in the range
  TIMES=`echo -e "$DUMPTEXT" | grep IP | cut -d' ' -f1 | cut -d'.' -f1`
  END_TIME=`date +%s`
  FAILS=0
  echo "Valid range: $START_TIME - $END_TIME" >> $LOGFILE
  for T in $TIMES; do
    if [[ $T -lt $START_TIME ]]; then
      ((FAIL++))
      echo "Packet time $T too low" >> $LOGFILE
    fi
    if [[ $T -gt $END_TIME ]]; then
      ((FAIL++))
      echo "Packet time $T too high" >> $LOGFILE
    fi
  done

  echo "$0:${LINENO}:P:HardwareTimestamps:TEST_captured2:$LINES:SolarCapture got both packets OK" >> $RESULTFILE
  if [[ "$FAILS" == "0" ]]; then
    echo "$0:${LINENO}:P:HardwareTimestamps:TEST_timestamp:0:Hardware timestamps OK" >> $RESULTFILE
  else
    echo "$0:${LINENO}:F:HardwareTimestamps:TEST_timestamp:$FAILS:Hardware timestamps invalid" >> $RESULTFILE
  fi

else
  echo "$0:${LINENO}:F:HardwareTimestamps:TEST_captured2:$LINES:SolarCapture did not get both packets" >> $RESULTFILE
  echo "$0:${LINENO}:E:HardwareTimestamps:TEST_timestamp:2:Timestamps not tested" >> $RESULTFILE
fi

# Clean up
ip route del $ROUTE

exit

