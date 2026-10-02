#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# X-SPDX-Copyright-Text: Copyright (C) 2026, Advanced Micro Devices, Inc.
#
# ON-17615: launch a solar_clusterd instance suitable for exercising
# cluster_client against.
#
# By default this generates a minimal config defining one cluster that
# captures ALL traffic on the given interface, via plain "steal" mode
# (unicast-all + multicast-all filters -- the same filter type efsink/efrss
# use by default) with a configurable number of channels, e.g.:
#
#   [Cluster A]
#   CaptureInterface = eth4
#   NumChannels = 4
#   ProtectionMode = EF_PD_DEFAULT
#   CaptureStream = all
#
# Pass -M sniff to instead use CaptureMode=sniff (non-disruptive port
# mirroring instead of stealing matched traffic from the kernel) -- but
# note ef_filter_spec_set_port_sniff() (etherfabric/vi.h) is "not supported
# by 5000-series and 6000-series adapters", so it will fail with EINVAL on
# that hardware; "steal" (the default here, and solar_clusterd's own
# default when CaptureMode is omitted) has no such restriction.
#
# so that cluster_client can attach to it with e.g. './cluster_client 0@A'.
# Pass -c to use a hand-written config file instead (see solar_clusterd's
# example.conf, installed under its documentation directory, for the full
# syntax).
#
# solar_clusterd now lives in SolarCapture (see docs/solar_cluster.md) --
# it was removed from Onload as of Onload 9.2.0, so by default this assumes
# it's already installed and on PATH from a SolarCapture build, with its
# cluster_protocol.so extension module built and installed alongside it.
# (Only an older, pre-9.2.0 Onload release would bundle its own copy.)
#
# For working against an uninstalled dev/source SolarCapture tree instead,
# pass -t <solarcapture-tree> (e.g. a git checkout of this repo). This runs
# solar_clusterd straight out of that tree's src/solar_clusterd/. If the
# tree doesn't already have solar_clusterd's cluster_protocol.so Python
# C-extension built, this compiles it itself into a cache directory next
# to this script, alongside symlinks to solar_clusterd's other .py modules,
# and points PYTHONPATH at that -- the tree itself is left untouched.
#
# Building cluster_protocol.so needs Onload's ef_vi headers and ciul/cplane
# static libs, which SolarCapture doesn't vendor itself -- point the
# ONLOAD_TREE env var at a built Onload checkout for these (the same
# convention tests/Makefile and src/unit_tests/Makefile use), and pass
# -p <platform> too if its build directory isn't build/gnu_<uname -m>.
# ONLOAD_TREE is only needed when cluster_protocol.so must be compiled from
# source -- if <solarcapture-tree> already has it built, it's used as-is.

set -euo pipefail

# Cache lives under /tmp, scoped per-uid, rather than next to the script:
# the script's own directory may be on a shared/NFS-mounted path (so a
# previous non-root run's cache dir would block a later `sudo` run with
# "Permission denied", and vice versa) -- /tmp keeps root's and a normal
# user's caches independent and avoids that entirely.
CACHE_DIR="${TMPDIR:-/tmp}/solar_clusterd_pymodule-$(id -u)"

CLUSTER_NAME=A
INTERFACE=
NUM_CHANNELS=4
PROTECTION_MODE=EF_PD_DEFAULT
CAPTURE_MODE=steal
CONFIG_FILE=
SOCKET_PATH=
FOREGROUND=1
SC_TREE=
PLATFORM="gnu_$(uname -m)"

usage() {
  cat >&2 <<EOF
usage: $(basename "$0") -i <interface> [options]
       $(basename "$0") -c <config-file> [options]

  -i <interface>     Interface to capture on. Required unless -c is given.
  -c <config-file>   Use this config file verbatim instead of generating
                      one. -n/-N/-m/-i are ignored when this is given.
  -n <name>          Cluster name for the generated config (default: $CLUSTER_NAME)
  -N <num>           NumChannels for the generated config (default: $NUM_CHANNELS)
  -m <mode>          ProtectionMode for the generated config, e.g.
                      EF_PD_DEFAULT / EF_PD_VF (default: $PROTECTION_MODE)
  -M <steal|sniff>   CaptureMode for the generated config (default: $CAPTURE_MODE).
                      sniff needs port-sniff support -- not available on
                      5000/6000-series adapters (see script header comment).
  -s <socket-path>   Passed through as solar_clusterd's -s <socket-path>
  -b                 Daemonize (background) instead of running in the
                      foreground (default: foreground)
  -t <solarcapture-tree>
                      Run solar_clusterd out of this built/source
                      SolarCapture tree instead of requiring it installed
                      on PATH (see script header comment for details).
  -p <platform>      Build platform subdir under \$ONLOAD_TREE/build/, used
                      only with -t when cluster_protocol.so must be
                      compiled from source (default: $PLATFORM)
  -h                 Show this help

Examples:
  $(basename "$0") -i eth4
  $(basename "$0") -i eth4 -n B -N 8
  ONLOAD_TREE=~/git/onload $(basename "$0") -i eth4 -t ~/git/solarcapture
  # then, in another shell:
  ./cluster_client 0@A
EOF
  exit 1
}

while getopts "i:c:n:N:m:M:s:bt:p:h" opt; do
  case "$opt" in
    i) INTERFACE=$OPTARG ;;
    c) CONFIG_FILE=$OPTARG ;;
    n) CLUSTER_NAME=$OPTARG ;;
    N) NUM_CHANNELS=$OPTARG ;;
    m) PROTECTION_MODE=$OPTARG ;;
    M) CAPTURE_MODE=$OPTARG ;;
    s) SOCKET_PATH=$OPTARG ;;
    b) FOREGROUND=0 ;;
    t) SC_TREE=$OPTARG ;;
    p) PLATFORM=$OPTARG ;;
    h) usage ;;
    *) usage ;;
  esac
done

if [ -z "$CONFIG_FILE" ] && [ -z "$INTERFACE" ]; then
  echo "ERROR: either -i <interface> or -c <config-file> is required" >&2
  usage
fi

case "$CAPTURE_MODE" in
  steal|sniff) ;;
  *) echo "ERROR: -M must be 'steal' or 'sniff', not '$CAPTURE_MODE'" >&2; exit 1 ;;
esac

# --- Locate solar_clusterd, either on PATH (default) or in a dev tree (-t) --
if [ -n "$SC_TREE" ]; then
  SOLAR_CLUSTERD_DIR="$SC_TREE/src/solar_clusterd"
  SOLAR_CLUSTERD="$SOLAR_CLUSTERD_DIR/solar_clusterd"

  [ -f "$SOLAR_CLUSTERD" ] || { echo "ERROR: $SOLAR_CLUSTERD not found" >&2; exit 1; }

  if [ -f "$SOLAR_CLUSTERD_DIR/cluster_protocol.so" ]; then
    echo "Using existing build: $SOLAR_CLUSTERD_DIR/cluster_protocol.so"
    export PYTHONPATH="$SC_TREE/src${PYTHONPATH:+:$PYTHONPATH}"
  else
    [ -n "${ONLOAD_TREE:-}" ] || {
      echo "ERROR: $SOLAR_CLUSTERD_DIR/cluster_protocol.so isn't built, and" >&2
      echo "       ONLOAD_TREE isn't set -- point it at a built Onload" >&2
      echo "       checkout to compile it (see script header comment), or" >&2
      echo "       build $SC_TREE's solar_clusterd first." >&2
      exit 1
    }
    CIUL_LIB="$ONLOAD_TREE/build/$PLATFORM/lib/ciul/libciul1.a"
    CPLANE_LIB="$ONLOAD_TREE/build/$PLATFORM/lib/cplane/libcplane0.a"
    [ -f "$CIUL_LIB" ]   || { echo "ERROR: $CIUL_LIB not found -- build $ONLOAD_TREE first (scripts/onload_build), or check -p" >&2; exit 1; }
    [ -f "$CPLANE_LIB" ] || { echo "ERROR: $CPLANE_LIB not found -- build $ONLOAD_TREE first (scripts/onload_build), or check -p" >&2; exit 1; }

    SO_PATH="$CACHE_DIR/solar_clusterd/cluster_protocol.so"
    NEEDS_BUILD=1
    if [ -f "$SO_PATH" ] &&
       [ "$SO_PATH" -nt "$SOLAR_CLUSTERD_DIR/cluster_protocol.c" ] &&
       [ "$SO_PATH" -nt "$SOLAR_CLUSTERD_DIR/filter_string.c" ]; then
      NEEDS_BUILD=0
    fi

    mkdir -p "$CACHE_DIR/solar_clusterd"
    ln -sf "$SOLAR_CLUSTERD_DIR/__init__.py"     "$CACHE_DIR/solar_clusterd/__init__.py"
    ln -sf "$SOLAR_CLUSTERD_DIR/daemonize.py"    "$CACHE_DIR/solar_clusterd/daemonize.py"
    ln -sf "$SOLAR_CLUSTERD_DIR/parse_config.py" "$CACHE_DIR/solar_clusterd/parse_config.py"

    if [ "$NEEDS_BUILD" = 1 ]; then
      echo "cluster_protocol.so not found in $SC_TREE; compiling into $CACHE_DIR"
      PY_CFLAGS=$(python3-config --cflags)
      PY_LIBS=$(python3-config --libs)
      OBJDIR=$(mktemp -d)

      gcc -fPIC -Wall -g -O2 $PY_CFLAGS \
        -I"$ONLOAD_TREE/src/include" -I"$SOLAR_CLUSTERD_DIR" \
        -c "$SOLAR_CLUSTERD_DIR/filter_string.c" -o "$OBJDIR/filter_string.o"
      gcc -fPIC -Wall -g -O2 $PY_CFLAGS \
        -I"$ONLOAD_TREE/src/include" -I"$SOLAR_CLUSTERD_DIR" \
        -c "$SOLAR_CLUSTERD_DIR/cluster_protocol.c" -o "$OBJDIR/cluster_protocol.o"
      gcc -shared -g -Wl,-E -o "$SO_PATH" \
        "$OBJDIR/filter_string.o" "$OBJDIR/cluster_protocol.o" \
        "$CIUL_LIB" "$CPLANE_LIB" $PY_LIBS
      rm -rf "$OBJDIR"
      echo "Built $SO_PATH"
    fi
    export PYTHONPATH="$CACHE_DIR${PYTHONPATH:+:$PYTHONPATH}"
  fi
else
  SOLAR_CLUSTERD=$(command -v solar_clusterd || true)
  if [ -z "$SOLAR_CLUSTERD" ]; then
    echo "ERROR: solar_clusterd not found on PATH." >&2
    echo "       Either install SolarCapture (or, on an Onload release" >&2
    echo "       older than 9.2.0, its bundled copy)," >&2
    echo "       or pass -t <solarcapture-tree> to run out of a source checkout." >&2
    exit 1
  fi
fi

if [ -n "$INTERFACE" ] && [ ! -e "/sys/class/net/$INTERFACE" ]; then
  echo "WARNING: no such interface '$INTERFACE' on this host (continuing anyway)" >&2
fi

if [ "$(id -u)" != 0 ]; then
  echo "WARNING: not running as root; ef_driver_open()/ef_pd_alloc() may fail" >&2
  echo "         unless this host permits non-root access to the char driver" >&2
fi

# --- Generate config, unless one was supplied ------------------------------
GENERATED_CONFIG=
if [ -z "$CONFIG_FILE" ]; then
  GENERATED_CONFIG=$(mktemp /tmp/solar_clusterd.XXXXXX.conf)
  {
    echo "; Generated by $(basename "$0") on $(date -Iseconds)"
    echo "[Cluster $CLUSTER_NAME]"
    echo "CaptureInterface = $INTERFACE"
    echo "NumChannels = $NUM_CHANNELS"
    echo "ProtectionMode = $PROTECTION_MODE"
    echo "CaptureStream = all"
    if [ "$CAPTURE_MODE" = sniff ]; then
      echo "CaptureMode = sniff"
      echo "Promiscuous = 1"
    fi
  } > "$GENERATED_CONFIG"
  CONFIG_FILE=$GENERATED_CONFIG
  echo "Generated config ($CONFIG_FILE):"
  sed 's/^/  /' "$CONFIG_FILE"
fi

cleanup() {
  [ -n "$GENERATED_CONFIG" ] && rm -f "$GENERATED_CONFIG"
}
trap cleanup EXIT

# --- Launch -----------------------------------------------------------------
ARGS=()
[ -n "$SOCKET_PATH" ] && ARGS+=(-s "$SOCKET_PATH")
[ "$FOREGROUND" = 1 ] && ARGS+=(-f)

echo "Starting solar_clusterd..."
python3 "$SOLAR_CLUSTERD" "${ARGS[@]}" "$CONFIG_FILE" &
SC_PID=$!
trap 'kill -TERM "$SC_PID" 2>/dev/null || true; wait "$SC_PID" 2>/dev/null || true; cleanup' INT TERM
wait "$SC_PID"
rc=$?
cleanup
trap - EXIT
exit $rc
