#!/bin/bash
# SPDX-License-Identifier: MIT
# X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.


usage() {
    echo "Usage:  $(basename $0) version interface"
}

cleanup() {
    rpm -e solar_capture-pro >/dev/null 2>&1
    rpm -e solar_capture-python  >/dev/null 2>&1
    rpm -e solar_capture-live  >/dev/null 2>&1
    rpm -e solar_capture-core  >/dev/null 2>&1
    rm -fr /usr/lib64/solar_capture
    rm -f  /usr/lib64/libsolarcapture*
    rm -f  /usr/bin/solar_*
    rm -fr /usr/share/doc/packages/solar_capture*
    rm -fr /usr/lib/python2.7/site-packages/solar_capture
}

show() {
    ls $1 >/dev/null 2>&1 && find $1
}

check() {
    echo "Files remaining after $1"
    show /usr/lib64/solar_capture
    show /usr/lib64/libsolarcapture*
    show /usr/bin/solar_*
    show /usr/share/doc/packages/solar_capture*
    show /usr/lib/python2.7/site-packages/solar_capture
    echo
}


# Pkg version, e.g. 1.6.0.1_156944089b63-0
ver="$1"
iface="$2"


[ -z "${ver}" ]   && { usage; exit 1; }
[ -z "${iface}" ] && { usage; exit 1; }


cleanup


rpm -i solar_capture-core-${ver}.x86_64.rpm
rpm -e solar_capture-core
check "install/uninstall core:"


rpm -i solar_capture-core-${ver}.x86_64.rpm solar_capture-live-${ver}.x86_64.rpm
rpm -e solar_capture-live solar_capture-core
check "install/uninstall core+live:"

rpm -i solar_capture-core-${ver}.x86_64.rpm
# Build python while core is installed
mkdir -p rpm/{BUILD,BUILDROOT,SRPMS,RPMS,SPECS,SOURCES}
rpmbuild \
    --define "_topdir $PWD/rpm" \
    --rebuild \
    solar_capture-python-${ver}.src.rpm >build.log 2>&1
cp rpm/RPMS/x86_64/solar_capture-python-${ver}.x86_64.rpm .
rpm -i solar_capture-python-${ver}.x86_64.rpm
rpm -e solar_capture-python solar_capture-core
check "install/uninstall core+python:"

rpm -i \
    solar_capture-core-${ver}.x86_64.rpm \
    solar_capture-python-${ver}.x86_64.rpm \
    solar_capture-pro-${ver}.x86_64.rpm
rpm -e solar_capture-pro solar_capture-python solar_capture-core
check "install/uninstall core+python+pro:"



rpm -i \
    solar_capture-core-${ver}.x86_64.rpm \
    solar_capture-python-${ver}.x86_64.rpm \
    solar_capture-pro-${ver}.x86_64.rpm
solar_capture interface=${iface} output=/tmp/sctest.pcap &
pid=$!
sleep 2
kill $pid
rm -f /tmp/sctest.pcap
rpm -e solar_capture-pro solar_capture-python solar_capture-core
check "install/uninstall core+python+pro and run solar_capture:"

cleanup
