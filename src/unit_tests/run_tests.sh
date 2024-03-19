#!/bin/bash -e
# SPDX-License-Identifier: MIT
# X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.


err()  { echo >&2 "$*"; }
log()  { err  "$*"; }
fail() { log "$*"; exit 1; }

prog=$(basename $0)
topdir=$(cd $(dirname $0)/../..; pwd)
ut_top=${topdir}/build/ut
scriptdir=${topdir}/scripts

# Option flags
opt_valgrind=0
opt_xml=0

declare -A suites

#  rpc_server_ut.ut_stream

suites["components"]="c=ut_hash_table"

usage="
Usage:
    $0 [options] [test_suite]

With no args, all available unit tests will be run.

Available options:
    --valgrind      Run the tests under valgrind.
    --xml           Write out results in XML format (for Jenkins).
                    Applies to test results and any valgrind report.
    --list          List the Python unit tests (auto-discovered).
    --list-groups   List the test suites available.
    --help          Print this help.

Available test targets:
    all         All C and Python unit tests.
    c           The C unit test suite.
    python      The Python unit tests

Pre-defined test suites:
    ${!suites[@]}

You can also select C tests by naming the exes, e.g.:
    $prog c=ut_hash_table
"

vg_cmd="\
valgrind \
 --leak-check=full \
 --show-reachable=yes \
 --trace-children=yes \
 --track-fds=yes \
 --track-origins=yes \
"

_run_c_unittest()
{
    test=$1
    shift
    test_opts="$*"

    test_name=$(basename $test)
    vg=
    if [ $opt_valgrind -ne 0 ] || [ -n "$RUN_TEST_WITH_VG" ]; then
        if [ $opt_xml -eq 0 ]; then
            vg="$vg_cmd --verbose"
        else
            vg="$vg_cmd --quiet --xml=yes --xml-file=${ut_top}/MEMCHECK-${test_name}.xml"
        fi
        export CK_FORK=no
    fi

    # The unittest progs write a results file to $test.out in current dir,
    # so we cd to $ut_top before running.
    if [ $opt_xml -eq 0 ]; then
        # More output to console for interactive users
        log
        log "*** ${test}"
        ( cd $ut_top && $vg $test $test_opts; true ) 2>&1 | tee ${ut_top}/${test_name}.log
    else
        # Less output to console for Jenkins
        if ( cd $ut_top && $vg $test $test_opts ) >${test_name}.log 2>&1; then
            log "PASS ${test}"
        else
            log "FAIL ${test}"
        fi
    fi
}


c_unittest()
{
    testlist=${*//,/ }
    log
    log "C tests: ${testlist}"
    [ -n "$testlist" ] || testlist=$(cd ${ut_top}/bin; ls ut_* 2>/dev/null || true)
    for test in $testlist; do
        _run_c_unittest ${ut_top}/bin/$test
    done

    # Process "Check" test results
    outfiles=$(ls $ut_top/*.out || true)
}

_run_python_unittest()
{
    test=$1
    shift
    test_opts="$*"

    test_name=$(basename $test)

    # The unittest progs write a results file to $test.out in current dir,
    # so we cd to $ut_top before running.
    if [ $opt_xml -eq 0 ]; then
        # More output to console for interactive users
        log
        log "*** ${test}"
        ( cd $ut_top && $test $test_opts; true ) 2>&1 | tee ${ut_top}/${test_name}.log
        cat ${ut_top}/${test_name}.out 2>/dev/null || true
    else
        # Less output to console for Jenkins
        if ( cd $ut_top && $test $test_opts ) >${test_name}.log 2>&1; then
            log "PASS ${test}"
        else
            log "FAIL ${test}"
        fi
    fi
}

python_unittest()
{
    testlist=${*//,/ }
    log
    log "Python tests: ${testlist}"
    [ -n "$testlist" ] || testlist=$(${topdir}/src/unit_tests/python-unit-tests.sh --list || true)
    for test in $testlist; do
        _run_python_unittest ${topdir}/$test
    done

    # Process "Check" test results
    outfiles=$(ls $ut_top/*.out || true)
}

count_passes()
{
    passes=0
    errors=0
    fails=0

    outfiles=$(ls $ut_top/*.out 2>/dev/null || true)
    if [ -n "$outfiles" ]; then
        # Report "Check"-based tests
        passes=$(grep ':P:' $outfiles | wc -l || true)
        errors=$(grep ':E:' $outfiles | wc -l || true)
        fails=$(grep ':F:' $outfiles | wc -l || true)
    fi
    log
    log "=============================================================================="
    log "Unit tests:"
    log "$passes PASS, $fails FAIL, $errors Test Errors"
    log "=============================================================================="
}


reset_state()
{
    find ${topdir}/build -name '*.gcda' -exec rm -f {} \;
    find ${topdir}/build -name '.coverage*' -exec rm -f {} \;
    rm -f ${ut_top}/*.log
    rm -f ${ut_top}/*.out
    rm -f ${ut_top}/*.xml
}

# ----------------------------------------------------------------------------

run_tests()
{
    reset_state
    for tt in ${@}; do
        t="$tt"
        [ -n "${suites[$tt]}" ] && tt="${suites[$tt]}"
        for t in $tt; do
            case "$t" in
                all)    c_unittest
                        python_unittest ;;
                c)      c_unittest ;;
                python) python_unittest ;;
                c=*)    c_unittest ${t#c=} ;;
                python=*) python_unittest ${t#python=} ;;
                *)      fail "Unknown test group: $t
Did you forget to prefix the test with c= ?
" ;;
            esac
        done
    done

    count_passes
}

# ----------------------------------------------------------------------------


cd $topdir

while [ -n "$1" ]; do
    case "$1" in
        -h|--help)
            err "$usage"
            exit 0
            ;;
        -l|--list)
            shift
            exec ${topdir}/src/unit_tests/python-unit-tests.sh --list $*
            ;;
        --list-groups)
            echo "all c py ${!suites[@]}"
            exit 0
            ;;
        --count)
            count_passes
            exit 0
            ;;
        --valgrind)
            opt_valgrind=1
            ;;
        --xml)
            opt_xml=1
            ;;
        *)
            break
            ;;
    esac
    shift
done

[ -z "$*" ] && set -- "all"
run_tests "$@"
