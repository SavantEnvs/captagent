#!/usr/bin/env bash
#
# mayhem/build.sh — build captagent's fuzz harnesses, their standalone reproducers and the KAT probe.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem, offline (libpcap-dev comes
# from the Dockerfile). Upstream's autotools build is bypassed on purpose: it needs aclocal/autoconf and a
# generated src/config.h, and most of the daemon (config parser, plugin loader) is irrelevant to the two
# parsers fuzzed here. The upstream .c files are compiled directly, unmodified, against mayhem/include/config.h.
#
# Outputs (all under /mayhem):
#   fuzz_socket_pcap, fuzz_sip_parser                  libFuzzer + ASan/UBSan (halting) + DWARF 3
#   fuzz_socket_pcap-standalone, fuzz_sip_parser-standalone   run-once reproducers (no libFuzzer runtime)
#   kat                                                normal-flags known-answer probe used by test.sh
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

INC=(-I"$SRC/mayhem/include" -I"$SRC/include" -I"$SRC/src"
     -I"$SRC/src/modules/socket/pcap" -I"$SRC/src/modules/protocol/sip")
PCAP_DIR=src/modules/socket/pcap
SIP_DIR=src/modules/protocol/sip

# Upstream sources each harness links, besides itself.
PCAP_SRCS=(src/log.c $PCAP_DIR/ipreasm.c $PCAP_DIR/tcpreasm.c $PCAP_DIR/localapi.c $PCAP_DIR/sctp_support.c)
SIP_SRCS=(src/log.c $SIP_DIR/parser_sip.c)

# Packet code casts byte offsets of a capture buffer to header structs, so the alignment check fires on
# every odd-offset header and would halt the fuzzer long before any real defect; relax only that check
# (and pointer-overflow, which fires on the same null-based header arithmetic that already SEGVs when
# dereferenced). Everything else in ASan+UBSan stays halting.
PCAP_RELAX=""
case "$SANITIZER_FLAGS" in *undefined*) PCAP_RELAX="-fno-sanitize=alignment,pointer-overflow" ;; esac

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$WORK/lsan_off.o"

# compile <flavor: fuzz|plain> <extra flags> <source> <object>
compile() {
  local flavor="$1" extra="$2" src="$3" obj="$4" cov=""
  [ "$flavor" = fuzz ] && cov="-fsanitize=fuzzer-no-link"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $extra $cov -fcommon "${INC[@]}" -c "$src" -o "$obj"
}

# build_target <target> <relax flags> <harness source> <upstream sources...>
build_target() {
  local t="$1" relax="$2" harness="$3"; shift 3
  local flavor objs
  for flavor in fuzz plain; do
    objs=()
    mkdir -p "$WORK/$t-$flavor"
    compile "$flavor" "$relax" "$harness" "$WORK/$t-$flavor/harness.o"
    objs+=("$WORK/$t-$flavor/harness.o")
    local i=0 s
    for s in "$@"; do
      i=$((i + 1))
      compile "$flavor" "$relax" "$s" "$WORK/$t-$flavor/up$i.o"
      objs+=("$WORK/$t-$flavor/up$i.o")
    done
    if [ "$flavor" = fuzz ]; then
      # shellcheck disable=SC2086
      $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${objs[@]}" "$WORK/lsan_off.o" -lpcap -lpthread -o "$OUT/$t"
    else
      # shellcheck disable=SC2086
      $CC $SANITIZER_FLAGS $DEBUG_FLAGS $STANDALONE_FUZZ_MAIN "${objs[@]}" "$WORK/lsan_off.o" -lpcap -lpthread -o "$OUT/$t-standalone"
    fi
  done
}

build_target fuzz_socket_pcap "$PCAP_RELAX" mayhem/fuzz_socket_pcap.c "${PCAP_SRCS[@]}"
# Repro-only (not a Mayhemfile target): the action stub also reads msg->len bytes at msg->data, which the
# fuzz targets deliberately do not (see mayhem/fuzz_socket_pcap/known-findings/README.md).
# shellcheck disable=SC2086
compile plain "$PCAP_RELAX -DPCAP_ENV_READ_PAYLOAD" mayhem/fuzz_socket_pcap.c "$WORK/readpayload.o"
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $STANDALONE_FUZZ_MAIN "$WORK/readpayload.o" "$WORK"/fuzz_socket_pcap-plain/up*.o \
    "$WORK/lsan_off.o" -lpcap -lpthread -o "$OUT/fuzz_socket_pcap-readpayload-standalone"
build_target fuzz_sip_parser "" mayhem/fuzz_sip_parser.c "${SIP_SRCS[@]}"

# Known-answer probe: NORMAL flags (no sanitizers, no DWARF pin), dynamically linked — test.sh's oracle.
# shellcheck disable=SC2086
$CC -O2 $COVERAGE_FLAGS -DPCAP_ENV_RECORD_PAYLOAD -fcommon "${INC[@]}" mayhem/kat.c "${SIP_SRCS[@]}" "${PCAP_SRCS[@]:1}" \
    -lpcap -lpthread -o "$OUT/kat"
ldd "$OUT/kat" | grep -q 'libpcap' || { echo "kat is not dynamically linked against libpcap" >&2; exit 1; }
