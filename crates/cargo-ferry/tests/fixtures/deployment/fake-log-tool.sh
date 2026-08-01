#!/bin/sh
set -eu

arguments=" $* "
case "$arguments" in
  " devices -l ")
    printf '%s\n' 'List of devices attached' 'serial device product:test model:Fake_Phone device:fake transport_id:1'
    ;;
  *" shell getprop ")
    printf '%s\n' '[ro.build.version.release]: [16]' '[ro.product.cpu.abi]: [arm64-v8a]'
    ;;
  *" shell pidof "*)
    printf '%s\n' '4242'
    ;;
  *" logcat "*)
    if [ "${RUSTFERRY_FAKE_HOLD:-0}" = 1 ]; then
      trap '' INT TERM
      (trap '' INT TERM; while :; do sleep 1; done) &
      printf '%s\n' "$!" > "$RUSTFERRY_FAKE_DESCENDANT_PID"
    fi
    printf '%s\n' \
      '1754049999.100 4242 4243 D Ferry: hidden debug' \
      '1754049999.200 4242 4243 I Ferry: android ready'
    if [ "${RUSTFERRY_FAKE_HOLD:-0}" = 1 ]; then
      while :; do sleep 1; done
    fi
    ;;
  " simctl spawn "*" log stream "*)
    printf '%s\n' \
      '{"timestamp":"2026-08-01T12:00:00Z","messageType":"Debug","subsystem":"com.example.app","eventMessage":"hidden debug","processID":99}' \
      '{"timestamp":"2026-08-01T12:00:01Z","messageType":"Error","subsystem":"com.example.app","eventMessage":"ios ready","processID":99}'
    ;;
  *)
    printf '%s\n' "unexpected fake-tool arguments:$arguments" >&2
    exit 64
    ;;
esac
