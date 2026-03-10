#!/bin/sh
# When run as a GitHub Action, inputs are passed as args: root [threshold-mb] [json].
# Otherwise pass args through to fors33-scanner.
set -e

if [ -n "$1" ] && [ -d "$1" ]; then
    root="$1"
    shift
    thresh="$1"
    shift
    json_val="$1"
    shift
    if [ "$json_val" = "true" ]; then
        [ -n "$thresh" ] && exec fors33-scanner --root "$root" --threshold-mb "$thresh" --json "$@"
        exec fors33-scanner --root "$root" --json "$@"
    fi
    [ -n "$thresh" ] && exec fors33-scanner --root "$root" --threshold-mb "$thresh" "$@"
    exec fors33-scanner --root "$root" "$@"
fi

exec fors33-scanner "$@"
