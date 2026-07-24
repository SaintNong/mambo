#!/usr/bin/env basha
# simple shell script to run mambo from start -> end function

if [[ $# -lt 3 ]]; then
    echo "Usage: $0 <binary> <start-function> <end-function>" >&2
    exit 2
fi

binary=$1
start=$2
end=$3

symbol_address() {
    address=$(nm "$binary" | awk -v symbol="$1" '$3 == symbol { print "0x" $1; exit }')
    if [[ -z $address ]]; then
        echo "Symbol not found: $1" >&2
        exit 2
    fi
    printf '%s\n' "$address"
}

start_address=$(symbol_address "$start") || exit $?
end_address=$(symbol_address "$end") || exit $?

.venv/bin/python mambo.py \
    --binary "$binary" \
    --start "$start_address" \
    --end "$end_address" \
    "${@:4}"
