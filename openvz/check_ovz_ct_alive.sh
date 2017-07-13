#!/bin/bash
#
# Check if openvz container is alive
#
# Purpose:
#       This check is the specified conatiner is is running
#       and returns the number of processes active
#
# History:
#       1.0 20150503 <marcus.zoller@idnt.net> created.
#

usage() {
  cat <<EOF
      Usage:
          $(basename $0) [options]

          -c <ctid>    OpenVZ container id to check
EOF
    exit 0
}

while getopts "c:" opt; do
    case "$opt" in
        c) CTID="$OPTARG";;
        *) usage;;
    esac
done

[ -z "${CTID}" ] && usage

if [ ! -d /proc/vz/container/${CTID} ]; then
    # Container not running
    echo "DOWN: Container stopped."
    exit 2
fi

numproc=$(cat /proc/vz/container/${CTID}/tasks | wc -l)

echo "UP: Running on `hostname` (${numproc} processes)."
exit 0
