#!/bin/bash

if [ "$1" = "bpfmon-list" ]; then
	echo '#bpfmon-counters'
	grep -E '^[ \t]*[a-z]+[0-9]+:' /proc/net/dev|tr : ' '|awk '{print $1" bit rx/tx counters"}'
	exit 0
fi

if [ "$1" = "" ] || [ ! -d "/sys/class/net/$1" ]; then
	echo 0 0
	exit 0
fi

grep -E "^[ \t]*$1:" /proc/net/dev|awk '{print $2*8" "$10*8}'
