#!/bin/sh

grep lo: /proc/net/dev|awk '{print $3" "$2}'
