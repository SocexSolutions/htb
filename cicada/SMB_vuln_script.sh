#!/bin/sh
#Author: rewardone
#Description:
# Requires root or enough permissions to use tcpdump
# Will listen for the first 7 packets of a null login
# and grab the SMB Version
#Notes:
# Will sometimes not capture or will print multiple
# lines. May need to run a second time for success.
if [ -z $1 ]; then
    echo "Usage: ./smbver.sh RHOST {RPORT}" && exit
else
    rhost=$1
fi
if [ ! -z $2 ]; then
    rport=$2
else
    rport=139
fi

echo "rhost: $rhost"
echo "rport: $rport"

OUT1=$(sudo tcpdump -s0 -n -i any port $rport -A -c 7 2>/dev/null)
echo "out1: $OUT1"

OUT2=$(echo "$OUT1" | grep -i "samba\|s.a.m" | tr -d '.')
echo "out2: $OUT2"

echo -n "$rhost: "
echo "$OUT2" | grep -o 'UnixSamba[^[:space:]]*' | tr -d '\n'
echo "exit" | smbclient -L $rhost 1>/dev/null 2>/dev/null
echo
