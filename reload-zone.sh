#!/bin/bash
if [ -z "$1" ]
then
	echo "USAGE: reload-zone.sh ZONE_NAME"
	exit 1
fi

ZONE=$1
ZONE=${ZONE##*/}

if [ ! -f /etc/bind/zones/${ZONE} ]
then
	echo "Zone file not found for ${ZONE}"
	exit 2
fi

/etc/bind/bindtool /etc/bind/zones/${ZONE} /var/cache/bind/${ZONE}.out

STATUS=$?
if [ ${STATUS} -eq 0 ]
then
	systemctl stop bind9
	rm -f /var/cache/bind/${ZONE}.jnl
	mv /var/cache/bind/${ZONE}.out /var/cache/bind/${ZONE}
	systemctl start bind9
	sleep 1
	/usr/sbin/rndc reconfig
else
	echo "Zone not modified"
	exit ${STATUS}
fi
