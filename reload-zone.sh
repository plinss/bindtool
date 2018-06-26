#!/usr/bin/env bash

if [ -z "$1" ]
then
	echo "USAGE: reload-zone.sh ZONE_NAME"
	exit 1
fi

ZONE=$1
ZONE=${ZONE##*/}

ZONEDIR=/etc/bind/zones
CACHEDIR=/var/cache/bind

if [ ! -f ${ZONEDIR}/${ZONE} ]
then
	echo "Zone file not found for ${ZONE}"
	exit 2
fi

/usr/local/bin/bindtool ${ZONEDIR}/${ZONE} ${CACHEDIR}/${ZONE}.out

STATUS=$?
if [ ${STATUS} -ne 0 ]
then
	echo "Zone not modified"
	exit ${STATUS}
fi

CHECK=$(/usr/sbin/named-checkzone ${ZONE} ${CACHEDIR}/${ZONE}.out)

STATUS=$?
if [ ${STATUS} -eq 0 ]
then
	systemctl stop bind9
	rm -f ${CACHEDIR}/${ZONE}.jnl
	mv ${CACHEDIR}/${ZONE}.out ${CACHEDIR}/${ZONE}
	systemctl start bind9
	sleep 1
	/usr/sbin/rndc reconfig
else
	echo "Error in zone file"
	echo "${CHECK}"
	echo "Zone not modified"
	exit ${STATUS}
fi
