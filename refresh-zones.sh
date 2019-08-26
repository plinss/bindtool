#!/usr/bin/env bash

ZONE_DIR=/etc/bind/zones
CACHE_DIR=/var/local/bindtool
BIND_DIR=/var/cache/bind

RELOAD=0

ZONE_FILES=$(find ${ZONE_DIR} -maxdepth 1 -type f)

CHANGED_ZONES=()

for ZONE_FILE in ${ZONE_FILES} ; do
	ZONE_NAME=${ZONE_FILE##*/}
	/usr/local/bin/bindtool ${ZONE_FILE} ${CACHE_DIR}/${ZONE_NAME}.new
	if [ $? -eq 0 ]; then
		sed 's/@[ \t]*SOA[ \t].*$//' ${CACHE_DIR}/${ZONE_NAME} > ${CACHE_DIR}/old_zone
		sed 's/@[ \t]*SOA[ \t].*$//' ${CACHE_DIR}/${ZONE_NAME}.new > ${CACHE_DIR}/new_zone
		diff ${CACHE_DIR}/old_zone ${CACHE_DIR}/new_zone &> /dev/null
		DIFF_RESULT=$?
		rm ${CACHE_DIR}/old_zone ${CACHE_DIR}/new_zone
		if [ ${DIFF_RESULT} -eq 0 ]; then    # zone not modified
			rm ${CACHE_DIR}/${ZONE_NAME}.new
		else
			CHECK=$(/usr/sbin/named-checkzone ${ZONE_NAME} ${CACHE_DIR}/${ZONE_NAME}.new)
			if [ $? -ne 0 ]; then
				echo "Error in zone file ${ZONE_FILE}"
				echo "${CHECK}"
				rm ${CACHE_DIR}/${ZONE_NAME}.new
			else
				RELOAD=1
				mv -f ${CACHE_DIR}/${ZONE_NAME}.new ${CACHE_DIR}/${ZONE_NAME}
				CHANGED_ZONES+=("${ZONE_NAME}")
			fi
		fi
	fi
done

if [ ${RELOAD} -ne 0 ]
then
	systemctl stop bind9

	for ZONE_NAME in ${CHANGED_ZONES[@]} ; do
		rm -f ${BIND_DIR}/${ZONE_NAME}.jnl
		cp -f ${CACHE_DIR}/${ZONE_NAME} ${BIND_DIR}/${ZONE_NAME}
	done

	systemctl start bind9
	sleep 1
	/usr/sbin/rndc reconfig
fi
