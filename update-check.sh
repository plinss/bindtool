#!/usr/bin/env bash

BINDTOOL=$(which bindtool)

if [ -L ${BINDTOOL} ]; then
    BINDTOOL=$(readlink -f ${BINDTOOL})
fi

DIR=${BINDTOOL%/*}

pushd ${DIR} > /dev/null
/usr/bin/git fetch &> /dev/null
LOG="$(/usr/bin/git log HEAD..origin/master)"
if [[ ${LOG} ]] ; then
    echo "bindtool update available"
    echo
    echo "${LOG}"
    echo
    echo "Run 'cd ${DIR} ; sudo git pull' to update"
    echo
fi
popd > /dev/null
