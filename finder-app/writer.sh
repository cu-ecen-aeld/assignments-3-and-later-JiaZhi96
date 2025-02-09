#!/bin/bash

if [ $# != 2 ]
then
    echo "2 Arguments needed [writefile] [writestr]"
    exit 1
fi

WRITE_FILE=$1
WRITE_STR=$2
WRITE_DIR=$(dirname ${WRITE_FILE})

if [ ! -d ${WRITE_DIR} ]
then
    mkdir -p ${WRITE_DIR}
fi

if [ ! -e ${WRITE_FILE} ]
then
    touch ${WRITE_FILE}
    if [ $? -neq 0 ]
    then
        exit 1
    fi
fi

echo ${WRITE_STR} > ${WRITE_FILE}

exit 0
