#/bin/bash

if [ $# != 2 ]
then
    echo "2 Arguments needed [filesdir] [searchstr]"
    exit 1
fi

FILES_DIR=$1
SEARCH_STR=$2

if [ ! -d "${FILES_DIR}" ]
then
    echo "Directory ${FILES_DIR} do not exist"
    exit 1
fi

NUM_OF_OCCURENCE=$(grep -o ${SEARCH_STR} ${FILES_DIR}/* | wc -l)
NUM_OF_FILES=$(find ${FILES_DIR} -maxdepth 1 -type f | wc -l)

echo "The number of files are ${NUM_OF_FILES} and the number of matching lines are ${NUM_OF_OCCURENCE}"

exit 0