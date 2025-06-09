#!/bin/bash

CC=${1}
XXD=${2}
INPUT_FILE=${3}
OUTPUT_DIR=${4}
OUTPUT_FILENAME=${5}

if [ ! -d "${OUTPUT_DIR}" ]; then
  echo "Output directory ${OUTPUT_DIR} does not exist."
  exit 1
fi

echo "Using compiler: ${CC}"
echo "Using xxd: ${XXD}"
echo "Input file: ${INPUT_FILE}"
echo "Output directory: ${OUTPUT_DIR}"
echo "Output filename: ${OUTPUT_FILENAME}"

BC_FILENAME="$(basename ${INPUT_FILE}).bc"

cd "${OUTPUT_DIR}" || exit 1

${CC} -Os -emit-llvm -c "${INPUT_FILE}" -o "${BC_FILENAME}"
${XXD} -i "${BC_FILENAME}" > "${OUTPUT_FILENAME}"

