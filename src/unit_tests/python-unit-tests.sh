#!/bin/bash

TESTS+=( src/test/invoke_wrapper.sh )

if [[ "$1" == "--list" ]]; then
  for T in "${TESTS[@]}"; do
	  echo $T
  done
  exit
fi

for T in "${TESTS[@]}"; do
	$T
done
