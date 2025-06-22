#!/bin/sh

export ENV_IN_SECRET_IKM_LOCATION=./sample.d/.secret/ikm.original.dat
export ENV_IN_SECRET_PEPPER_LOCATION=./sample.d/.secret/pepper.dat

export ENV_IN_PUBLIC_SALT_LOCATION=./sample.d/salt.dat
export ENV_IN_PUBLIC_INFO_LOCATION=./sample.d/info.txt

mkdir -p ./sample.d/.secret

printf 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b |
	xxd -r -ps > "${ENV_IN_SECRET_IKM_LOCATION}"

printf 000102030405060708090a0b0c |
	xxd -r -ps > "${ENV_IN_PUBLIC_SALT_LOCATION}"

printf 0123456789abcdef0123456789abcdef |
	xxd -r -ps > "${ENV_IN_SECRET_PEPPER_LOCATION}"

printf f0f1f2f3f4f5f6f7f8f9 |
	xxd -r -ps > "${ENV_IN_PUBLIC_INFO_LOCATION}"

./genkey
