#!/bin/bash
#
# Decrypt data encrypted with AWS KMS, OpenSSL, and PBKDF2
#
set -euo pipefail

test "${DEBUG:-false}" = "true" && set -x

if [[ "$#" -lt 2 ]]; then
    echo "Usage: ${0} <env> <encrypted_filename>"
    exit 1
fi

env="${1}"
encrypted_filename="${2}"
# Ajuste para buscar diretamente ".key" sem ".enc.key"
encrypted_key_file="${encrypted_filename%.enc}.key"
output_filename="${encrypted_filename%.enc}"

if [[ ! -f "${encrypted_filename}" || ! -f "${encrypted_key_file}" ]]; then
    echo "Required files not found: \"${encrypted_filename}\" or \"${encrypted_key_file}\""
    exit 1
fi

kms_key_id="alias/${env}"

# Step 1: Retrieve the encrypted data key
echo "Reading encrypted data key from \"${encrypted_key_file}\""
encrypted_data_key=$(cat "${encrypted_key_file}")

# Step 2: Decrypt the data key using AWS KMS
echo "Decrypting data key with KMS"
data_key=$(aws kms decrypt --ciphertext-blob fileb://<(echo "${encrypted_data_key}" | base64 --decode) \
 --query Plaintext \
 --output text | tr -d '\n' | base64 --decode)


# Step 3: Decrypt the file using OpenSSL with PBKDF2
echo "Decrypting \"${encrypted_filename}\" into \"${output_filename}\""
openssl enc -d -aes-256-cbc -pbkdf2 -in "${encrypted_filename}" -out "${output_filename}" -pass pass:"${data_key}"

# Step 4: Clean up sensitive data
echo "Cleaning up sensitive data"
unset data_key

rm -f "${encrypted_filename}" "${encrypted_key_file}"


echo "Decryption complete: \"${output_filename}\" restored."